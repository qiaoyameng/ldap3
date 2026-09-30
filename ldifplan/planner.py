"""Generate reversible forward/compensation LDIF plans from a snapshot and ops.

Design notes
------------
* The snapshot is the source of truth for "old" data.  Compensation values are
  taken from real entry state captured during an in-order simulation; the
  planner never fabricates empty values to stand in for missing old data.
* Every operation is simulated on :class:`~ldifplan.mockdit.MockDIT`.
  Operations that fail (noSuchObject, entryAlreadyExists, non-leaf delete,
  unknown change type, ...) are classified ``invalid`` with the server-style
  reason and are excluded from both plans.
* Compensation records are generated in reverse order.  If an invalid
  operation touches entry X, the simulated DIT used for later operations no
  longer matches reality, so compensation for earlier operations on the same
  entry is classified ``blocked`` (with the reason stating that a later
  operation on the entry is not reversible), instead of emitting a
  confidently-wrong rollback.
* modDN compensation targets the *current* (post-forward) address, as required.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .mockdit import MockDIT, MockDITError
from .values import decode_json_value, normalize_values

STATUS_REVERSIBLE = "reversible"
STATUS_INVALID = "invalid"
STATUS_BLOCKED = "blocked"


def _decode_attribute_map(attributes: Dict[str, Any]) -> Dict[str, List[bytes]]:
    result: Dict[str, List[bytes]] = {}
    for attr, values in attributes.items():
        if values is None:
            values = []
        if isinstance(values, (str, bytes)) or isinstance(values, dict):
            values = [values]
        result[attr] = [decode_json_value(value) for value in values]
    return result


@dataclass
class PlannedOperation:
    index: int
    operation: Dict[str, Any]
    status: str
    reason: Optional[str] = None
    forward_record: Optional[Dict[str, Any]] = None
    reverse_records: List[Dict[str, Any]] = field(default_factory=list)
    forward_dn: Optional[str] = None
    target_dn: Optional[str] = None
    final_dn: Optional[str] = None

    def to_report(self) -> Dict[str, Any]:
        report = {
            "index": self.index,
            "type": _op_type(self.operation),
            "status": self.status,
            "dn": self.forward_dn,
            "forward_target": self.target_dn,
            "final_target": self.final_dn,
        }
        if self.reason:
            report["reason"] = self.reason
        if self.status == STATUS_REVERSIBLE and self.reverse_records:
            report["reverse_records"] = len(self.reverse_records)
        return report


@dataclass
class PlanResult:
    forward_records: List[Dict[str, Any]]
    reverse_records: List[Dict[str, Any]]
    operations: List[PlannedOperation]
    original_snapshot: Dict[str, Dict[str, List[bytes]]]
    excluded_dns: List[str] = field(default_factory=list)
    verification_problems: List[str] = field(default_factory=list)

    @property
    def reversible(self) -> bool:
        return all(item.status == STATUS_REVERSIBLE for item in self.operations)

    def report(self) -> Dict[str, Any]:
        return {
            "reversible_range_complete": self.reversible,
            "excluded_dns": sorted(self.excluded_dns),
            "operations": [item.to_report() for item in self.operations],
        }


def _op_type(operation: Dict[str, Any]) -> str:
    return str(operation.get("operation", operation.get("type", "?"))).lower()


class ChangePlanner:
    """Build forward/reverse plans from snapshot + change operations."""

    def __init__(self, snapshot: Dict[str, Dict[str, Any]]):
        decoded = {dn: _decode_attribute_map(attrs) for dn, attrs in snapshot.items()}
        self.snapshot = decoded
        self.dit = MockDIT(decoded)
        self.original = self.dit.snapshot_copy()

    def plan(self, operations: Sequence[Dict[str, Any]]) -> PlanResult:
        planned: List[PlannedOperation] = []

        for index, raw_operation in enumerate(operations):
            planned.append(self._simulate(index, raw_operation))

        reverse_records, excluded = self._build_compensation(planned)
        forward_records = [
            copy.deepcopy(item.forward_record)
            for item in planned
            if item.status == STATUS_REVERSIBLE and item.forward_record is not None
        ]

        problems = self._verify_compensation(forward_records, reverse_records, excluded)
        return PlanResult(
            forward_records,
            reverse_records,
            planned,
            self.original,
            excluded_dns=sorted(excluded),
            verification_problems=problems,
        )

    # ----- forward simulation -----

    def _simulate(self, index: int, raw_operation: Dict[str, Any]) -> PlannedOperation:
        operation = self._normalize_operation(raw_operation)
        planned = PlannedOperation(index=index, operation=operation, status=STATUS_INVALID)
        kind = _op_type(operation)
        if operation.get("dn"):
            try:
                planned.forward_dn = self.dit.normalize_dn(operation["dn"])
            except Exception:
                planned.forward_dn = operation["dn"]

        try:
            if kind in ("add",):
                self._simulate_add(planned, operation)
            elif kind == "delete":
                self._simulate_delete(planned, operation)
            elif kind == "modify":
                self._simulate_modify(planned, operation)
            elif kind in ("moddn", "modrdn", "modify_dn", "rename", "move"):
                self._simulate_moddn(planned, operation)
            else:
                planned.reason = (
                    "operation %r cannot be reliably reversed: unsupported change type" % kind
                )
        except MockDITError as error:
            planned.status = STATUS_INVALID
            planned.reason = "cannot be applied (resultCode=%d): %s" % (
                error.result_code,
                error,
            )
        return planned

    @staticmethod
    def _normalize_operation(raw: Dict[str, Any]) -> Dict[str, Any]:
        operation = dict(raw)
        if "type" in operation and "operation" not in operation:
            operation["operation"] = operation.pop("type")
        return operation

    def _simulate_add(self, planned: PlannedOperation, operation: Dict[str, Any]) -> None:
        dn = operation["dn"]
        attributes = _decode_attribute_map(operation.get("attributes", {}))
        self.dit.add(dn, attributes)
        normalized = self.dit.normalize_dn(dn)
        planned.forward_dn = normalized
        planned.target_dn = normalized
        planned.final_dn = normalized
        entry_copy = copy.deepcopy(self.dit.entries[normalized])
        planned.forward_record = {"dn": normalized, "changetype": "add", "attributes": entry_copy}
        planned.reverse_records = [{"dn": normalized, "changetype": "delete"}]
        planned.status = STATUS_REVERSIBLE

    def _simulate_delete(self, planned: PlannedOperation, operation: Dict[str, Any]) -> None:
        dn = self.dit.normalize_dn(operation["dn"])
        if dn not in self.dit.entries:
            raise MockDITError("no such object: %s" % operation["dn"], 32)
        if self.dit.has_children(dn):
            raise MockDITError(
                "not allowed on non-leaf: %s has subordinates and no subtree-delete "
                "control was requested; deletion of non-leaf entries cannot be "
                "guaranteed reversible" % dn,
                66,
            )
        old_entry = copy.deepcopy(self.dit.entries[dn])
        self.dit.delete(dn)
        planned.forward_dn = dn
        planned.target_dn = dn
        planned.forward_record = {"dn": dn, "changetype": "delete"}
        planned.reverse_records = [{"dn": dn, "changetype": "add", "attributes": old_entry}]
        planned.status = STATUS_REVERSIBLE

    def _simulate_modify(self, planned: PlannedOperation, operation: Dict[str, Any]) -> None:
        dn = self.dit.normalize_dn(operation["dn"])
        changes = self._normalize_changes(operation.get("changes", []))
        if dn not in self.dit.entries:
            raise MockDITError("no such object: %s" % operation["dn"], 32)

        before = copy.deepcopy(self.dit.entries[dn])
        self.dit.modify(dn, changes)
        after = self.dit.entries[dn]
        compensation = self._compensate_modify(before, after)
        planned.forward_dn = dn
        planned.target_dn = dn
        planned.final_dn = dn
        planned.forward_record = {"dn": dn, "changetype": "modify", "changes": changes}
        planned.reverse_records = [{"dn": dn, "changetype": "modify", "changes": compensation}]
        planned.status = STATUS_REVERSIBLE

    @staticmethod
    def _normalize_changes(raw_changes: Any) -> List[Dict[str, Any]]:
        changes: List[Dict[str, Any]] = []
        for change in raw_changes:
            item = dict(change)
            if "operation" not in item:
                raise MockDITError("modify change needs an add/delete/replace operation", 2)
            item["operation"] = item["operation"].lower()
            if item["operation"] not in ("add", "delete", "replace"):
                raise MockDITError("unknown modify operation %r" % item["operation"], 2)
            item["values"] = normalize_values(item.get("values"))
            changes.append(item)
        return changes

    @staticmethod
    def _compensate_modify(before: Dict[str, List[bytes]],
                           after: Dict[str, List[bytes]]) -> List[Dict[str, Any]]:
        """Build changes turning *after* back into *before*.

        Values come from the captured snapshot state only.  Removed values are
        restored with ``add``; newly added values are undone with ``delete``.
        When the attribute had no values surviving from before (or was absent),
        a single ``replace`` is used so a forward replace-with-empty becomes an
        exact restore-with-old-values rather than fabricated adds.
        """
        compensation: List[Dict[str, Any]] = []
        for attribute in sorted(set(before) | set(after)):
            old_values = before.get(attribute, [])
            new_values = after.get(attribute, [])
            if old_values == new_values:
                continue
            surviving = [value for value in new_values if value in old_values]
            added = [value for value in new_values if value not in old_values]
            removed = [value for value in old_values if value not in new_values]
            if not surviving:
                compensation.append({
                    "operation": "replace",
                    "attribute": attribute,
                    "values": list(old_values),
                })
                continue
            if added:
                compensation.append({
                    "operation": "delete",
                    "attribute": attribute,
                    "values": added,
                })
            if removed:
                compensation.append({
                    "operation": "add",
                    "attribute": attribute,
                    "values": removed,
                })
        return compensation

    def _simulate_moddn(self, planned: PlannedOperation, operation: Dict[str, Any]) -> None:
        dn = self.dit.normalize_dn(operation["dn"])
        new_rdn = operation.get("newrdn") or operation.get("newRdn") or operation.get("new_rdn")
        if not new_rdn:
            raise MockDITError("modDN requires newrdn", 2)
        delete_old_rdn = bool(
            operation.get("deleteoldrdn", operation.get("deleteOldRdn", operation.get("delete_old_rdn", True)))
        )
        new_superior = operation.get("newsuperior", operation.get("newSuperior", operation.get("new_superior")))
        if new_superior is not None:
            new_superior = self.dit.normalize_dn(new_superior)

        new_dn, removed, added = self.dit.modify_dn(dn, new_rdn, delete_old_rdn, new_superior)

        # Compensation order (records are consumed in reverse execution order):
        # 1. while the entry still lives at the post-forward address, restore
        #    exactly the RDN attribute values the forward modDN deleted and
        #    delete exactly the RDN values it added (values are taken from the
        #    simulated state, never invented);
        # 2. move the entry back to its original address with deleteOldRdn=1,
        #    because step 1 has already restored the original RDN value set.
        reconcile_changes: List[Dict[str, Any]] = []
        restore_values = [(attr, value) for attr, value, was_present in removed if was_present]
        drop_values = [(attr, value, was_present) for attr, value, was_present in added
                       if not was_present]
        for attribute in sorted({attr for attr, _ in restore_values}):
            reconcile_changes.append({
                "operation": "add",
                "attribute": attribute,
                "values": [value for attr, value in restore_values if attr == attribute],
            })
        for attribute in sorted({attr for attr, _, _ in drop_values}):
            reconcile_changes.append({
                "operation": "delete",
                "attribute": attribute,
                "values": [value for attr, value, _ in drop_values if attr == attribute],
            })

        reverse_records: List[Dict[str, Any]] = []
        if reconcile_changes:
            reverse_records.append({"dn": new_dn, "changetype": "modify",
                                    "changes": reconcile_changes})
        reverse_records.append({
            "dn": new_dn,
            "changetype": "moddn",
            "newrdn": _first_rdn(dn),
            "deleteoldrdn": True,
            "newsuperior": self.dit.parent_dn(dn),
        })

        planned.forward_dn = dn
        planned.target_dn = new_dn
        planned.final_dn = new_dn
        planned.forward_record = {
            "dn": dn,
            "changetype": "moddn",
            "newrdn": new_rdn,
            "deleteoldrdn": delete_old_rdn,
            "newsuperior": new_superior,
        }
        planned.reverse_records = reverse_records
        planned.status = STATUS_REVERSIBLE

    # ----- compensation ordering / taint handling -----

    def _build_compensation(self, planned: List[PlannedOperation]):
        """Collect compensation records for entries inside the reversible range.

        Policy: an entry is *tainted* when any operation on it (or on an address
        it moved between) is invalid or unsupported.  Every planned operation
        touching a tainted address is then reported as ``blocked`` (with a reason)
        and left out of both plans, so forward.ldif only ever touches entries
        whose complete change set can be undone exactly.  Taint follows modDN
        renames by closing over both old and new addresses.
        """
        tainted: set = set()
        for planned_op in planned:
            if planned_op.status != STATUS_REVERSIBLE:
                tainted.update(self._touched_dns(planned_op))

        changed = True
        while changed:
            changed = False
            for planned_op in planned:
                if planned_op.status == STATUS_REVERSIBLE:
                    continue
                touched = set(self._touched_dns(planned_op))
                if touched - tainted:
                    tainted |= touched
                    changed = True

        for planned_op in planned:
            if planned_op.status == STATUS_REVERSIBLE and tainted & set(self._touched_dns(planned_op)):
                planned_op.status = STATUS_BLOCKED
                planned_op.reason = (
                    "another operation on this entry (%s) is outside the reversible "
                    "range; the whole entry change is withheld from the plan rather "
                    "than emitting partial compensation"
                    % ", ".join(sorted(tainted & set(self._touched_dns(planned_op))))
                )

        records: List[Dict[str, Any]] = []
        for planned_op in reversed(planned):
            if planned_op.status == STATUS_REVERSIBLE:
                records.extend(copy.deepcopy(planned_op.reverse_records))
        return records, tainted

    @staticmethod
    def _touched_dns(planned_op: PlannedOperation) -> List[str]:
        dns: List[str] = []
        if planned_op.forward_dn:
            dns.append(planned_op.forward_dn)
        if planned_op.target_dn and planned_op.target_dn != planned_op.forward_dn:
            dns.append(planned_op.target_dn)
        return dns

    # ----- verification of the reversible range -----

    def _verify_compensation(self, forward_records: List[Dict[str, Any]],
                             reverse_records: List[Dict[str, Any]],
                             excluded_dns: set) -> List[str]:
        """Apply both plans on a fresh mock DIT and check the reversible range.

        Entries touched by an excluded (invalid/blocked/unsupported) operation
        are outside the promised range and are therefore not compared.
        """
        from .mockdit import apply_change_records

        verify_dit = MockDIT(copy.deepcopy(self.snapshot))
        apply_change_records(verify_dit, forward_records)
        apply_change_records(verify_dit, reverse_records)
        restored = verify_dit.entries

        in_scope = lambda dn: not any(dn == excluded or dn.startswith(excluded + ",")
                                      for excluded in excluded_dns)
        problems: List[str] = []
        for dn in sorted(dn for dn in set(self.original) | set(restored) if in_scope(dn)):
            if dn not in self.original:
                problems.append("extra entry after compensation: %s" % dn)
            elif dn not in restored:
                problems.append("entry missing after compensation: %s" % dn)
                continue
            for attribute in sorted(set(self.original[dn]) | set(restored[dn])):
                if self.original[dn].get(attribute) != restored[dn].get(attribute):
                    problems.append(
                        "attribute %s of %s not restored: %r vs %r"
                        % (attribute, dn, self.original[dn].get(attribute),
                           restored[dn].get(attribute))
                    )
        return problems


def _first_rdn(dn: str) -> str:
    depth = 0
    for index, char in enumerate(dn):
        if char == "\\":
            continue
        if char == ",":
            return dn[:index]
    return dn


