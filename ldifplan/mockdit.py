"""In-memory LDAP DIT used for plan simulation and round-trip verification.

This deliberately implements the RFC 4511 operation semantics directly
(including modifyDN new-superior moves with proper RDN attribute handling
and non-leaf checks) instead of driving ldap3's mock strategy, because that
strategy's modifyDN move path keeps the old entry around under some flag
combinations and therefore does not model server behaviour precisely enough
for compensating-operation generation.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ldap3.utils.dn import safe_dn

from .values import normalize_values


class MockDITError(Exception):
    """An operation could not be applied to the mock DIT.

    ``result_code`` mirrors the numeric LDAP result codes that matter for a
    plan reviewer (noSuchObject=32, entryAlreadyExists=68, notAllowedOnNonLeaf=66).
    """

    def __init__(self, message: str, result_code: int = 80):
        super().__init__(message)
        self.result_code = result_code


NO_SUCH_OBJECT = 32
ENTRY_ALREADY_EXISTS = 68
NOT_ALLOWED_ON_NON_LEAF = 66
NAMING_VIOLATION = 64
PROTOCOL_ERROR = 2
UNWILLING_TO_PERFORM = 53


def parse_rdn(rdn: str) -> List[Tuple[str, str]]:
    """Parse a (possibly multi-valued) RDN into [(attribute, unescaped_value)]."""
    avas: List[Tuple[str, str]] = []
    for part in _split_top_level(rdn, "+"):
        attr, sep, raw_value = part.partition("=")
        if not sep:
            raise MockDITError("malformed RDN %r" % rdn, NAMING_VIOLATION)
        avas.append((attr.strip(), _unescape_dn_value(raw_value.strip())))
    if not avas:
        raise MockDITError("empty RDN", NAMING_VIOLATION)
    return avas


def _split_top_level(value: str, separator: str) -> List[str]:
    parts: List[str] = []
    current = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\":
            current.append(value[index : index + 2])
            index += 2
            continue
        if char == separator:
            parts.append("".join(current))
            current = []
            index += 1
            continue
        current.append(char)
        index += 1
    parts.append("".join(current))
    return parts


def _unescape_dn_value(value: str) -> str:
    result = []
    index = 0
    while index < len(value):
        char = value[index]
        if char != "\\":
            result.append(char)
            index += 1
            continue
        if index + 3 <= len(value) and value[index + 1 : index + 3].isalnum():
            result.append(chr(int(value[index + 1 : index + 3], 16)))
            index += 3
        else:
            result.append(value[index + 1])
            index += 2
    return "".join(result)


class MockDIT:
    """Dict keyed by normalised DN holding ordered {attribute: [bytes]} entries."""

    def __init__(self, snapshot: Optional[Dict[str, Dict[str, Any]]] = None):
        self.entries: Dict[str, Dict[str, List[bytes]]] = {}
        self.ids: Dict[str, str] = {}
        self._next_id = 0
        if snapshot:
            self.load_snapshot(snapshot)

    def load_snapshot(self, snapshot: Dict[str, Dict[str, Any]]) -> None:
        for dn, attributes in snapshot.items():
            self.add(dn, attributes, exist_ok=False)

    def _new_id(self) -> str:
        self._next_id += 1
        return "entry-%d" % self._next_id

    @staticmethod
    def normalize_dn(dn: str) -> str:
        return safe_dn(dn)

    def parent_dn(self, dn: str) -> Optional[str]:
        normalized = self.normalize_dn(dn)
        components = _split_top_level(normalized, ",")
        if len(components) <= 1:
            return None
        return self.normalize_dn(",".join(components[1:]))

    def has_children(self, dn: str) -> bool:
        normalized = self.normalize_dn(dn)
        if normalized not in self.entries:
            raise MockDITError("no such object %s" % dn, NO_SUCH_OBJECT)
        prefix = normalized + ","
        return any(existing.startswith(prefix) for existing in self.entries)

    def add(self, dn: str, attributes: Dict[str, Any], exist_ok: bool = False) -> str:
        normalized = self.normalize_dn(dn)
        if normalized in self.entries:
            raise MockDITError("entry already exists: %s" % dn, ENTRY_ALREADY_EXISTS)
        prepared = {attr: normalize_values(values) for attr, values in attributes.items()}
        for attribute, value in parse_rdn(_split_top_level(normalized, ",")[0]):
            prepared.setdefault(attribute, [])
            encoded = value.encode("utf-8")
            if encoded not in prepared[attribute]:
                prepared[attribute].append(encoded)
        self.entries[normalized] = prepared
        self.ids[normalized] = self._new_id()
        return self.ids[normalized]

    def delete(self, dn: str) -> Dict[str, List[bytes]]:
        normalized = self.normalize_dn(dn)
        if normalized not in self.entries:
            raise MockDITError("no such object: %s" % dn, NO_SUCH_OBJECT)
        if any(existing.endswith("," + normalized) for existing in self.entries):
            raise MockDITError("not allowed on non-leaf: %s still has subordinates" % dn,
                               NOT_ALLOWED_ON_NON_LEAF)
        entry = self.entries.pop(normalized)
        self.ids.pop(normalized)
        return copy.deepcopy(entry)

    def modify(self, dn: str, changes: List[Dict[str, Any]]) -> None:
        normalized = self.normalize_dn(dn)
        if normalized not in self.entries:
            raise MockDITError("no such object: %s" % dn, NO_SUCH_OBJECT)
        entry = self.entries[normalized]
        for change in changes:
            operation = change["operation"].lower()
            attribute = change["attribute"]
            values = normalize_values(change.get("values"))
            existing = entry.setdefault(attribute, [])
            if operation == "add":
                if any(value in existing for value in values):
                    raise MockDITError(
                        "attributeOrValueExists adding %s to %s" % (attribute, dn), 20)
                existing.extend(values)
            elif operation == "delete":
                if not values:
                    if attribute not in entry:
                        raise MockDITError(
                            "no such attribute %s on %s" % (attribute, dn), 16)
                    del entry[attribute]
                    continue
                for value in values:
                    try:
                        existing.remove(value)
                    except ValueError:
                        raise MockDITError(
                            "no such attribute value for %s on %s" % (attribute, dn), 16)
                if not existing:
                    del entry[attribute]
            elif operation == "replace":
                if values:
                    entry[attribute] = values
                else:
                    entry.pop(attribute, None)
            else:
                raise MockDITError("unknown modify operation %r" % operation, PROTOCOL_ERROR)

    def modify_dn(self, dn: str, new_rdn: str, delete_old_rdn: bool,
                  new_superior: Optional[str] = None) -> Tuple[str, List[Tuple[str, bytes, bool]],
                                                                List[Tuple[str, bytes, bool]]]:
        """Apply modDN.

        Returns ``(new_dn, removed_rdn_values, added_rdn_values)`` where each
        rdn-value triple is ``(attribute, value, was_present_before)`` for the
        removed list and ``(attribute, value, is_present_after)`` for added.
        """
        normalized = self.normalize_dn(dn)
        if normalized not in self.entries:
            raise MockDITError("no such object: %s" % dn, NO_SUCH_OBJECT)
        new_avas = parse_rdn(new_rdn)
        components = _split_top_level(normalized, ",")
        old_avas = parse_rdn(components[0])
        old_parent = ",".join(components[1:])
        if new_superior is not None:
            parent_normalized = self.normalize_dn(new_superior)
            if parent_normalized and parent_normalized not in self.entries:
                raise MockDITError("new superior does not exist: %s" % new_superior, NO_SUCH_OBJECT)
        else:
            parent_normalized = old_parent
        if new_rdn.strip() == "":
            raise MockDITError("newRDN is empty", NAMING_VIOLATION)
        new_dn = self.normalize_dn(
            new_rdn + ("," + parent_normalized if parent_normalized else ""))
        if new_dn in self.entries:
            raise MockDITError("entry already exists at %s" % new_dn, ENTRY_ALREADY_EXISTS)

        entry = self.entries[normalized]
        removed: List[Tuple[str, bytes, bool]] = []
        added: List[Tuple[str, bytes, bool]] = []
        new_map = {attr: value.encode("utf-8") for attr, value in new_avas}
        old_map = {attr: value.encode("utf-8") for attr, value in old_avas}

        for attr, value in old_map.items():
            if delete_old_rdn and new_map.get(attr) != value:
                present = value in entry.get(attr, [])
                if present:
                    entry.setdefault(attr, []).remove(value)
                    if not entry[attr]:
                        del entry[attr]
                removed.append((attr, value, present))
        for attr, value in new_map.items():
            if old_map.get(attr) != value:
                present_after = value in entry.get(attr, [])
                if not present_after:
                    entry.setdefault(attr, []).append(value)
                added.append((attr, value, present_after))

        del self.entries[normalized]
        self.entries[new_dn] = entry
        identity = self.ids.pop(normalized)
        self.ids[new_dn] = identity
        # renaming/moving a non-leaf relocates the whole subtree: child DNs
        # end with ",<old parent dn>", they become ",<new dn>" + remainder
        suffix = "," + normalized
        moved_children = [child for child in list(self.entries) if child.endswith(suffix)]
        for child in moved_children:
            child_entry = self.entries.pop(child)
            child_id = self.ids.pop(child)
            relocated = child[: -len(suffix)] + "," + new_dn
            self.entries[relocated] = child_entry
            self.ids[relocated] = child_id
        return new_dn, removed, added

    # ----- verification helpers -----

    def snapshot_copy(self) -> Dict[str, Dict[str, List[bytes]]]:
        return copy.deepcopy(self.entries)

    def diff(self, other: Dict[str, Dict[str, List[bytes]]]) -> List[str]:
        problems: List[str] = []
        a = self.entries
        b = other
        for dn in sorted(set(a) | set(b)):
            if dn not in a:
                problems.append("missing dn: %s" % dn)
                continue
            if dn not in b:
                problems.append("unexpected dn: %s" % dn)
                continue
            attrs_a = a[dn]
            attrs_b = b[dn]
            if set(attrs_a) != set(attrs_b):
                problems.append("attribute set differs for %s: %r vs %r"
                                % (dn, sorted(attrs_a), sorted(attrs_b)))
                continue
            for attribute in attrs_a:
                if list(attrs_a[attribute]) != list(attrs_b[attribute]):
                    problems.append("values differ for %s on %s: %r vs %r"
                                    % (attribute, dn, attrs_a[attribute], attrs_b[attribute]))
        return problems


def apply_change_records(dit: "MockDIT", records: Iterable[Dict[str, Any]]) -> None:
    """Apply parsed LDIF change records to *dit* in order, raising on the first error."""
    for record in records:
        change_type = record["changetype"].lower()
        if change_type == "add":
            dit.add(record["dn"], record["attributes"])
        elif change_type == "delete":
            dit.delete(record["dn"])
        elif change_type == "modify":
            dit.modify(record["dn"], record["changes"])
        elif change_type in ("moddn", "modrdn"):
            dit.modify_dn(
                record["dn"],
                record["newrdn"],
                record["deleteoldrdn"],
                record.get("newsuperior"),
            )
        else:
            raise MockDITError("unsupported changetype %r" % change_type, PROTOCOL_ERROR)
