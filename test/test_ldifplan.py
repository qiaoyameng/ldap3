"""Tests for reversible LDIF plan generation, LDIF transport and mock DIT round trips."""

import base64

import pytest

from ldifplan import ChangePlanner, parse_ldif_changes
from ldifplan.ldif import fold_line, needs_base64, render_ldif, unfold_ldif
from ldifplan.mockdit import MockDIT, MockDITError, apply_change_records
from ldifplan.planner import STATUS_BLOCKED, STATUS_INVALID, STATUS_REVERSIBLE


BASE = {
    "dc=example,dc=com": {"objectClass": [b"top", b"domain"], "dc": [b"example"]},
    "ou=people,dc=example,dc=com": {"objectClass": [b"top", b"organizationalUnit"],
                                    "ou": [b"people"]},
    "cn=Ann,ou=people,dc=example,dc=com": {
        "objectClass": [b"top", b"person", b"inetOrgPerson"],
        "cn": [b"Ann"],
        "sn": [b"X"],
        "mail": [b"a1@example.com", b"a2@example.com"],
    },
}


# ----- LDIF transport -----

def test_needs_base64_rules():
    assert not needs_base64(b"plain ascii")
    assert needs_base64(b" leading space")
    assert needs_base64(b"trailing space ")
    assert needs_base64(b"\x00nul")
    assert needs_base64(b"unicode \xc3\xa9")
    assert not needs_base64(b"")


def test_fold_and_unfold_roundtrip_long_binary():
    blob = bytes(range(1, 251)) * 4
    record = {"dn": "cn=Ann,ou=people,dc=example,dc=com", "changetype": "add",
              "attributes": {"jpegPhoto": [blob], "cn": [b"Ann"], "x": [b"y" * 300]}}
    text = render_ldif([record])
    for line in text.splitlines():
        if line and not line.startswith("#"):
            assert len(line.encode("utf-8")) <= 77
    parsed = parse_ldif_changes(text)
    assert parsed[0]["attributes"]["jpegPhoto"] == [blob]
    assert parsed[0]["attributes"]["x"] == [b"y" * 300]


def test_fold_keeps_multibyte_chars_intact():
    long_unicode = "变更内容" * 40
    line = "description: " + long_unicode
    folded = fold_line(line)
    assert unfold_ldif(folded) == [line]


def test_empty_value_replace_renders_bare_attribute():
    record = {"dn": "cn=Ann,ou=people,dc=example,dc=com", "changetype": "modify",
              "changes": [{"operation": "replace", "attribute": "mail", "values": []}]}
    text = render_ldif([record])
    assert "replace: mail\nmail:\n" in text
    parsed = parse_ldif_changes(text)
    assert parsed[0]["changes"][0]["values"] == []


def test_leading_space_value_base64():
    record = {"dn": "cn=Ann,ou=people,dc=example,dc=com", "changetype": "modify",
              "changes": [{"operation": "add", "attribute": "description",
                           "values": [" starts with space".encode("utf-8")]}]}
    text = render_ldif([record])
    assert "description::" in text
    parsed = parse_ldif_changes(text)
    assert parsed[0]["changes"][0]["values"] == [b" starts with space"]


def test_modrdn_keyword_accepted():
    text = """dn: cn=Ann,ou=people,dc=example,dc=com
changetype: modrdn
newrdn: cn=Bob
deleteoldrdn: 0
newsuperior: dc=example,dc=com
"""
    parsed = parse_ldif_changes(text)
    assert parsed[0]["changetype"] == "moddn"
    assert parsed[0]["newrdn"] == "cn=Bob"
    assert parsed[0]["deleteoldrdn"] is False
    assert parsed[0]["newsuperior"] == "dc=example,dc=com"


# ----- mock DIT semantics -----

def test_modify_dn_moves_subtree():
    dit = MockDIT({
        "dc=e": {"o": [b"e"]},
        "ou=a,dc=e": {"ou": [b"a"]},
        "cn=x,ou=a,dc=e": {"cn": [b"x"]},
    })
    dit.modify_dn("ou=a,dc=e", "ou=b", True)
    assert "ou=b,dc=e" in dit.entries
    assert "cn=x,ou=b,dc=e" in dit.entries
    assert "ou=a,dc=e" not in dit.entries


def test_delete_nonleaf_rejected():
    dit = MockDIT(BASE)
    with pytest.raises(MockDITError) as exc:
        dit.delete("ou=people,dc=example,dc=com")
    assert exc.value.result_code == 66


def test_modify_requires_existing_value_for_delete():
    dit = MockDIT(BASE)
    with pytest.raises(MockDITError):
        dit.modify("cn=Ann,ou=people,dc=example,dc=com",
                   [{"operation": "delete", "attribute": "mail", "values": [b"missing"]}])


# ----- planner: reversible operations -----

def test_multivalued_add_delete_replace_roundtrip():
    ops = [
        {"operation": "modify", "dn": "cn=Ann,ou=people,dc=example,dc=com", "changes": [
            {"operation": "add", "attribute": "mail", "values": [b"a3@example.com"]},
            {"operation": "delete", "attribute": "mail", "values": [b"a2@example.com"]},
            {"operation": "replace", "attribute": "title", "values": [b"Engineer", b"Lead"]},
        ]},
    ]
    result = ChangePlanner(BASE).plan(ops)
    assert result.reversible
    verify = MockDIT(BASE)
    apply_change_records(verify, result.forward_records)
    entry = verify.entries["cn=Ann,ou=people,dc=example,dc=com"]
    assert entry["mail"] == [b"a1@example.com", b"a3@example.com"]
    apply_change_records(verify, result.reverse_records)
    assert verify.entries == result.original_snapshot


def test_replace_with_empty_restores_old_values_without_invention():
    ops = [
        {"operation": "modify", "dn": "cn=Ann,ou=people,dc=example,dc=com", "changes": [
            {"operation": "replace", "attribute": "mail", "values": []},
        ]},
    ]
    result = ChangePlanner(BASE).plan(ops)
    changes = result.reverse_records[0]["changes"]
    assert changes == [{"operation": "replace", "attribute": "mail",
                        "values": [b"a1@example.com", b"a2@example.com"]}]
    verify = MockDIT(BASE)
    apply_change_records(verify, result.forward_records)
    apply_change_records(verify, result.reverse_records)
    assert verify.entries == result.original_snapshot


def test_binary_value_roundtrip():
    blob = bytes(range(1, 255))
    snapshot = {"cn=x,dc=e": {"objectClass": [b"top"], "cn": [b"x"]}}
    ops = [{"operation": "modify", "dn": "cn=x,dc=e",
            "changes": [{"operation": "add", "attribute": "jpegPhoto",
                         "values": [{"type": "binary",
                                     "base64": base64.b64encode(blob).decode()}]}]}]
    result = ChangePlanner(snapshot).plan(ops)
    text = render_ldif(result.forward_records) + "\n" + render_ldif(result.reverse_records)
    parsed_forward, parsed_reverse = parse_ldif_changes(render_ldif(result.forward_records)), \
        parse_ldif_changes(render_ldif(result.reverse_records))
    verify = MockDIT(snapshot)
    apply_change_records(verify, parsed_forward)
    assert verify.entries["cn=x,dc=e"]["jpegPhoto"] == [blob]
    apply_change_records(verify, parsed_reverse)
    assert verify.entries == result.original_snapshot


def test_moddn_rename_reverse_targets_new_address():
    ops = [{"operation": "moddn", "dn": "cn=Ann,ou=people,dc=example,dc=com",
            "newrdn": "cn=Ann Liu", "deleteoldrdn": True}]
    result = ChangePlanner(BASE).plan(ops)
    assert result.reversible
    assert result.operations[0].forward_dn == "cn=Ann,ou=people,dc=example,dc=com"
    assert result.operations[0].target_dn == "cn=Ann Liu,ou=people,dc=example,dc=com"
    reverse_modify, reverse_moddn = result.reverse_records
    assert reverse_modify["dn"] == "cn=Ann Liu,ou=people,dc=example,dc=com"
    assert reverse_moddn["dn"] == "cn=Ann Liu,ou=people,dc=example,dc=com"
    assert reverse_moddn["newrdn"] == "cn=Ann"
    verify = MockDIT(BASE)
    apply_change_records(verify, parse_ldif_changes(render_ldif(result.forward_records)))
    assert verify.entries["cn=Ann Liu,ou=people,dc=example,dc=com"]["cn"] == [b"Ann Liu"]
    apply_change_records(verify, parse_ldif_changes(render_ldif(result.reverse_records)))
    assert verify.entries == result.original_snapshot


def test_moddn_move_preserves_old_rdn_value():
    snapshot = dict(BASE)
    snapshot["ou=other,dc=example,dc=com"] = {"objectClass": [b"top", b"organizationalUnit"],
                                              "ou": [b"other"]}
    ops = [{"operation": "moddn", "dn": "cn=Ann,ou=people,dc=example,dc=com",
            "newrdn": "cn=Ann", "deleteoldrdn": False,
            "newsuperior": "ou=other,dc=example,dc=com"}]
    result = ChangePlanner(snapshot).plan(ops)
    verify = MockDIT(snapshot)
    apply_change_records(verify, result.forward_records)
    moved = verify.entries["cn=Ann,ou=other,dc=example,dc=com"]
    assert moved["cn"] == [b"Ann"]
    apply_change_records(verify, result.reverse_records)
    assert verify.entries == result.original_snapshot


def test_add_then_delete_roundtrip():
    ops = [
        {"operation": "add", "dn": "cn=New,ou=people,dc=example,dc=com",
         "attributes": {"objectClass": [b"top", b"person"], "cn": [b"New"], "sn": [b"N"]}},
        {"operation": "modify", "dn": "cn=New,ou=people,dc=example,dc=com",
         "changes": [{"operation": "add", "attribute": "mail", "values": [b"n@example.com"]}]},
        {"operation": "delete", "dn": "cn=New,ou=people,dc=example,dc=com"},
    ]
    result = ChangePlanner(BASE).plan(ops)
    assert result.reversible
    verify = MockDIT(BASE)
    apply_change_records(verify, result.forward_records)
    assert "cn=New,ou=people,dc=example,dc=com" not in verify.entries
    apply_change_records(verify, result.reverse_records)
    assert verify.entries == result.original_snapshot


# ----- planner: non-reversible handling -----

def test_missing_entry_marked_invalid_with_reason():
    ops = [{"operation": "modify", "dn": "cn=Nope,ou=people,dc=example,dc=com",
            "changes": [{"operation": "add", "attribute": "mail", "values": [b"x"]}]}]
    result = ChangePlanner(BASE).plan(ops)
    assert result.operations[0].status == STATUS_INVALID
    assert "resultCode=32" in result.operations[0].reason
    assert result.forward_records == []
    assert result.reverse_records == []


def test_duplicate_add_marked_invalid():
    ops = [{"operation": "add", "dn": "cn=Ann,ou=people,dc=example,dc=com",
            "attributes": {"cn": [b"Ann"]}}]
    result = ChangePlanner(BASE).plan(ops)
    assert result.operations[0].status == STATUS_INVALID
    assert "68" in result.operations[0].reason


def test_unsupported_operation_marked_invalid():
    ops = [{"operation": "extendedPasswordReset", "dn": "cn=Ann,ou=people,dc=example,dc=com"}]
    result = ChangePlanner(BASE).plan(ops)
    assert result.operations[0].status == STATUS_INVALID
    assert "unsupported change type" in result.operations[0].reason


def test_taint_blocks_all_operations_on_same_entry():
    ops = [
        {"operation": "modify", "dn": "cn=Ann,ou=people,dc=example,dc=com",
         "changes": [{"operation": "add", "attribute": "mail", "values": [b"z@example.com"]}]},
        {"operation": "passwordModify", "dn": "cn=Ann,ou=people,dc=example,dc=com"},
        {"operation": "modify", "dn": "cn=Ann,ou=people,dc=example,dc=com",
         "changes": [{"operation": "add", "attribute": "title", "values": [b"T"]}]},
    ]
    result = ChangePlanner(BASE).plan(ops)
    statuses = [op.status for op in result.operations]
    assert statuses == [STATUS_BLOCKED, STATUS_INVALID, STATUS_BLOCKED]
    assert "cn=Ann,ou=people,dc=example,dc=com" in result.excluded_dns
    assert result.forward_records == []
    assert not result.verification_problems


def test_reversible_range_still_restores_with_other_entries_tainted():
    ops = [
        {"operation": "modify", "dn": "cn=Ann,ou=people,dc=example,dc=com",
         "changes": [{"operation": "add", "attribute": "mail", "values": [b"z@example.com"]}]},
        {"operation": "modify", "dn": "cn=Ghost,ou=people,dc=example,dc=com",
         "changes": [{"operation": "add", "attribute": "mail", "values": [b"g"]}]},
    ]
    result = ChangePlanner(BASE).plan(ops)
    verify = MockDIT(BASE)
    apply_change_records(verify, result.forward_records)
    apply_change_records(verify, result.reverse_records)
    assert not result.verification_problems
    assert verify.entries["cn=Ann,ou=people,dc=example,dc=com"] == \
        result.original_snapshot["cn=Ann,ou=people,dc=example,dc=com"]


def test_demo_files_forward_then_reverse_restores_reversible_range(tmp_path):
    import copy
    import json
    import os

    from ldifplan.cli import load_operations, load_snapshot
    from ldifplan.ldif import write_ldif
    from ldifplan.planner import ChangePlanner

    demo_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "ldif_plan_demo")
    snapshot = load_snapshot(os.path.join(demo_dir, "snapshot.json"))
    operations = load_operations(os.path.join(demo_dir, "operations.json"))

    result = ChangePlanner(snapshot).plan(operations)
    assert not result.verification_problems
    statuses = [op.status for op in result.operations]
    assert statuses.count(STATUS_REVERSIBLE) == 6
    assert statuses.count(STATUS_INVALID) == 2
    assert statuses.count(STATUS_BLOCKED) == 2

    forward_path = tmp_path / "forward.ldif"
    reverse_path = tmp_path / "reverse.ldif"
    write_ldif(str(forward_path), result.forward_records)
    write_ldif(str(reverse_path), result.reverse_records)

    forward = parse_ldif_changes(forward_path.read_text(encoding="utf-8"))
    reverse = parse_ldif_changes(reverse_path.read_text(encoding="utf-8"))
    dit = MockDIT(copy.deepcopy(snapshot))
    apply_change_records(dit, forward)
    apply_change_records(dit, reverse)

    excluded = set(result.excluded_dns)
    in_scope = lambda dn: not any(dn == e or dn.startswith(e + ",") for e in excluded)
    for dn, entry in result.original_snapshot.items():
        if in_scope(dn):
            assert dit.entries[dn] == entry
    # forward LDIF only ever references in-scope entries
    for record in result.forward_records:
        assert all(in_scope(record["dn"]) for _ in [0])
