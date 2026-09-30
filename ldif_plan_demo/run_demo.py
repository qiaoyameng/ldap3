"""End-to-end demo: generate the plan, apply forward then reverse to a mock DIT."""

import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ldifplan.cli import load_operations, load_snapshot
from ldifplan.ldif import parse_ldif_changes, render_ldif, write_ldif
from ldifplan.mockdit import MockDIT, apply_change_records
from ldifplan.planner import ChangePlanner, STATUS_REVERSIBLE

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")


def main() -> int:
    snapshot = load_snapshot(os.path.join(HERE, "snapshot.json"))
    operations = load_operations(os.path.join(HERE, "operations.json"))

    result = ChangePlanner(snapshot).plan(operations)
    os.makedirs(OUT, exist_ok=True)
    write_ldif(os.path.join(OUT, "forward.ldif"), result.forward_records,
               "Forward LDIF (plan only). See plan_report.json for excluded operations.")
    write_ldif(os.path.join(OUT, "reverse.ldif"), result.reverse_records,
               "Compensation LDIF in reverse execution order.")
    with open(os.path.join(OUT, "plan_report.json"), "w", encoding="utf-8") as handle:
        json.dump(result.report(), handle, ensure_ascii=False, indent=2)

    # Independent verification: parse the text files back from disk and apply
    # them to a fresh mock DIT, as `ldifplan verify` does.
    forward = parse_ldif_changes(open(os.path.join(OUT, "forward.ldif"), encoding="utf-8").read())
    reverse = parse_ldif_changes(open(os.path.join(OUT, "reverse.ldif"), encoding="utf-8").read())

    original = MockDIT(copy.deepcopy(snapshot)).snapshot_copy()
    dit = MockDIT(copy.deepcopy(snapshot))
    apply_change_records(dit, forward)
    assert dit.entries != original, "forward plan changed nothing"
    apply_change_records(dit, reverse)

    excluded = set(result.excluded_dns)
    in_scope = lambda dn: not any(dn == e or dn.startswith(e + ",") for e in excluded)
    for dn in original:
        if in_scope(dn):
            assert dit.entries.get(dn) == original[dn], "not restored: %s" % dn
    print("OK: forward then reverse restored %d in-scope entries exactly; "
          "excluded: %s" % (sum(1 for dn in original if in_scope(dn)),
                           ", ".join(sorted(excluded)) or "-"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
