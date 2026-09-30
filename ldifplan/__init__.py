"""Reversible LDIF change-plan generation on top of ldap3.

The package turns an entry snapshot plus a sequence of change operations
into a *plan* made of RFC 2849 LDIF change records:

* a forward LDIF implementing the requested changes;
* a reverse LDIF (compensation) that restores the snapshot for every entry
  inside the reversible range;
* a JSON report describing, per operation, whether it is reversible, the
  reason when it is not, and the addresses targeted by each side.

Nothing here executes changes against a real directory.  Changes are only
applied to an in-memory mock DIT (:mod:`ldifplan.mockdit`) used both for
planning and for verification.
"""

from .planner import ChangePlanner, PlannedOperation, PlanResult
from .ldif import (
    LDIFParseError,
    fold_line,
    needs_base64,
    parse_ldif_changes,
    render_change_record,
    render_ldif,
    unfold_ldif,
    write_ldif,
)
from .mockdit import MockDIT, MockDITError
from .values import decode_json_value, encode_json_value, normalize_values

__all__ = [
    "ChangePlanner",
    "PlannedOperation",
    "PlanResult",
    "LDIFParseError",
    "MockDIT",
    "MockDITError",
    "fold_line",
    "needs_base64",
    "parse_ldif_changes",
    "render_change_record",
    "render_ldif",
    "unfold_ldif",
    "write_ldif",
    "decode_json_value",
    "encode_json_value",
    "normalize_values",
]
