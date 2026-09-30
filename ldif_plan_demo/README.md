# Reversible LDIF change-plan demo

Plan-only workflow: nothing is ever sent to a live LDAP server.  All changes
are simulated and verified against an in-memory mock DIT (RFC 4511 semantics,
including subtree moves on modDN).

## Inputs

- `snapshot.json` — current entry set. Values are JSON strings for text, or
  `{"type": "binary", "base64": "..."}` for binary attributes.
- `operations.json` — ordered change requests:
  - `{"operation": "add", "dn": ..., "attributes": {...}}`
  - `{"operation": "delete", "dn": ...}` (non-leaf delete is rejected and
    flagged, because it cannot be safely reversed without subtree guarantees)
  - `{"operation": "modify", "dn": ..., "changes": [{"operation":
    "add|delete|replace", "attribute": ..., "values": [...]}]}` — an empty
    `values` list means the whole attribute is deleted / replaced with no
    values; old values are always taken from the snapshot, never fabricated
  - `{"operation": "moddn", "dn": ..., "newrdn": ..., "deleteoldrdn": bool,
    "newsuperior": "..."}` (`modrdn`/`rename`/`move` are aliases)

## Run

```
.venv/bin/python -m ldifplan plan \
    --snapshot ldif_plan_demo/snapshot.json \
    --operations ldif_plan_demo/operations.json \
    --outdir ldif_plan_demo/out

.venv/bin/python -m ldifplan verify \
    --snapshot ldif_plan_demo/snapshot.json \
    --forward ldif_plan_demo/out/forward.ldif \
    --reverse ldif_plan_demo/out/reverse.ldif \
    --report ldif_plan_demo/out/plan_report.json
```

Or simply `.venv/bin/python ldif_plan_demo/run_demo.py`.

## Outputs

- `out/forward.ldif` — forward change records (operations in the reversible
  range only); RFC 2849 with 77-octet line folding and `::` base64 for binary
  or otherwise non-SAFE-CHAR values (leading/trailing spaces, non-ASCII, NUL).
- `out/reverse.ldif` — compensation records, already in reverse execution
  order. modDN compensation always addresses the entry location current at
  that point of the rollback, restores any RDN attribute values the forward
  rename deleted, then moves the entry back.
- `out/plan_report.json` — per-operation `reversible | invalid | blocked`
  status with the reason for anything outside the reversible range, plus
  `excluded_dns`.

The demo intentionally includes cases that cannot be reliably reversed:

| # | case | outcome |
|---|------|---------|
| 6 | modify on an entry absent from the snapshot | `invalid` (noSuchObject 32) |
| 7 | delete of a non-leaf container | `invalid` (notAllowedOnNonLeaf 66) |
| 8 | unsupported operation type (password modify) | `invalid` (unsupported) |
| 1, 9 | other changes on the same entry as #8 | `blocked` — the whole entry change is withheld rather than emitting partial compensation |
