"""Value normalisation helpers shared by the planner, LDIF layer and mock DIT."""

from __future__ import annotations

from typing import Any, Iterable, List

from ldap3.utils.conv import to_raw


def normalize_values(values: Any) -> List[bytes]:
    """Return *values* as a list of raw bytes (duplicates preserved in order)."""
    if values is None:
        return []
    if isinstance(values, (bytes, str)) or not isinstance(values, Iterable):
        values = [values]
    result: List[bytes] = []
    for value in values:
        if isinstance(value, dict):
            value = decode_json_value(value)
        raw = to_raw(value)
        if not isinstance(raw, bytes):
            raise TypeError("attribute value must be bytes, str or number, got %r" % (value,))
        result.append(raw)
    return result


def encode_json_value(value: bytes) -> Any:
    """Encode a raw attribute value for the JSON snapshot/report."""
    try:
        return {"type": "text", "value": value.decode("utf-8")}
    except UnicodeDecodeError:
        import base64

        return {"type": "binary", "base64": base64.b64encode(value).decode("ascii")}


def decode_json_value(spec: Any) -> bytes:
    """Decode a JSON value specification (plain string or {type, ...} object)."""
    if isinstance(spec, dict):
        kind = spec.get("type")
        if kind == "binary" or "base64" in spec:
            import base64

            return base64.b64decode(spec["base64"], validate=False)
        if kind in (None, "text"):
            return to_raw(spec.get("value", ""))
        raise ValueError("unknown JSON value type %r" % kind)
    return to_raw(spec)
