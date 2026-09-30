"""Minimal RFC 2849 (LDIF) reader/writer focused on *change* records.

Supported change types: add, delete, modify, moddn/modrdn.

The writer:
* emits ``attr:: <base64>`` whenever a value is binary or not SAFE-INIT-CHAR
  /SAFE-CHAR safe, or when the attribute value would otherwise be ambiguous
  (leading space, starts with ``:``/``<``, ...);
* folds physical lines at 77 octets of content per RFC 2849 section 2 note 2
  (each continuation line starts with a single space);
* never invents empty values: an attribute present in a modify record with no
  value lines renders as ``attr:`` (the LDIF representation of a delete of the
  whole attribute / replacement with no values), which is distinct from an
  absent attribute.
"""

from __future__ import annotations

import base64
from typing import Any, Dict, Iterable, List, Optional, Tuple


SAFE_CHARS = set(range(0x20, 0x7F))  # %x01-09 / %x0B-0C / %x0E-7F subset we keep ASCII-safe
SAFE_INIT_FORBIDDEN = {ord(" "), ord(":"), ord("<")}
LINE_WIDTH = 77


class LDIFParseError(ValueError):
    """Raised when LDIF text cannot be parsed as change records."""


def needs_base64(data: bytes) -> bool:
    """Return True if *data* must be base64 encoded per RFC 2849 SAFE-CHAR rules."""
    if not data:  # empty value stays a plain empty value
        return False
    for index, byte in enumerate(data):
        if byte in (0x0A, 0x0D, 0x00):  # NUL, LF, CR are never safe
            return True
        if byte < 0x20 or byte > 0x7E:  # non-ASCII / control -> base64
            return True
        if index == 0 and byte in SAFE_INIT_FORBIDDEN:
            return True
        if index == len(data) - 1 and byte == ord(" "):  # trailing space
            return True
    return False


def fold_line(line: str, width: int = LINE_WIDTH) -> str:
    """Fold one logical line to <= *width* UTF-8 content octets per physical line.

    Folding happens after encoding to UTF-8 so the octet limit is exact, but
    splits are realigned to character boundaries; continuation lines start with
    a single space (RFC 2849 section 2, note 2).
    """
    encoded = line.encode("utf-8")
    if len(encoded) <= width:
        return line
    pieces: List[str] = []
    cursor = 0
    first = True
    limit = width
    while cursor < len(encoded):
        take = min(limit, len(encoded) - cursor)
        while take > 0:
            try:
                piece = encoded[cursor : cursor + take].decode("utf-8")
                break
            except UnicodeDecodeError:
                take -= 1
        if not first:
            piece = " " + piece
        pieces.append(piece)
        cursor += take
        first = False
        limit = width - 1  # continuation space
    return "\n".join(pieces)

def _value_spec(attribute: str, value: bytes) -> str:
    if needs_base64(value):
        return "%s:: %s" % (attribute, base64.b64encode(value).decode("ascii"))
    return "%s: %s" % (attribute, value.decode("utf-8"))


def _bare_spec(attribute: str) -> str:
    return "%s:" % attribute


def _dnish_spec(attribute: str, value: str) -> str:
    raw = value.encode("utf-8")
    if needs_base64(raw):
        return "%s:: %s" % (attribute, base64.b64encode(raw).decode("ascii"))
    return "%s: %s" % (attribute, value)


def render_change_record(record: Dict[str, Any]) -> str:
    """Render one parsed change record as folded LDIF text (without trailing blank line)."""
    change_type = record["changetype"].lower()
    lines: List[str] = []
    dn = record["dn"]
    if needs_base64(dn.encode("utf-8")):
        lines.append("dn:: %s" % base64.b64encode(dn.encode("utf-8")).decode("ascii"))
    else:
        lines.append("dn: %s" % dn)

    if change_type == "add":
        lines.append("changetype: add")
        for attribute, values in record["attributes"].items():
            for value in values:
                lines.append(_value_spec(attribute, value))
    elif change_type == "delete":
        lines.append("changetype: delete")
    elif change_type == "modify":
        lines.append("changetype: modify")
        changes = record["changes"]
        for group_index, change in enumerate(changes):
            operation = change["operation"].lower()
            attribute = change["attribute"]
            values = change.get("values", [])
            if group_index:
                lines.append("-")
            lines.append("%s: %s" % (operation, attribute))
            for value in values:
                lines.append(_value_spec(attribute, value))
            if not values:
                lines.append(_bare_spec(attribute))
    elif change_type in ("moddn", "modrdn"):
        keyword = "modrdn" if change_type == "modrdn" else "moddn"
        lines.append("changetype: %s" % keyword)
        lines.append(_dnish_spec("newrdn", record["newrdn"]))
        lines.append("deleteoldrdn: %d" % (1 if record["deleteoldrdn"] else 0))
        if record.get("newsuperior"):
            lines.append(_dnish_spec("newsuperior", record["newsuperior"]))
    else:
        raise ValueError("unsupported changetype %r" % change_type)

    return "\n".join(fold_line(line) for line in lines)


def render_ldif(records: Iterable[Dict[str, Any]], comment: Optional[str] = None) -> str:
    """Render multiple change records separated by blank lines, LF terminated."""
    chunks: List[str] = []
    if comment:
        header = "\n".join(line if line.startswith("#") else "# " + line
                            for line in comment.splitlines())
        chunks.append(header)
    chunks.extend(render_change_record(record) for record in records)
    return "\n\n".join(chunks) + ("\n" if chunks else "")


def write_ldif(path: str, records: Iterable[Dict[str, Any]], comment: Optional[str] = None) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(render_ldif(records, comment))


def unfold_ldif(text: str) -> List[str]:
    """Unfold RFC 2849 folded lines; CR/LF/CRLF are all accepted."""
    logical: List[str] = []
    for raw in text.splitlines():
        if raw.startswith(" ") or raw.startswith("\t"):
            if not logical:
                raise LDIFParseError("continuation line without a preceding line: %r" % raw)
            logical[-1] += raw[1:]
        else:
            logical.append(raw)
    return logical


def _split_attr(line: str) -> Tuple[str, bool, str]:
    colon = line.find(":")
    if colon < 0:
        raise LDIFParseError("malformed LDIF line (no ':'): %r" % line)
    name = line[:colon].strip()
    is_b64 = line[colon + 1 : colon + 2] == ":"
    rest = line[colon + (2 if is_b64 else 1) :]
    if rest[:1] == " ":
        rest = rest[1:]
    return name, is_b64, rest


def _decode_value(is_b64: bool, raw: str) -> bytes:
    if is_b64:
        return base64.b64decode(raw.strip().encode("ascii"))
    return raw.encode("utf-8")


def parse_ldif_changes(text: str) -> List[Dict[str, Any]]:
    """Parse LDIF change records into plain dictionaries.

    Record shapes::

        {"dn": ..., "changetype": "add", "attributes": {attr: [bytes]}}
        {"dn": ..., "changetype": "delete"}
        {"dn": ..., "changetype": "modify", "changes": [
            {"operation": "add|delete|replace", "attribute": ..., "values": [bytes]}]}
        {"dn": ..., "changetype": "moddn|modrdn", "newrdn": str,
         "deleteoldrdn": bool, "newsuperior": str|None}
    """
    lines = unfold_ldif(text)
    records: List[Dict[str, Any]] = []

    blocks: List[List[str]] = [[]]
    for line in lines:
        if not line.strip():
            if blocks[-1]:
                blocks.append([])
            continue
        if line.lstrip().startswith("#"):
            continue
        blocks[-1].append(line)
    if not blocks[-1]:
        blocks.pop()

    for block in blocks:
        record: Dict[str, Any] = {}
        index = 0
        while index < len(block):
            line = block[index]
            name, is_b64, raw = _split_attr(line)
            lname = name.lower()
            if lname == "dn":
                record["dn"] = _decode_value(is_b64, raw).decode("utf-8")
                index += 1
                break
            if lname == "version":
                index += 1
                continue
            raise LDIFParseError("first record line must be 'dn', got %r" % line)

        changetype = None
        while index < len(block):
            name, is_b64, raw = _split_attr(block[index])
            lname = name.lower()
            if lname == "changetype":
                changetype = _decode_value(is_b64, raw).decode("utf-8").strip().lower()
                record["changetype"] = changetype
                index += 1
                break
            if lname == "version":
                index += 1
                continue
            raise LDIFParseError("missing changetype in record for %r" % record.get("dn"))

        if changetype == "add":
            attributes: Dict[str, List[bytes]] = {}
            while index < len(block):
                name, is_b64, raw = _split_attr(block[index])
                attributes.setdefault(name, []).append(_decode_value(is_b64, raw))
                index += 1
            record["attributes"] = attributes
        elif changetype == "delete":
            if index != len(block):
                raise LDIFParseError("delete record for %r must not carry attributes" % record["dn"])
        elif changetype == "modify":
            changes: List[Dict[str, Any]] = []
            current: Optional[Dict[str, Any]] = None
            while index < len(block):
                line = block[index]
                stripped = line.strip()
                if stripped == "-":
                    current = None
                    index += 1
                    continue
                name, is_b64, raw = _split_attr(line)
                lower = name.lower()
                if lower in ("add", "delete", "replace"):
                    current = {"operation": lower, "attribute": raw.strip() if not is_b64
                               else _decode_value(True, raw).decode("utf-8"), "values": []}
                    changes.append(current)
                elif raw != "" or is_b64:
                    if current is None:
                        raise LDIFParseError("modify value without add/delete/replace for %r" % record["dn"])
                    current["values"].append(_decode_value(is_b64, raw))
                index += 1
            record["changes"] = changes
        elif changetype in ("moddn", "modrdn"):
            record["changetype"] = "moddn"
            record["newsuperior"] = None
            while index < len(block):
                name, is_b64, raw = _split_attr(block[index])
                lname = name.lower()
                value = _decode_value(is_b64, raw).decode("utf-8").strip()
                if lname == "newrdn":
                    record["newrdn"] = value
                elif lname == "deleteoldrdn":
                    if value not in ("0", "1"):
                        raise LDIFParseError("deleteoldrdn must be 0 or 1 for %r" % record["dn"])
                    record["deleteoldrdn"] = value == "1"
                elif lname == "newsuperior":
                    record["newsuperior"] = value
                else:
                    raise LDIFParseError("unexpected line in moddn record for %r: %r" % (record["dn"], line))
                index += 1
            if "newrdn" not in record or "deleteoldrdn" not in record:
                raise LDIFParseError("moddn record for %r needs newrdn and deleteoldrdn" % record["dn"])
        else:
            raise LDIFParseError("unsupported changetype %r for %r" % (changetype, record.get("dn")))

        records.append(record)

    return records
