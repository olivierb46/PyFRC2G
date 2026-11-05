"""
Change report: compare the rules of the previous run with the current ones.

Rules are matched by RULE ID (pfSense tracker / OPNsense uuid) when available, otherwise
by their content. RULE ORDER is not compared: inserting one rule would otherwise mark every
following rule as modified.
"""

import csv
import hashlib
import os

CHANGES_FIELDNAMES = ["CHANGE", "GATEWAY", "RULE ORDER", "RULE ID", "RULE", "DETAIL"]
_IDENTITY_FIELDS = ("GATEWAY", "SOURCE", "DESTINATION", "PROTOCOL", "PORT", "ACTION", "COMMENT")
_IGNORED_FIELDS = {"RULE ORDER", "RULE ID"}


def read_rows(csv_path):
    """Read a rules CSV. Returns (rows, fieldnames) or (None, None) if missing."""
    if not csv_path or not os.path.isfile(csv_path):
        return None, None
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        return rows, reader.fieldnames or []


def _content_key(row):
    raw = "\x1f".join((row.get(field) or "").strip() for field in _IDENTITY_FIELDS)
    return "content:" + hashlib.sha1(raw.encode("utf-8")).hexdigest()


def _index(rows, use_ids):
    """Map key -> row; duplicate keys get a #n suffix so nothing is lost."""
    index = {}
    for row in rows:
        rule_id = (row.get("RULE ID") or "").strip() if use_ids else ""
        base = f"id:{row.get('GATEWAY', '')}:{rule_id}" if rule_id else _content_key(row)
        key, n = base, 1
        while key in index:
            n += 1
            key = f"{base}#{n}"
        index[key] = row
    return index


def _summary(row):
    return (f"{row.get('ACTION', '')} {row.get('SOURCE', '')} -> {row.get('DESTINATION', '')} "
            f"[{row.get('PROTOCOL', '')} {row.get('PORT', '')}] {row.get('COMMENT', '')}").strip()


def _change(kind, row, detail=""):
    return {
        "CHANGE": kind,
        "GATEWAY": row.get("GATEWAY", ""),
        "RULE ORDER": row.get("RULE ORDER", ""),
        "RULE ID": row.get("RULE ID", ""),
        "RULE": _summary(row),
        "DETAIL": detail,
    }


def diff_rules(previous_rows, previous_fields, current_rows):
    """
    Compare two rule sets.

    Returns:
        list: Change dicts (CHANGES_FIELDNAMES): ADDED, REMOVED, MODIFIED.
    """
    # Snapshots from older versions have no RULE ID column: fall back to content matching.
    use_ids = "RULE ID" in (previous_fields or [])
    before = _index(previous_rows, use_ids)
    after = _index(current_rows, use_ids)
    changes = []

    for key, row in after.items():
        old = before.get(key)
        if old is None:
            changes.append(_change("ADDED", row))
            continue
        modified = [
            f"{field}: {old.get(field, '')} -> {row.get(field, '')}"
            for field in row
            if field not in _IGNORED_FIELDS and (old.get(field) or "") != (row.get(field) or "")
        ]
        if modified:
            changes.append(_change("MODIFIED", row, "; ".join(modified)))
    for key, row in before.items():
        if key not in after:
            changes.append(_change("REMOVED", row))

    order = {"ADDED": 0, "MODIFIED": 1, "REMOVED": 2}
    return sorted(changes, key=lambda c: (order[c["CHANGE"]], c["GATEWAY"]))


def count_changes(changes):
    counts = {"ADDED": 0, "MODIFIED": 0, "REMOVED": 0}
    for change in changes or []:
        counts[change["CHANGE"]] += 1
    return counts
