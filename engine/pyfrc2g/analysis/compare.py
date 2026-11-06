"""
Compare two firewalls (e.g. CARP primary / secondary, pre-production / production).

    pyfrc2g --compare fw1.xml fw2.xml

Rules are matched by interface + RULE ID when both firewalls share identifiers (pfSense CARP
sync keeps the trackers), otherwise by content. The firewall name is removed from the GATEWAY
column so that "fw1/LAN" and "fw2/LAN" are compared. Aliases and NAT rules are compared too.
"""

import logging
import os

from pyfrc2g.analysis.changes import diff_rules
from pyfrc2g.model.rules import interface_part

COMPARE_FIELDNAMES = ["DIFFERENCE", "KIND", "INTERFACE", "RULE ORDER", "RULE ID", "ITEM", "DETAIL"]
LABELS = {"ADDED": "ONLY IN B", "REMOVED": "ONLY IN A", "MODIFIED": "DIFFERENT"}
DIFF_COLORS = {"ONLY IN A": "#f8d7da", "ONLY IN B": "#d4edda", "DIFFERENT": "#fff3cd"}


def _strip_gateway(rows, key="GATEWAY"):
    out = []
    for row in rows:
        copy = {k: v for k, v in row.items() if not k.startswith("_")}
        copy[key] = interface_part(copy.get(key, ""))
        out.append(copy)
    return out


def _shares_ids(rows_a, rows_b):
    ids_a = {r.get("RULE ID") for r in rows_a if r.get("RULE ID")}
    ids_b = {r.get("RULE ID") for r in rows_b if r.get("RULE ID")}
    return bool(ids_a & ids_b)


def compare_rules(rows_a, rows_b):
    a, b = _strip_gateway(rows_a), _strip_gateway(rows_b)
    fields = list(a[0].keys()) if a else []
    if not _shares_ids(a, b):
        fields = [f for f in fields if f != "RULE ID"]  # Content matching.
    out = []
    for change in diff_rules(a, fields, b):
        out.append({"DIFFERENCE": LABELS[change["CHANGE"]], "KIND": "RULE",
                    "INTERFACE": change["GATEWAY"], "RULE ORDER": change["RULE ORDER"],
                    "RULE ID": change["RULE ID"], "ITEM": change["RULE"], "DETAIL": change["DETAIL"]})
    return out


def compare_aliases(aliases_a, aliases_b):
    out = []
    for name in sorted(set(aliases_a) | set(aliases_b)):
        a, b = aliases_a.get(name), aliases_b.get(name)
        if a is None or b is None:
            present = a or b
            out.append({"DIFFERENCE": "ONLY IN B" if a is None else "ONLY IN A", "KIND": "ALIAS",
                        "INTERFACE": "", "RULE ORDER": "", "RULE ID": "",
                        "ITEM": present.get("name", name),
                        "DETAIL": f"{present.get('type', '')}: {present.get('content', '')}"})
            continue
        details = [f"{field}: {a.get(field, '')} -> {b.get(field, '')}"
                   for field in ("type", "content") if (a.get(field) or "") != (b.get(field) or "")]
        if details:
            out.append({"DIFFERENCE": "DIFFERENT", "KIND": "ALIAS", "INTERFACE": "", "RULE ORDER": "",
                        "RULE ID": "", "ITEM": a.get("name", name), "DETAIL": "; ".join(details)})
    return out


def compare_nat(nat_a, nat_b):
    def key(row):
        return tuple((row.get(f) or "") for f in ("TYPE", "INTERFACE", "PROTOCOL", "SOURCE",
                                                    "DESTINATION", "DESTINATION PORT", "TARGET",
                                                    "TARGET PORT", "DISABLED"))

    def text(row):
        return (f"{row.get('TYPE')} {row.get('INTERFACE')} {row.get('SOURCE')} -> "
                f"{row.get('DESTINATION')}:{row.get('DESTINATION PORT')} => "
                f"{row.get('TARGET')}:{row.get('TARGET PORT')}")

    keys_a = {key(r): r for r in nat_a}
    keys_b = {key(r): r for r in nat_b}
    out = []
    for k, row in keys_a.items():
        if k not in keys_b:
            out.append({"DIFFERENCE": "ONLY IN A", "KIND": "NAT", "INTERFACE": row.get("INTERFACE", ""),
                        "RULE ORDER": "", "RULE ID": row.get("RULE ID", ""), "ITEM": text(row),
                        "DETAIL": row.get("COMMENT", "")})
    for k, row in keys_b.items():
        if k not in keys_a:
            out.append({"DIFFERENCE": "ONLY IN B", "KIND": "NAT", "INTERFACE": row.get("INTERFACE", ""),
                        "RULE ORDER": "", "RULE ID": row.get("RULE ID", ""), "ITEM": text(row),
                        "DETAIL": row.get("COMMENT", "")})
    return out


def write_comparison(output_dir, name_a, name_b, differences, meta):
    """Write CSV, HTML and PDF comparison reports. Returns the list of written files."""
    from pyfrc2g.outputs.csv_files import write_csv
    from pyfrc2g.outputs.html_report import write_compare_html
    from pyfrc2g.outputs.pdf import write_compare_pdf

    os.makedirs(output_dir, exist_ok=True)
    base = os.path.join(output_dir, f"compare_{name_a}_vs_{name_b}")
    files = [write_csv(f"{base}.csv", COMPARE_FIELDNAMES, differences),
             write_compare_html(f"{base}.html", name_a, name_b, differences, meta)]
    pdf = write_compare_pdf(f"{base}.pdf", name_a, name_b, differences, meta)
    if pdf:
        files.append(pdf)
    for path in files:
        logging.info(f"✓ Comparison written: {path}")
    return files
