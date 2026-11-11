"""
Excel workbook (openpyxl): Summary, Rules, Audit, Changes, Zone matrix, Rule usage and NAT
sheets, with filters, frozen header and colored rows.
"""

import logging

from pyfrc2g.analysis.audit import AUDIT_FIELDNAMES, SEVERITIES, count_by_severity
from pyfrc2g.analysis.exceptions import ACCEPTED_FIELDNAMES
from pyfrc2g.analysis.changes import CHANGES_FIELDNAMES, count_changes
from pyfrc2g.analysis.hits import HITS_FIELDNAMES
from pyfrc2g.analysis.matrix import STATUS_COLORS
from pyfrc2g.model.nat import NAT_FIELDNAMES
from pyfrc2g.model.rules import interface_stats
from pyfrc2g.outputs.pdf import CHANGE_COLORS, SEVERITY_COLORS

ACTION_COLORS = {"pass": "#d4edda", "block": "#f8d7da", "reject": "#f8d7da"}


def _xlsx_sheet(wb, title, fieldnames, rows, color_of=None):
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    # Style objects are created once and shared; cells are addressed by index (ws[row] and
    # ws.max_row rescan the whole sheet, which made large sheets quadratic).
    ws = wb.create_sheet(title)
    ws.append(fieldnames)
    header_font, header_fill = Font(bold=True), PatternFill("solid", fgColor="DFE3EA")
    for col in range(1, len(fieldnames) + 1):
        cell = ws.cell(row=1, column=col)
        cell.font, cell.fill = header_font, header_fill
    alignment = Alignment(vertical="top", wrap_text=True)
    fills = {}
    for index, row in enumerate(rows, start=2):
        ws.append([row.get(f, "") for f in fieldnames])
        color = color_of(row) if color_of else None
        fill = None
        if color:
            fill = fills.get(color) or fills.setdefault(color, PatternFill("solid", fgColor=color.lstrip("#")))
        for col in range(1, len(fieldnames) + 1):
            cell = ws.cell(row=index, column=col)
            cell.alignment = alignment
            if fill:
                cell.fill = fill
    ws.freeze_panes = "A2"
    if rows:
        ws.auto_filter.ref = f"A1:{get_column_letter(len(fieldnames))}{len(rows) + 1}"
    for index, field in enumerate(fieldnames, start=1):
        longest = max([len(str(field))] + [len(str(r.get(field, ""))) for r in rows[:500]])
        ws.column_dimensions[get_column_letter(index)].width = min(max(10, longest + 2), 60)
    return ws


def write_xlsx_report(report, path, rule_fieldnames):
    """Excel workbook: Summary, Rules, Audit, Changes, NAT sheets (with filters)."""
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font
    except ImportError:
        logging.warning("openpyxl not installed: Excel export skipped (pip install openpyxl)")
        return None

    wb = Workbook()
    summary = wb.active
    summary.title = "Summary"
    for key, value in report.metadata():
        summary.append([key, value])
    summary.append([])
    summary.append(["Interface", "Rules", "Pass", "Block", "Reject", "Disabled"])
    for cell in summary[summary.max_row]:
        cell.font = Font(bold=True)
    for iface, s in interface_stats(report.rules).items():
        summary.append([iface, s["total"], s["pass"], s["block"], s["reject"], s["disabled"]])
    summary.append([])
    sev = count_by_severity(report.audit)
    summary.append(["Audit"] + [f"{s}: {sev[s]}" for s in SEVERITIES])
    if report.accepted:
        summary.append(["Accepted risks", len(report.accepted)])
    if report.changes is not None:
        cc = count_changes(report.changes)
        summary.append(["Changes"] + [f"{k.title()}: {v}" for k, v in cc.items()])
    summary.append(["NAT rules", len(report.nat)])
    if report.risk:
        from pyfrc2g.analysis.risk import describe

        summary.append(["Risk score", describe(report.risk)])
        for iface, value in report.risk.get("by_interface", {}).items():
            summary.append([f"  {iface}", value])
    summary.column_dimensions["A"].width = 30
    summary.column_dimensions["B"].width = 70

    _xlsx_sheet(wb, "Rules", rule_fieldnames, report.rules,
                lambda r: ("#E2E3E5" if r.get("DISABLED") == "True"
                           else ACTION_COLORS.get((r.get("ACTION") or "").lower())))
    _xlsx_sheet(wb, "Audit", AUDIT_FIELDNAMES, report.audit,
                lambda r: SEVERITY_COLORS.get(r.get("SEVERITY")))
    if report.accepted:
        _xlsx_sheet(wb, "Accepted risks", ACCEPTED_FIELDNAMES, report.accepted,
                    lambda r: SEVERITY_COLORS.get(r.get("SEVERITY")))
    if report.changes is not None:
        _xlsx_sheet(wb, "Changes", CHANGES_FIELDNAMES, report.changes,
                    lambda r: CHANGE_COLORS.get(r.get("CHANGE")))
    if report.matrix and report.matrix["sources"]:
        _xlsx_matrix(wb, report.matrix)
    if report.hits:
        _xlsx_sheet(wb, "Rule usage", HITS_FIELDNAMES, report.hits,
                    lambda r: {"UNUSED": "#F8D7DA", "STALE": "#FFF3CD"}.get(r.get("STATUS")))
    _xlsx_sheet(wb, "NAT", NAT_FIELDNAMES, report.nat,
                lambda r: "#E2E3E5" if r.get("DISABLED") == "True" else None)
    wb.save(path)
    return path


def _xlsx_matrix(wb, matrix):
    from openpyxl.styles import Alignment, Font, PatternFill

    ws = wb.create_sheet("Zone matrix")
    ws.append(["From / To"] + matrix["destinations"])
    for cell in ws[1]:
        cell.font = Font(bold=True)
    for source in matrix["sources"]:
        values = [source]
        for dest in matrix["destinations"]:
            status, detail = matrix["cells"].get((source, dest), ("", ""))
            values.append(f"{status}: {detail}" if status == "PARTIAL" else status)
        ws.append(values)
        ws.cell(row=ws.max_row, column=1).font = Font(bold=True)
        for col, dest in enumerate(matrix["destinations"], start=2):
            status = matrix["cells"].get((source, dest), ("", ""))[0]
            cell = ws.cell(row=ws.max_row, column=col)
            cell.alignment = Alignment(vertical="top", wrap_text=True)
            if status in STATUS_COLORS:
                cell.fill = PatternFill("solid", fgColor=STATUS_COLORS[status].lstrip("#"))
    ws.column_dimensions["A"].width = 22
    for col in range(2, len(matrix["destinations"]) + 2):
        ws.column_dimensions[ws.cell(row=1, column=col).column_letter].width = 26
    ws.freeze_panes = "B2"
