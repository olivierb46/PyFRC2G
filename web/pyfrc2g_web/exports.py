"""
Multi-firewall export (dashboard filters): an Excel workbook (summary, findings, accepted
risks, changes) or a PDF summary for management reviews.

items: [{"gateway": gateway record with site / owner / tags, "data": latest analysis data or None}].
"""

import io
from datetime import datetime
from xml.sax.saxutils import escape

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
SUMMARY_HEADER = ["Firewall", "Type", "Source", "Site", "Owner", "Tags", "Last analysis", "Risk score", "Level",
                  "Rules", "Critical", "High", "Medium", "Low", "Accepted risks", "Changes"]
FINDING_HEADER = ["Firewall", "Site", "Severity", "Check", "Interface", "Rule order", "Rule", "Detail"]
ACCEPTED_HEADER = ["Firewall", "Site", "Severity", "Check", "Rule", "Reason", "Owner", "Expires"]
CHANGE_HEADER = ["Firewall", "Site", "Change", "Interface", "Rule order", "Rule", "Detail"]
LEVEL_COLORS = {"CRITICAL": "C0392B", "HIGH": "E67E22", "MODERATE": "F1C40F", "LOW": "27AE60"}


def _summary_row(item):
    gw, data = item["gateway"], item["data"] or {}
    severities = data.get("severities") or {}
    changes = data.get("changes")
    return [gw["name"], gw.get("gateway_type") or "", "API" if gw.get("kind") == "api" else "file",
            gw.get("site") or "", gw.get("owner") or "", ", ".join(gw.get("tags") or []), gw.get("updated") or "",
            gw.get("score"), gw.get("level") or "", gw.get("rules") or 0,
            *(severities.get(s, 0) for s in SEVERITIES), len(data.get("accepted") or []),
            len(changes) if changes is not None else None]


def _findings(items):
    rows = []
    for item in items:
        gw = item["gateway"]
        for f in (item["data"] or {}).get("audit") or []:
            rows.append([gw["name"], gw.get("site") or "", f.get("SEVERITY"), f.get("CHECK"), f.get("GATEWAY"),
                         f.get("RULE ORDER"), f.get("RULE"), f.get("DETAIL")])
    return rows


def _accepted(items):
    rows = []
    for item in items:
        gw = item["gateway"]
        for f in (item["data"] or {}).get("accepted") or []:
            rows.append([gw["name"], gw.get("site") or "", f.get("SEVERITY"), f.get("CHECK"), f.get("RULE"),
                         f.get("REASON"), f.get("OWNER"), f.get("EXPIRES") or "never"])
    return rows


def _changes(items):
    rows = []
    for item in items:
        gw = item["gateway"]
        for c in (item["data"] or {}).get("changes") or []:
            rows.append([gw["name"], gw.get("site") or "", c.get("CHANGE"), c.get("GATEWAY"), c.get("RULE ORDER"),
                         c.get("RULE"), c.get("DETAIL")])
    return rows


def _xlsx(items, scope):
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    workbook = Workbook()
    sheets = [("Summary", SUMMARY_HEADER, [_summary_row(i) for i in items]),
              ("Findings", FINDING_HEADER, _findings(items)),
              ("Accepted risks", ACCEPTED_HEADER, _accepted(items)),
              ("Changes", CHANGE_HEADER, _changes(items))]
    for number, (title, header, rows) in enumerate(sheets):
        ws = workbook.active if number == 0 else workbook.create_sheet()
        ws.title = title
        ws.append(header)
        for cell in ws[1]:
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill("solid", fgColor="2F6FED")
        for row in rows:
            ws.append(row)
            for cell in ws[ws.max_row]:
                if isinstance(cell.value, str):  # Never a formula: values come from firewall configurations.
                    cell.data_type = "s"
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions
        for index, name in enumerate(header, 1):
            longest = max([len(str(name))] + [len(str(r[index - 1] or "")) for r in rows[:200]])
            ws.column_dimensions[get_column_letter(index)].width = min(60, max(10, longest + 2))
            if name in ("Rule", "Detail", "Reason"):
                for cell in ws[get_column_letter(index)][1:]:
                    cell.alignment = Alignment(wrap_text=True, vertical="top")
        if title == "Summary":
            level_column = SUMMARY_HEADER.index("Level") + 1
            for row in ws.iter_rows(min_row=2):
                color = LEVEL_COLORS.get(row[level_column - 1].value)
                if color:
                    row[level_column - 1].fill = PatternFill("solid", fgColor=color)
    sheet = workbook["Summary"]
    sheet.sheet_properties.tabColor = "2F6FED"
    workbook.properties.title = f"PyFRC2G report: {scope}"
    out = io.BytesIO()
    workbook.save(out)
    return out.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def _pdf(items, scope):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    cell = styles["BodyText"].clone("cell", fontSize=7.5, leading=9)
    head = styles["BodyText"].clone("head", fontSize=7.5, leading=9, textColor=colors.white, fontName="Helvetica-Bold")

    def table(header, rows, widths, level_column=None):
        data = [[Paragraph(escape(h), head) for h in header]]
        data += [[Paragraph(escape(("" if v is None else str(v))[:400]), cell) for v in row] for row in rows]
        t = Table(data, colWidths=[w * mm for w in widths], repeatRows=1)
        style = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2F6FED")),
                 ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CCCCCC")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                 ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F7FB")])]
        if level_column is not None:
            for i, row in enumerate(rows, 1):
                color = LEVEL_COLORS.get(row[level_column])
                if color:
                    style.append(("BACKGROUND", (level_column, i), (level_column, i), colors.HexColor("#" + color)))
        t.setStyle(TableStyle(style))
        return t

    analysed = [i for i in items if i["data"]]
    scores = [i["gateway"]["score"] for i in analysed if i["gateway"].get("score") is not None]
    totals = {s: sum((i["data"].get("severities") or {}).get(s, 0) for i in analysed) for s in SEVERITIES}
    story = [Paragraph("Firewall rules: security review", styles["Title"]),
             Paragraph(escape(f"Scope: {scope} · generated {datetime.now():%Y-%m-%d %H:%M} by PyFRC2G"),
                       styles["Normal"]), Spacer(1, 4 * mm),
             Paragraph(escape(f"{len(items)} firewall(s), {len(analysed)} analysed · average risk score "
                              f"{round(sum(scores) / len(scores)) if scores else '-'} · "
                              + " · ".join(f"{totals[s]} {s.lower()}" for s in SEVERITIES) + " finding(s)"),
                       styles["Normal"]), Spacer(1, 4 * mm)]
    summary = [[r[0], r[1], r[3], r[4], r[6], r[7], r[8], r[9], r[10], r[11], r[14]]
               for r in (_summary_row(i) for i in items)]
    story += [Paragraph("Firewalls", styles["Heading2"]),
              table(["Firewall", "Type", "Site", "Owner", "Last analysis", "Score", "Level", "Rules", "Critical",
                     "High", "Accepted"], summary, [38, 20, 28, 28, 32, 14, 20, 14, 16, 14, 18], level_column=6)]
    serious = [r for r in _findings(items) if r[2] in ("CRITICAL", "HIGH")]
    story += [Spacer(1, 5 * mm), Paragraph(f"Critical and high findings ({len(serious)}"
                                           + (", first 60 shown" if len(serious) > 60 else "") + ")",
                                           styles["Heading2"])]
    story.append(table(FINDING_HEADER[:1] + FINDING_HEADER[2:], [r[:1] + r[2:] for r in serious[:60]],
                       [34, 18, 36, 28, 12, 70, 70]) if serious else Paragraph("None.", styles["Normal"]))
    accepted = _accepted(items)
    if accepted:
        story += [Spacer(1, 5 * mm), Paragraph(f"Accepted risks ({len(accepted)})", styles["Heading2"]),
                  table(ACCEPTED_HEADER[:1] + ACCEPTED_HEADER[2:], [r[:1] + r[2:] for r in accepted[:60]],
                        [34, 18, 36, 60, 70, 22, 22])]
    out = io.BytesIO()
    SimpleDocTemplate(out, pagesize=landscape(A4), leftMargin=10 * mm, rightMargin=10 * mm, topMargin=10 * mm,
                      bottomMargin=10 * mm, title=f"PyFRC2G report: {scope}").build(story)
    return out.getvalue(), "application/pdf"


def build(fmt, items, scope):
    """(content bytes, mime type) of the export; fmt: 'xlsx' or 'pdf'."""
    return (_xlsx if fmt == "xlsx" else _pdf)(items, scope)
