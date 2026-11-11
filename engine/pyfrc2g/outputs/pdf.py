"""
PDF reports for PyFRC2G: summary page (with risk score), change / audit / zone matrix /
rule usage / NAT tables, comparison report, and assembly of the final PDF (report pages +
vector graph pages) with bookmarks.
"""

import functools
import html
import logging
import os

from pyfrc2g.analysis.audit import AUDIT_FIELDNAMES, SEVERITIES, count_by_severity
from pyfrc2g.analysis.changes import CHANGES_FIELDNAMES, count_changes
from pyfrc2g.model.nat import NAT_FIELDNAMES
from pyfrc2g.model.rules import interface_stats

SEVERITY_COLORS = {"CRITICAL": "#f8d7da", "HIGH": "#fde2c8", "MEDIUM": "#fff3cd", "LOW": "#e2e3e5"}
CHANGE_COLORS = {"ADDED": "#d4edda", "REMOVED": "#f8d7da", "MODIFIED": "#fff3cd"}


class RunReport:
    """Everything produced for one firewall run, shared by PDF / HTML / Excel outputs."""

    def __init__(self, gateway_name, gateway_type, source, generated_at, rules,
                 fingerprint="", source_fingerprint="", audit=None, changes=None, nat=None,
                 interfaces_filter=None, risk=None, matrix=None, hits=None, extra_meta=None,
                 hits_note=None, accepted=None):
        self.gateway_name = gateway_name
        self.gateway_type = gateway_type
        self.source = source
        self.generated_at = generated_at
        self.rules = rules
        self.fingerprint = fingerprint
        self.source_fingerprint = source_fingerprint
        self.audit = audit or []
        self.accepted = accepted or []  # Findings accepted by an exception (REASON, OWNER, EXPIRES).
        self.changes = changes  # None = no previous snapshot to compare with.
        self.nat = nat or []
        self.interfaces_filter = interfaces_filter
        self.risk = risk  # risk.compute() result.
        self.matrix = matrix  # matrix.build_matrix() result (None if not applicable).
        self.hits = hits or []  # hits.update_history() rows.
        self.hits_note = hits_note  # Why there are no hits rows (how to get them).
        self.extra_meta = list(extra_meta or [])

    def metadata(self):
        """Ordered (label, value) pairs describing the run."""
        meta = [
            ("Gateway", self.gateway_name),
            ("Type", self.gateway_type),
            ("Source", self.source),
            ("Generated", self.generated_at),
            ("Rules fingerprint (SHA-256)", self.fingerprint),
        ]
        if self.source_fingerprint:
            meta.append(("Backup file SHA-256", self.source_fingerprint))
        if self.interfaces_filter:
            meta.append(("Interfaces filter", ", ".join(self.interfaces_filter)))
        if self.risk:
            from pyfrc2g.analysis.risk import describe

            meta.append(("Risk score", describe(self.risk)))
        meta.extend(self.extra_meta)
        return meta


# ---------------------------------------------------------------------------
# ReportLab helpers
# ---------------------------------------------------------------------------

@functools.lru_cache(maxsize=None)
def _styles():
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet

    base = getSampleStyleSheet()
    return {
        "title": base["Title"],
        "h2": base["Heading2"],
        "body": base["BodyText"],
        "cell": ParagraphStyle("cell", parent=base["BodyText"], fontSize=CELL_FONT_SIZE, leading=9),
        "head": ParagraphStyle("head", parent=base["BodyText"], fontSize=7.5, leading=9,
                               fontName="Helvetica-Bold"),
    }


def _p(text, style):
    from reportlab.platypus import Paragraph

    return Paragraph(html.escape(str(text if text is not None else "")), style)


CELL_FONT_SIZE = 7.5
_CELL_PADDING = 12  # Default left + right cell padding (points).


def _cell(value, width, style):
    """
    Plain string when the text fits on one line (fast), wrapping Paragraph otherwise:
    Paragraph layout dominates the rendering time of large tables.
    """
    from reportlab.pdfbase.pdfmetrics import stringWidth

    text = str(value if value is not None else "")
    if "\n" not in text and stringWidth(text, "Helvetica", CELL_FONT_SIZE) <= width - _CELL_PADDING:
        return text
    return _p(text, style)


def _table(header, rows, col_widths, row_colors=None):
    """Build a zebra-free table with wrapped cells and optional per-row background colors."""
    from reportlab.lib import colors
    from reportlab.platypus import Table, TableStyle

    st = _styles()
    data = [[_p(h, st["head"]) for h in header]]
    data += [[_cell(cell, width, st["cell"]) for cell, width in zip(row, col_widths)] for row in rows]
    table = Table(data, colWidths=col_widths, repeatRows=1)
    style = [
        ("FONT", (0, 1), (-1, -1), "Helvetica", CELL_FONT_SIZE, CELL_FONT_SIZE + 1.5),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dfe3ea")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9aa3af")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    for i, color in enumerate(row_colors or [], start=1):
        if color:
            style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor(color)))
    table.setStyle(TableStyle(style))
    return table


TABLE_CHUNK = 60


def _tables(header, rows, col_widths, row_colors=None):
    """
    Large tables as several tables of TABLE_CHUNK rows (header repeated): ReportLab re-wraps the
    whole remaining table at every page split, which is quadratic for one big table.
    """
    rows = list(rows)
    colors_list = list(row_colors or [None] * len(rows))
    return [_table(header, rows[i:i + TABLE_CHUNK], col_widths, colors_list[i:i + TABLE_CHUNK])
            for i in range(0, max(len(rows), 1), TABLE_CHUNK)]


def _build_doc(path, story, title):
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.units import cm
    from reportlab.platypus import SimpleDocTemplate

    doc = SimpleDocTemplate(path, pagesize=landscape(A4), title=title,
                            leftMargin=1.2 * cm, rightMargin=1.2 * cm,
                            topMargin=1.2 * cm, bottomMargin=1.2 * cm)
    doc.build(story)
    return path


def _usable_width():
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.units import cm

    return landscape(A4)[0] - 2.4 * cm


# ---------------------------------------------------------------------------
# Report sections (each one written to its own PDF, merged later)
# ---------------------------------------------------------------------------

def write_summary_pdf(report, path, rows=None, interface=None):
    """Summary page: metadata, rules per interface/action, audit, changes and NAT counts."""
    from reportlab.platypus import Spacer

    st = _styles()
    rows = report.rules if rows is None else rows
    width = _usable_width()
    title = f"Flow matrix - {report.gateway_name}" + (f" - {interface}" if interface else "")
    story = [_p(title, st["title"])]

    story.append(_table(["Item", "Value"], report.metadata(), [width * 0.25, width * 0.75]))
    story.append(Spacer(1, 12))

    story.append(_p("Rules per interface", st["h2"]))
    stats = interface_stats(rows)
    stat_rows = [[iface, s["total"], s["pass"], s["block"], s["reject"], s["disabled"]]
                 for iface, s in stats.items()]
    totals = [sum(r[i] for r in stat_rows) for i in range(1, 6)]
    stat_rows.append(["TOTAL", *totals])
    story.append(_table(["Interface", "Rules", "Pass", "Block", "Reject", "Disabled"], stat_rows,
                        [width * 0.4] + [width * 0.12] * 5))

    if interface is None and report.risk and report.risk.get("by_interface"):
        story.append(Spacer(1, 12))
        story.append(_p("Risk score per interface (0-100)", st["h2"]))
        items = list(report.risk["by_interface"].items())
        story.append(_table(["Interface", "Score"], items, [width * 0.4, width * 0.15]))

    if interface is None:
        story.append(Spacer(1, 12))
        story.append(_p("Audit findings", st["h2"]))
        counts = count_by_severity(report.audit)
        story.append(_table(SEVERITIES, [[counts[s] for s in SEVERITIES]],
                            [width / len(SEVERITIES)] * len(SEVERITIES)))
        if report.accepted:
            story.append(_p(f"{len(report.accepted)} finding(s) accepted (justified risks, left out of the "
                            "findings above and of the risk score): see the Accepted risks section.", st["body"]))
        story.append(Spacer(1, 12))
        story.append(_p("Changes since previous run", st["h2"]))
        if report.changes is None:
            story.append(_p("First run: no previous snapshot to compare with.", st["body"]))
        else:
            counts = count_changes(report.changes)
            story.append(_table(["Added", "Modified", "Removed"],
                                [[counts["ADDED"], counts["MODIFIED"], counts["REMOVED"]]],
                                [width / 3] * 3))
        story.append(Spacer(1, 12))
        story.append(_p(f"NAT rules: {len(report.nat)}", st["body"]))

    return _build_doc(path, story, title)


def _section_pdf(path, title, fieldnames, rows, widths, color_field=None, colors_map=None,
                 empty_text="Nothing to report."):
    st = _styles()
    story = [_p(title, st["title"])]
    if not rows:
        story.append(_p(empty_text, st["body"]))
    else:
        width = _usable_width()
        story.extend(_tables(
            fieldnames, [[row.get(f, "") for f in fieldnames] for row in rows],
            [width * w for w in widths],
            row_colors=[colors_map.get(row.get(color_field)) for row in rows] if color_field else None,
        ))
    return _build_doc(path, story, title)


def write_changes_pdf(report, path):
    if report.changes is None:
        return None
    return _section_pdf(path, "Changes since previous run", CHANGES_FIELDNAMES, report.changes,
                        [0.08, 0.17, 0.06, 0.12, 0.32, 0.25], "CHANGE", CHANGE_COLORS,
                        empty_text="No rule added, modified or removed.")


def write_audit_pdf(report, path):
    return _section_pdf(path, "Audit findings", AUDIT_FIELDNAMES, report.audit,
                        [0.07, 0.16, 0.11, 0.055, 0.075, 0.27, 0.26], "SEVERITY", SEVERITY_COLORS,
                        empty_text="No finding.")


def write_accepted_pdf(report, path):
    from pyfrc2g.analysis.exceptions import ACCEPTED_FIELDNAMES

    if not report.accepted:
        return None
    return _section_pdf(path, "Accepted risks (left out of the audit findings and of the risk score)",
                        ACCEPTED_FIELDNAMES, report.accepted,
                        [0.06, 0.1, 0.09, 0.045, 0.06, 0.2, 0.15, 0.15, 0.08, 0.065],
                        "SEVERITY", SEVERITY_COLORS)


def write_nat_pdf(report, path):
    if not report.nat:
        return None
    return _section_pdf(path, "NAT rules", NAT_FIELDNAMES, report.nat,
                        [0.085, 0.08, 0.075, 0.085, 0.065, 0.095, 0.095, 0.1, 0.065, 0.11, 0.07, 0.075],
                        "DISABLED", {"True": "#e2e3e5"})


def write_hits_pdf(report, path):
    from pyfrc2g.analysis.hits import HITS_FIELDNAMES

    if not report.hits:
        return None
    colors_map = {"UNUSED": "#f8d7da", "STALE": "#fff3cd", "DISABLED": "#e2e3e5"}
    return _section_pdf(path, "Rule usage (hit counters)", HITS_FIELDNAMES, report.hits,
                        [0.1, 0.06, 0.08, 0.24, 0.07, 0.07, 0.06, 0.085, 0.09, 0.085, 0.06],
                        "STATUS", colors_map)


def write_matrix_pdf(report, path):
    """Zone matrix: one row per source zone, one column per destination zone."""
    from reportlab.lib import colors
    from reportlab.platypus import Spacer, Table, TableStyle

    from pyfrc2g.analysis.matrix import STATUS_COLORS

    matrix = report.matrix
    if not matrix or not matrix["sources"]:
        return None
    st = _styles()
    width = _usable_width()
    destinations = matrix["destinations"]
    header = [_p("From / To", st["head"])] + [_p(d, st["head"]) for d in destinations]
    data, style = [header], [
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9aa3af")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dfe3ea")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#dfe3ea")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    for r, source in enumerate(matrix["sources"], start=1):
        line = [_p(source, st["head"])]
        for c, dest in enumerate(destinations, start=1):
            status, detail = matrix["cells"].get((source, dest), ("", ""))
            text = status if status in ("-", "ALLOWED", "BLOCKED") else f"{status}: {detail}"
            line.append(_p(text[:220], st["cell"]))
            if status in STATUS_COLORS:
                style.append(("BACKGROUND", (c, r), (c, r), colors.HexColor(STATUS_COLORS[status])))
        data.append(line)
    first = width * 0.14
    other = (width - first) / max(1, len(destinations))
    table = Table(data, colWidths=[first] + [other] * len(destinations), repeatRows=1)
    table.setStyle(TableStyle(style))
    story = [_p("Zone matrix (IPv4)", st["title"]), table, Spacer(1, 8),
             _p("ALLOWED: all traffic allowed by one rule; PARTIAL: only some hosts or services "
                "(rule numbers and services listed, '?' = alias or interface not fully resolved); "
                "BLOCKED: no pass rule; '-': same zone.", st["body"])]
    return _build_doc(path, story, "Zone matrix")


def write_compare_pdf(path, name_a, name_b, differences, meta):
    from pyfrc2g.analysis.compare import COMPARE_FIELDNAMES, DIFF_COLORS

    st = _styles()
    width = _usable_width()
    title = f"Comparison {name_a} (A) vs {name_b} (B)"
    story = [_p(title, st["title"]), _table(["Item", "Value"], meta, [width * 0.2, width * 0.8])]
    from reportlab.platypus import Spacer

    story.append(Spacer(1, 12))
    if not differences:
        story.append(_p("No difference.", st["body"]))
    else:
        widths = [0.09, 0.06, 0.12, 0.06, 0.11, 0.3, 0.26]
        story.extend(_tables(COMPARE_FIELDNAMES,
                            [[d.get(f, "") for f in COMPARE_FIELDNAMES] for d in differences],
                            [width * w for w in widths],
                            row_colors=[DIFF_COLORS.get(d["DIFFERENCE"]) for d in differences]))
    return _build_doc(path, story, title)


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------

def png_to_pdf(png_path, pdf_path):
    """Raster fallback: put a PNG on an A4 page (scaled to fit)."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfgen import canvas

    img = ImageReader(png_path)
    img_w, img_h = img.getSize()
    page_w, page_h = A4 if img_h >= img_w else (A4[1], A4[0])
    scale = min(page_w / img_w, page_h / img_h)
    c = canvas.Canvas(pdf_path, pagesize=(page_w, page_h))
    c.drawImage(img, (page_w - img_w * scale) / 2, (page_h - img_h * scale) / 2,
                width=img_w * scale, height=img_h * scale)
    c.showPage()
    c.save()
    return pdf_path


def assemble_pdf(output_path, parts, title):
    """
    Merge PDF parts into one file with one bookmark per part.

    Args:
        output_path: Destination PDF.
        parts: List of (bookmark title, pdf path); None paths are skipped.
        title: Document title (metadata).
    """
    from pypdf import PdfReader, PdfWriter

    writer = PdfWriter()
    for bookmark, path in parts:
        if not path or not os.path.isfile(path):
            continue
        start = len(writer.pages)
        for page in PdfReader(path).pages:
            writer.add_page(page)
        if len(writer.pages) > start:
            writer.add_outline_item(bookmark, start)
    if not writer.pages:
        logging.warning(f"No page to write in {output_path}")
        return None
    writer.add_metadata({"/Title": title, "/Creator": "PyFRC2G"})
    with open(output_path, "wb") as f:
        writer.write(f)
    return output_path
