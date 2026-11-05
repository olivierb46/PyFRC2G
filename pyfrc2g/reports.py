"""
PDF reports for PyFRC2G: summary page, change / audit / NAT tables, and assembly of the
final PDF (report pages + vector graph pages) with bookmarks.
"""

import html
import logging
import os
from collections import OrderedDict

from pyfrc2g.audit import AUDIT_FIELDNAMES, SEVERITIES, count_by_severity
from pyfrc2g.diff import CHANGES_FIELDNAMES, count_changes
from pyfrc2g.nat import NAT_FIELDNAMES

SEVERITY_COLORS = {"CRITICAL": "#f8d7da", "HIGH": "#fde2c8", "MEDIUM": "#fff3cd", "LOW": "#e2e3e5"}
CHANGE_COLORS = {"ADDED": "#d4edda", "REMOVED": "#f8d7da", "MODIFIED": "#fff3cd"}
ACTIONS = ("pass", "block", "reject")


def interface_of(row):
    """Display interface of a rule row ('Floating-rules' for floating rules)."""
    if (row.get("FLOATING") or "").strip() in ("True", "1"):
        return "Floating-rules"
    gateway = (row.get("GATEWAY") or "").strip()
    return gateway.split("/", 1)[1] if "/" in gateway else gateway


def interface_stats(rows):
    """{interface: {"total", "pass", "block", "reject", "disabled"}} in first-seen order."""
    stats = OrderedDict()
    for row in rows:
        s = stats.setdefault(interface_of(row), {"total": 0, "disabled": 0,
                                                  **{a: 0 for a in ACTIONS}})
        s["total"] += 1
        action = (row.get("ACTION") or "").strip().lower()
        if action in s:
            s[action] += 1
        if (row.get("DISABLED") or "").strip() in ("True", "1"):
            s["disabled"] += 1
    return stats


class RunReport:
    """Everything produced for one firewall run, shared by PDF / HTML / Excel outputs."""

    def __init__(self, gateway_name, gateway_type, source, generated_at, rules,
                 fingerprint="", source_fingerprint="", audit=None, changes=None, nat=None,
                 interfaces_filter=None):
        self.gateway_name = gateway_name
        self.gateway_type = gateway_type
        self.source = source
        self.generated_at = generated_at
        self.rules = rules
        self.fingerprint = fingerprint
        self.source_fingerprint = source_fingerprint
        self.audit = audit or []
        self.changes = changes  # None = no previous snapshot to compare with.
        self.nat = nat or []
        self.interfaces_filter = interfaces_filter

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
        return meta


# ---------------------------------------------------------------------------
# ReportLab helpers
# ---------------------------------------------------------------------------

def _styles():
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet

    base = getSampleStyleSheet()
    return {
        "title": base["Title"],
        "h2": base["Heading2"],
        "body": base["BodyText"],
        "cell": ParagraphStyle("cell", parent=base["BodyText"], fontSize=7.5, leading=9),
        "head": ParagraphStyle("head", parent=base["BodyText"], fontSize=7.5, leading=9,
                               fontName="Helvetica-Bold"),
    }


def _p(text, style):
    from reportlab.platypus import Paragraph

    return Paragraph(html.escape(str(text if text is not None else "")), style)


def _table(header, rows, col_widths, row_colors=None):
    """Build a zebra-free table with wrapped cells and optional per-row background colors."""
    from reportlab.lib import colors
    from reportlab.platypus import Table, TableStyle

    st = _styles()
    data = [[_p(h, st["head"]) for h in header]]
    data += [[_p(cell, st["cell"]) for cell in row] for row in rows]
    table = Table(data, colWidths=col_widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dfe3ea")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9aa3af")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    for i, color in enumerate(row_colors or [], start=1):
        if color:
            style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor(color)))
    table.setStyle(TableStyle(style))
    return table


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

    if interface is None:
        story.append(Spacer(1, 12))
        story.append(_p("Audit findings", st["h2"]))
        counts = count_by_severity(report.audit)
        story.append(_table(SEVERITIES, [[counts[s] for s in SEVERITIES]],
                            [width / len(SEVERITIES)] * len(SEVERITIES)))
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
        story.append(_p(f"NAT port forwards: {len(report.nat)}", st["body"]))

    return _build_doc(path, story, title)


def _section_pdf(path, title, fieldnames, rows, widths, color_field=None, colors_map=None,
                 empty_text="Nothing to report."):
    st = _styles()
    story = [_p(title, st["title"])]
    if not rows:
        story.append(_p(empty_text, st["body"]))
    else:
        width = _usable_width()
        story.append(_table(
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
                        [0.08, 0.11, 0.13, 0.065, 0.08, 0.275, 0.26], "SEVERITY", SEVERITY_COLORS,
                        empty_text="No finding.")


def write_nat_pdf(report, path):
    if not report.nat:
        return None
    return _section_pdf(path, "NAT port forwards", NAT_FIELDNAMES, report.nat,
                        [0.085, 0.075, 0.09, 0.06, 0.11, 0.085, 0.11, 0.06, 0.155, 0.075, 0.095],
                        "DISABLED", {"True": "#e2e3e5"})


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
