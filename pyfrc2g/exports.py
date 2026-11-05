"""
Exports for PyFRC2G: CSV files, self-contained filterable HTML report, Excel workbook.
"""

import csv
import html
import logging

from pyfrc2g.audit import AUDIT_FIELDNAMES, SEVERITIES, count_by_severity
from pyfrc2g.diff import CHANGES_FIELDNAMES, count_changes
from pyfrc2g.nat import NAT_FIELDNAMES
from pyfrc2g.reports import CHANGE_COLORS, SEVERITY_COLORS, interface_stats

ACTION_COLORS = {"pass": "#d4edda", "block": "#f8d7da", "reject": "#f8d7da"}


def write_csv(path, fieldnames, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return path


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_HTML_STYLE = """
:root { --bg:#fff; --fg:#1f2328; --muted:#59636e; --line:#d1d9e0; --head:#f0f3f6;
        --pass:#d4edda; --block:#f8d7da; --warn:#fff3cd; --high:#fde2c8; --low:#e2e3e5; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#0d1117; --fg:#e6edf3; --muted:#9198a1; --line:#3d444d; --head:#161b22;
          --pass:#1b3a26; --block:#4a1d22; --warn:#3d3214; --high:#4a2c14; --low:#262c33; }
}
* { box-sizing:border-box; }
body { margin:0; padding:16px 24px; background:var(--bg); color:var(--fg);
       font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif; }
h1 { font-size:22px; margin:0 0 4px; } h2 { font-size:17px; margin:28px 0 8px; }
nav { position:sticky; top:0; background:var(--bg); padding:8px 0; border-bottom:1px solid var(--line);
      display:flex; gap:16px; flex-wrap:wrap; z-index:2; }
nav a { color:var(--fg); text-decoration:none; font-weight:600; }
.meta { color:var(--muted); }
.cards { display:flex; gap:12px; flex-wrap:wrap; margin:12px 0; }
.card { border:1px solid var(--line); border-radius:8px; padding:8px 14px; min-width:110px; }
.card b { display:block; font-size:20px; }
.wrap { overflow-x:auto; border:1px solid var(--line); border-radius:8px; }
table { border-collapse:collapse; width:100%; font-size:13px; }
th, td { border-bottom:1px solid var(--line); padding:5px 8px; text-align:left; vertical-align:top; }
th { background:var(--head); position:sticky; top:0; }
thead tr.filters th { padding:3px 4px; }
thead input { width:100%; min-width:60px; font:inherit; font-size:12px; padding:2px 4px;
              background:var(--bg); color:var(--fg); border:1px solid var(--line); border-radius:4px; }
.search { font:inherit; padding:6px 10px; width:min(420px,100%); margin:6px 0;
          background:var(--bg); color:var(--fg); border:1px solid var(--line); border-radius:6px; }
.count { color:var(--muted); margin-left:8px; }
tr.pass td:first-child, tr.ADDED td:first-child { box-shadow: inset 4px 0 var(--pass); }
tr.block td:first-child, tr.reject td:first-child, tr.REMOVED td:first-child,
tr.CRITICAL td:first-child { box-shadow: inset 4px 0 #d1242f; }
tr.HIGH td:first-child { box-shadow: inset 4px 0 #e16f24; }
tr.MEDIUM td:first-child, tr.MODIFIED td:first-child { box-shadow: inset 4px 0 #d4a72c; }
tr.LOW td:first-child { box-shadow: inset 4px 0 var(--muted); }
tr.disabled td { color:var(--muted); text-decoration:line-through; }
"""

_HTML_SCRIPT = """
document.querySelectorAll('table.filterable').forEach(function (table) {
  var inputs = table.querySelectorAll('thead tr.filters input');
  var search = document.getElementById(table.dataset.search);
  var counter = document.getElementById(table.dataset.count);
  var rows = Array.prototype.slice.call(table.tBodies[0].rows);
  function apply() {
    var global = (search && search.value || '').toLowerCase();
    var filters = Array.prototype.map.call(inputs, function (i) { return i.value.toLowerCase(); });
    var shown = 0;
    rows.forEach(function (row) {
      var cells = row.cells, ok = true;
      for (var i = 0; i < filters.length && ok; i++) {
        if (filters[i] && cells[i].textContent.toLowerCase().indexOf(filters[i]) === -1) ok = false;
      }
      if (ok && global && row.textContent.toLowerCase().indexOf(global) === -1) ok = false;
      row.hidden = !ok;
      if (ok) shown++;
    });
    if (counter) counter.textContent = shown + ' / ' + rows.length;
  }
  inputs.forEach(function (i) { i.addEventListener('input', apply); });
  if (search) search.addEventListener('input', apply);
  apply();
});
"""


def _e(value):
    return html.escape(str(value if value is not None else ""))


def _html_table(table_id, fieldnames, rows, row_class=None):
    if not rows:
        return "<p class='meta'>Nothing to report.</p>"
    head = "".join(f"<th>{_e(f)}</th>" for f in fieldnames)
    filters = "".join(f"<th><input aria-label='Filter {_e(f)}' placeholder='filter'></th>"
                      for f in fieldnames)
    body = []
    for row in rows:
        css = row_class(row) if row_class else ""
        cells = "".join(f"<td>{_e(row.get(f, ''))}</td>" for f in fieldnames)
        body.append(f"<tr class='{_e(css)}'>{cells}</tr>")
    return (
        f"<input class='search' id='{table_id}-search' type='search' placeholder='Search all columns'>"
        f"<span class='count' id='{table_id}-count'></span>"
        f"<div class='wrap'><table class='filterable' data-search='{table_id}-search' "
        f"data-count='{table_id}-count'><thead><tr>{head}</tr><tr class='filters'>{filters}</tr>"
        f"</thead><tbody>{''.join(body)}</tbody></table></div>"
    )


def _rule_class(row):
    classes = [(row.get("ACTION") or "").strip().lower()]
    if (row.get("DISABLED") or "").strip() in ("True", "1"):
        classes.append("disabled")
    return " ".join(classes)


def write_html_report(report, path, rule_fieldnames):
    """Single self-contained HTML file with summary and filterable tables."""
    sev = count_by_severity(report.audit)
    cards = "".join(f"<div class='card'>{s}<b>{sev[s]}</b></div>" for s in SEVERITIES)
    if report.changes is None:
        changes_html = "<p class='meta'>First run: no previous snapshot to compare with.</p>"
        change_cards = ""
    else:
        cc = count_changes(report.changes)
        change_cards = "".join(f"<div class='card'>{k.title()}<b>{v}</b></div>" for k, v in cc.items())
        changes_html = _html_table("changes", CHANGES_FIELDNAMES, report.changes,
                                   lambda r: r.get("CHANGE", ""))
    stats_rows = [{"INTERFACE": iface, "RULES": s["total"], "PASS": s["pass"], "BLOCK": s["block"],
                   "REJECT": s["reject"], "DISABLED": s["disabled"]}
                  for iface, s in interface_stats(report.rules).items()]
    stats_fields = ["INTERFACE", "RULES", "PASS", "BLOCK", "REJECT", "DISABLED"]
    stats_html = "".join(
        "<tr>" + "".join(f"<td>{_e(r[f])}</td>" for f in stats_fields) + "</tr>" for r in stats_rows)
    meta_html = "".join(f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in report.metadata())

    title = f"Flow matrix - {report.gateway_name}"
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)}</title><style>{_HTML_STYLE}</style></head>
<body>
<h1>{_e(title)}</h1>
<div class="meta">{_e(report.gateway_type)} · generated {_e(report.generated_at)}</div>
<nav><a href="#summary">Summary</a><a href="#rules">Rules ({len(report.rules)})</a>
<a href="#audit">Audit ({len(report.audit)})</a>
<a href="#changes">Changes ({'-' if report.changes is None else len(report.changes)})</a>
<a href="#nat">NAT ({len(report.nat)})</a></nav>
<h2 id="summary">Summary</h2>
<div class="wrap"><table>{meta_html}</table></div>
<h2>Rules per interface</h2>
<div class="wrap"><table><thead><tr>{''.join(f'<th>{f.title()}</th>' for f in stats_fields)}</tr>
</thead><tbody>{stats_html}</tbody></table></div>
<h2>Audit findings</h2><div class="cards">{cards}</div>
<div class="cards">{change_cards}</div>
<h2 id="rules">Rules</h2>
{_html_table("rules", rule_fieldnames, report.rules, _rule_class)}
<h2 id="audit">Audit findings</h2>
{_html_table("audit", AUDIT_FIELDNAMES, report.audit, lambda r: r.get("SEVERITY", ""))}
<h2 id="changes">Changes since previous run</h2>
{changes_html}
<h2 id="nat">NAT port forwards</h2>
{_html_table("nat", NAT_FIELDNAMES, report.nat,
             lambda r: "disabled" if r.get("DISABLED") == "True" else "")}
<script>{_HTML_SCRIPT}</script>
</body></html>
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
    return path


# ---------------------------------------------------------------------------
# Excel
# ---------------------------------------------------------------------------

def _xlsx_sheet(wb, title, fieldnames, rows, color_of=None):
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    ws = wb.create_sheet(title)
    ws.append(fieldnames)
    for cell in ws[1]:
        cell.font = Font(bold=True)
        cell.fill = PatternFill("solid", fgColor="DFE3EA")
    for row in rows:
        ws.append([row.get(f, "") for f in fieldnames])
        color = color_of(row) if color_of else None
        if color:
            fill = PatternFill("solid", fgColor=color.lstrip("#"))
            for cell in ws[ws.max_row]:
                cell.fill = fill
    ws.freeze_panes = "A2"
    if rows:
        ws.auto_filter.ref = ws.dimensions
    for index, field in enumerate(fieldnames, start=1):
        longest = max([len(str(field))] + [len(str(r.get(field, ""))) for r in rows[:500]])
        ws.column_dimensions[get_column_letter(index)].width = min(max(10, longest + 2), 60)
    for row in ws.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = Alignment(vertical="top", wrap_text=True)
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
    if report.changes is not None:
        cc = count_changes(report.changes)
        summary.append(["Changes"] + [f"{k.title()}: {v}" for k, v in cc.items()])
    summary.append(["NAT port forwards", len(report.nat)])
    summary.column_dimensions["A"].width = 30
    summary.column_dimensions["B"].width = 70

    _xlsx_sheet(wb, "Rules", rule_fieldnames, report.rules,
                lambda r: ("#E2E3E5" if r.get("DISABLED") == "True"
                           else ACTION_COLORS.get((r.get("ACTION") or "").lower())))
    _xlsx_sheet(wb, "Audit", AUDIT_FIELDNAMES, report.audit,
                lambda r: SEVERITY_COLORS.get(r.get("SEVERITY")))
    if report.changes is not None:
        _xlsx_sheet(wb, "Changes", CHANGES_FIELDNAMES, report.changes,
                    lambda r: CHANGE_COLORS.get(r.get("CHANGE")))
    _xlsx_sheet(wb, "NAT", NAT_FIELDNAMES, report.nat,
                lambda r: "#E2E3E5" if r.get("DISABLED") == "True" else None)
    wb.save(path)
    return path
