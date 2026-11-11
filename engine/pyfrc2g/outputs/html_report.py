"""
Self-contained HTML reports (no external resource): run report with filterable tables, and
comparison report. Light / dark theme follows the browser.
"""

import html

from pyfrc2g.analysis.audit import AUDIT_FIELDNAMES, SEVERITIES, count_by_severity
from pyfrc2g.analysis.exceptions import ACCEPTED_FIELDNAMES
from pyfrc2g.analysis.changes import CHANGES_FIELDNAMES, count_changes
from pyfrc2g.analysis.hits import HITS_FIELDNAMES
from pyfrc2g.model.nat import NAT_FIELDNAMES
from pyfrc2g.model.rules import interface_stats

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
.risk b { font-size:28px; }
table.matrix td, table.matrix th { text-align:center; min-width:90px; }
table.matrix th:first-child { text-align:left; }
td.ALLOWED { background:var(--pass); } td.BLOCKED { background:var(--block); }
td.PARTIAL { background:var(--warn); } td.same { color:var(--muted); }
tr.UNUSED td:first-child { box-shadow: inset 4px 0 #d1242f; }
tr.STALE td:first-child { box-shadow: inset 4px 0 #d4a72c; }
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


def _matrix_html(matrix):
    if not matrix or not matrix["sources"]:
        return "<p class='meta'>Not available for this firewall type.</p>"
    head = "".join(f"<th>{_e(d)}</th>" for d in matrix["destinations"])
    body = []
    for source in matrix["sources"]:
        cells = []
        for dest in matrix["destinations"]:
            status, detail = matrix["cells"].get((source, dest), ("", ""))
            css = "same" if status == "-" else status
            cells.append(f"<td class='{_e(css)}' title='{_e(detail)}'>{_e(status)}"
                         + (f"<br><small>{_e(detail)}</small>" if status == "PARTIAL" else "") + "</td>")
        body.append(f"<tr><th>{_e(source)}</th>{''.join(cells)}</tr>")
    return (f"<div class='wrap'><table class='matrix'><thead><tr><th>From / To</th>{head}</tr></thead>"
            f"<tbody>{''.join(body)}</tbody></table></div>"
            "<p class='meta'>IPv4. PARTIAL: only some hosts or services ('?' = alias or interface "
            "not fully resolved). Hover a cell for details.</p>")


def _risk_html(risk):
    if not risk:
        return ""
    from pyfrc2g.analysis.risk import describe

    per_iface = "".join(f"<div class='card'>{_e(i)}<b>{v}</b></div>"
                        for i, v in risk.get("by_interface", {}).items())
    history = risk.get("history") or []
    trend = " → ".join(str(h.get("score")) for h in history[-10:])
    return (f"<h2>Risk score</h2><div class='cards'><div class='card risk'>Global"
            f"<b>{risk['score']}</b>{_e(describe(risk))}</div>{per_iface}</div>"
            + (f"<p class='meta'>Last runs: {_e(trend)}</p>" if len(history) > 1 else ""))


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

    accepted_link = f'<a href="#accepted">Accepted risks ({len(report.accepted)})</a>' if report.accepted else ""
    accepted_html = (
        "<h2 id='accepted'>Accepted risks</h2><p class='meta'>Justified risks, left out of the audit findings "
        "and of the risk score.</p>"
        + _html_table("accepted", ACCEPTED_FIELDNAMES, report.accepted, lambda r: r.get("SEVERITY", ""))
        if report.accepted else "")
    title = f"Flow matrix - {report.gateway_name}"
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)}</title><style>{_HTML_STYLE}</style></head>
<body>
<h1>{_e(title)}</h1>
<div class="meta">{_e(report.gateway_type)} · generated {_e(report.generated_at)}</div>
<nav><a href="#summary">Summary</a><a href="#rules">Rules ({len(report.rules)})</a>
<a href="#audit">Audit ({len(report.audit)})</a>{accepted_link}
<a href="#changes">Changes ({'-' if report.changes is None else len(report.changes)})</a>
<a href="#matrix">Zone matrix</a>
<a href="#hits">Rule usage ({len(report.hits)})</a>
<a href="#nat">NAT ({len(report.nat)})</a></nav>
<h2 id="summary">Summary</h2>
<div class="wrap"><table>{meta_html}</table></div>
<h2>Rules per interface</h2>
<div class="wrap"><table><thead><tr>{''.join(f'<th>{f.title()}</th>' for f in stats_fields)}</tr>
</thead><tbody>{stats_html}</tbody></table></div>
{_risk_html(report.risk)}
<h2>Audit findings</h2><div class="cards">{cards}</div>
<div class="cards">{change_cards}</div>
<h2 id="rules">Rules</h2>
{_html_table("rules", rule_fieldnames, report.rules, _rule_class)}
<h2 id="audit">Audit findings</h2>
{_html_table("audit", AUDIT_FIELDNAMES, report.audit, lambda r: r.get("SEVERITY", ""))}
{accepted_html}
<h2 id="changes">Changes since previous run</h2>
{changes_html}
<h2 id="matrix">Zone matrix</h2>
{_matrix_html(report.matrix)}
<h2 id="hits">Rule usage (hit counters)</h2>
{_html_table("hits", HITS_FIELDNAMES, report.hits, lambda r: r.get("STATUS", "")) if report.hits
 else f"<p class='meta'>No hit counters. {_e(report.hits_note or 'See --hits.')}</p>"}
<h2 id="nat">NAT rules</h2>
{_html_table("nat", NAT_FIELDNAMES, report.nat,
             lambda r: "disabled" if r.get("DISABLED") == "True" else "")}
<script>{_HTML_SCRIPT}</script>
</body></html>
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
    return path


def write_compare_html(path, name_a, name_b, differences, meta):
    """Self-contained HTML comparison report."""
    from pyfrc2g.analysis.compare import COMPARE_FIELDNAMES

    title = f"Comparison {name_a} (A) vs {name_b} (B)"
    meta_html = "".join(f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in meta)
    css = _HTML_STYLE + """
tr.only-a td:first-child { box-shadow: inset 4px 0 #d1242f; }
tr.only-b td:first-child { box-shadow: inset 4px 0 #2da44e; }
tr.different td:first-child { box-shadow: inset 4px 0 #d4a72c; }
"""
    table = _html_table("diff", COMPARE_FIELDNAMES, differences,
                        lambda r: r.get("DIFFERENCE", "").lower().replace(" in ", "-").replace(" ", "-"))
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)}</title><style>{css}</style></head>
<body><h1>{_e(title)}</h1>
<div class="wrap"><table>{meta_html}</table></div>
<h2>Differences</h2>{table}
<script>{_HTML_SCRIPT}</script></body></html>
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
    return path
