"""
Server-side SVG charts (no JavaScript library, no external resource). Colors come from CSS
classes of static/app.css, so the charts follow the light / dark theme.
"""

import html

from markupsafe import Markup


def _e(value):
    return html.escape(str(value), quote=True)


def risk_line(history, height=180):
    """Risk score (0-100) over the runs: area + line + points, with grid and labels."""
    points = [(h.get("date", ""), h.get("score", 0) or 0) for h in history if h.get("score") is not None]
    if not points:
        return Markup("<p class='muted'>No history yet.</p>")
    width, left, right, top, bottom = 640, 34, 12, 12, 26
    plot_w, plot_h = width - left - right, height - top - bottom
    step = plot_w / max(1, len(points) - 1)

    def xy(i, score):
        return left + (i * step if len(points) > 1 else plot_w / 2), top + plot_h * (1 - min(score, 100) / 100)

    parts = [f"<svg class='chart' viewBox='0 0 {width} {height}' role='img' "
             f"aria-label='Risk score over the last {len(points)} analyses'>"]
    for value in (0, 25, 50, 75, 100):
        y = top + plot_h * (1 - value / 100)
        parts.append(f"<line class='grid' x1='{left}' x2='{width - right}' y1='{y:.1f}' y2='{y:.1f}'/>"
                     f"<text class='axis' x='{left - 6}' y='{y + 4:.1f}' text-anchor='end'>{value}</text>")
    for threshold, css in ((60, "band-critical"), (30, "band-high")):
        y = top + plot_h * (1 - threshold / 100)
        parts.append(f"<line class='threshold {css}' x1='{left}' x2='{width - right}' y1='{y:.1f}' y2='{y:.1f}'/>")
    coords = [xy(i, s) for i, (_, s) in enumerate(points)]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in coords)
    area = f"{coords[0][0]:.1f},{top + plot_h} {line} {coords[-1][0]:.1f},{top + plot_h}"
    parts.append(f"<polygon class='area' points='{area}'/><polyline class='line' points='{line}'/>")
    for (date, score), (x, y) in zip(points, coords):
        parts.append(f"<circle class='dot' cx='{x:.1f}' cy='{y:.1f}' r='3.5'><title>{_e(date)}: {score}</title></circle>")
    labels = [0, len(points) - 1] if len(points) > 1 else [0]
    for i in labels:
        anchor = "start" if i == 0 and len(points) > 1 else "end"
        parts.append(f"<text class='axis' x='{coords[i][0]:.1f}' y='{height - 6}' text-anchor='{anchor}'>"
                     f"{_e(points[i][0][:10])}</text>")
    parts.append("</svg>")
    return Markup("".join(parts))


def sparkline(history, width=120, height=32):
    scores = [h.get("score") or 0 for h in history if h.get("score") is not None][-20:]
    if len(scores) < 2:
        return Markup("")
    step = width / (len(scores) - 1)
    line = " ".join(f"{i * step:.1f},{height - 2 - (s / 100) * (height - 4):.1f}" for i, s in enumerate(scores))
    return Markup(f"<svg class='spark' viewBox='0 0 {width} {height}' preserveAspectRatio='none' "
                  f"aria-hidden='true'><polyline points='{line}'/></svg>")


def bars(items, value_suffix=""):
    """Horizontal bars: items = [(label, value, css class)]."""
    items = [i for i in items if i[1]]
    if not items:
        return Markup("<p class='muted'>Nothing to show.</p>")
    maximum = max(v for _, v, _ in items) or 1
    row_h, label_w, width = 26, 150, 520
    height = row_h * len(items)
    parts = [f"<svg class='chart bars' viewBox='0 0 {width} {height}' role='img'>"]
    for index, (label, value, css) in enumerate(items):
        y = index * row_h
        bar_w = max(2, (width - label_w - 60) * value / maximum)
        parts.append(f"<text class='label' x='0' y='{y + 17}'>{_e(str(label)[:22])}</text>"
                     f"<rect class='bar {_e(css)}' x='{label_w}' y='{y + 5}' width='{bar_w:.1f}' height='16' rx='4'/>"
                     f"<text class='value' x='{label_w + bar_w + 8:.1f}' y='{y + 17}'>{value}{_e(value_suffix)}</text>")
    parts.append("</svg>")
    return Markup("".join(parts))


def donut(segments, label=""):
    """Ring chart: segments = [(name, value, css class)]."""
    total = sum(v for _, v, _ in segments)
    if not total:
        return Markup("<p class='muted'>Nothing to show.</p>")
    radius, circumference = 42, 2 * 3.14159265 * 42
    offset = 0.0
    parts = ["<svg class='donut' viewBox='0 0 120 120' role='img'>",
             f"<circle class='ring-bg' cx='60' cy='60' r='{radius}'/>"]
    for name, value, css in segments:
        if not value:
            continue
        length = circumference * value / total
        parts.append(f"<circle class='ring {_e(css)}' cx='60' cy='60' r='{radius}' "
                     f"stroke-dasharray='{length:.2f} {circumference - length:.2f}' "
                     f"stroke-dashoffset='{-offset:.2f}' transform='rotate(-90 60 60)'>"
                     f"<title>{_e(name)}: {value}</title></circle>")
        offset += length
    parts.append(f"<text class='donut-total' x='60' y='58' text-anchor='middle'>{total}</text>"
                 f"<text class='donut-label' x='60' y='76' text-anchor='middle'>{_e(label)}</text></svg>")
    return Markup("".join(parts))
