"""Jinja filters and helpers of the web application templates."""

from datetime import datetime


def register(app):
    env = app.jinja_env
    env.filters["datetime"] = lambda ts: datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else ""
    env.filters["map_score"] = lambda gws: [(g["name"], g["score"] or 0, g["level"] or "") for g in gws]
    env.filters["map_critical"] = lambda gws: [(g["name"], g["critical"] or 0, "CRITICAL") for g in gws]
    env.filters["dictitems"] = lambda d, css="": [(k, v, css) for k, v in sorted((d or {}).items(),
                                                                                   key=lambda kv: -kv[1])]
    env.filters["interface_bars"] = lambda stats: [(s["name"], s["total"], "") for s in stats]
    env.filters["sum_actions"] = _sum_actions
    env.globals["rule_class"] = _rule_class


def _sum_actions(stats):
    totals = {"pass": 0, "block": 0, "reject": 0, "disabled": 0}
    for item in stats or []:
        for key in totals:
            totals[key] += item.get(key, 0)
    return totals


def _rule_class(row):
    classes = [(row.get("ACTION") or "").lower()]
    if row.get("DISABLED") in ("True", "1"):
        classes.append("disabled")
    return " ".join(classes)
