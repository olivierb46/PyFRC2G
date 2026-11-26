"""
Prometheus metrics (text exposition format) of the firewalls and of the application.

Served by /metrics only when PYFRC2G_METRICS_TOKEN is set; the scraper sends it as
"Authorization: Bearer <token>". The figures are those of the whole instance (no user scope).
"""

import time

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def _escape(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _line(name, value, **labels):
    shown = ",".join(f'{key}="{_escape(val)}"' for key, val in labels.items())
    return f"{name}{{{shown}}} {value}" if shown else f"{name} {value}"


def timestamp(text):
    """Epoch seconds of a database date ('YYYY-MM-DD HH:MM:SS', local time), or None."""
    try:
        return time.mktime(time.strptime(text, "%Y-%m-%d %H:%M:%S"))
    except (TypeError, ValueError):
        return None


def render(db, version, now=None):
    """Return the metrics page as text."""
    from pyfrc2g_web import access

    now = now or time.time()
    out = []

    def family(name, kind, help_text):
        out.extend((f"# HELP {name} {help_text}", f"# TYPE {name} {kind}"))

    family("pyfrc2g_web_info", "gauge", "Version of the application (always 1).")
    out.append(_line("pyfrc2g_web_info", 1, version=version))
    gateways = access.labelled_gateways(db)
    figures = (("risk_score", "score", "Risk score (0-100)."), ("findings", "findings", "Active findings."),
               ("critical_findings", "critical", "Active critical findings."), ("rules", "rules", "Rules."))
    for metric, key, help_text in figures:
        family(f"pyfrc2g_firewall_{metric}", "gauge", help_text)
        for gw in gateways:
            if gw.get(key) is not None:
                out.append(_line(f"pyfrc2g_firewall_{metric}", gw[key], firewall=gw["name"], site=gw["site"]))
    family("pyfrc2g_firewall_last_analysis_timestamp_seconds", "gauge", "Time of the last analysis.")
    family("pyfrc2g_firewall_analysis_age_seconds", "gauge", "Seconds since the last analysis.")
    for gw in gateways:
        when = timestamp(gw.get("updated"))
        if when is not None:
            out.append(_line("pyfrc2g_firewall_last_analysis_timestamp_seconds", int(when), firewall=gw["name"]))
            out.append(_line("pyfrc2g_firewall_analysis_age_seconds", int(now - when), firewall=gw["name"]))
    family("pyfrc2g_runs", "gauge", "Stored analysis runs by status.")
    counts = {}
    for run in db.runs(limit=1000):
        counts[run["status"]] = counts.get(run["status"], 0) + 1
    for status, count in sorted(counts.items()):
        out.append(_line("pyfrc2g_runs", count, status=status))
    from pyfrc2g_web import remediation

    tracked = db.remediations()
    family("pyfrc2g_remediations", "gauge", "Findings followed up, by status.")
    for status, count in sorted(remediation.stats(tracked)["counts"].items()):
        out.append(_line("pyfrc2g_remediations", count, status=status))
    family("pyfrc2g_remediations_overdue", "gauge", "Findings being fixed whose due date has passed.")
    out.append(_line("pyfrc2g_remediations_overdue", remediation.stats(tracked)["overdue"]))
    family("pyfrc2g_sessions", "gauge", "Active user sessions.")
    out.append(_line("pyfrc2g_sessions", len(db.sessions())))
    family("pyfrc2g_accepted_risks", "gauge", "Accepted risks by approval status.")
    risks = {}
    for item in db.exceptions():
        risks[item["status"]] = risks.get(item["status"], 0) + 1
    for status, count in sorted(risks.items()):
        out.append(_line("pyfrc2g_accepted_risks", count, status=status))
    return "\n".join(out) + "\n"
