"""
Accepted risks ("exceptions"): a finding can be accepted with a reason, an owner and an optional
expiry date. An accepted finding leaves the list of findings, the severity counts and the risk
score; it is kept in data["accepted"] with its justification. Once the expiry date has passed
the finding counts again.

An exception targets a check (e.g. ANY_ANY) on one firewall or on all of them, and either one
rule (rule_key: the RULE ID, else the rule summary) or every rule of that check.
"""

from pyfrc2g.analysis import risk
from pyfrc2g.analysis.exceptions import rule_key, split  # noqa: F401 (rule_key used by the routes)

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def engine_list(exceptions):
    """Return the approved exceptions in the engine format (as in the --exceptions file)."""
    # Pending and rejected exceptions are not applied.
    return [{"check": e["check_name"], "rule": e.get("rule_key") or "", "gateway": e.get("gateway") or "",
             "reason": e["reason"], "owner": e.get("owner") or "", "expires": e.get("expires") or ""}
            for e in exceptions if e.get("status", "approved") == "approved"]


def apply(data, exceptions, gateway, today=None):
    """
    Split data["audit_all"] (every finding; seeded from data["audit"] on the first call) into
    data["audit"] (active) and data["accepted"], and recompute severities and risk. Return data.
    """
    everything = data.get("audit_all")
    if everything is None:
        everything = data["audit_all"] = list(data.get("audit") or [])
    active, accepted = split(everything, engine_list(exceptions), gateway, today)
    changed = bool(accepted) or bool(data.get("_excepted"))
    data["audit"], data["accepted"], data["_excepted"] = active, accepted, bool(accepted)
    data["severities"] = {s: n for s in SEVERITIES if (n := sum(1 for f in active if f.get("SEVERITY") == s))}
    if changed and data.get("risk"):
        before = data["risk"]
        computed = risk.compute(active)
        previous = before["score"] - before["delta"] if before.get("delta") is not None \
            and before.get("score") is not None else None
        before.update(score=computed["score"], level=computed["level"], by_interface=computed["by_interface"],
                      delta=None if previous is None else computed["score"] - previous)
    return data


def expiring(exceptions, days, today=None):
    """Return [(exception, days left)] for approved exceptions expiring within `days` days, soonest first."""
    from datetime import date, timedelta

    today = today or date.today()
    limit = today + timedelta(days=days)
    soon = []
    for e in exceptions:
        if e.get("status", "approved") != "approved" or not e.get("expires"):
            continue
        try:
            expires = date.fromisoformat(str(e["expires"]))
        except ValueError:
            continue
        if today <= expires <= limit:
            soon.append((e, (expires - today).days))
    return sorted(soon, key=lambda item: item[1])


def remind(db, days, today=None):
    """Emit an audit event (syslog / webhook) once per exception and expiry date. Return the number sent."""
    sent = 0
    for e, left in expiring(db.exceptions(), days, today):
        key = f"risk_reminder:{e['id']}"
        if db.get_meta(key) == str(e["expires"]):
            continue
        db.set_meta(key, str(e["expires"]))
        db.add_event("system", "accepted risk expiring",
                     f"{e['check_name']} on {e.get('gateway') or 'all firewalls'}: expires {e['expires']} "
                     f"({left} day(s)), owner {e.get('owner') or '-'}, accepted by {e.get('username')}")
        sent += 1
    return sent


def summary(data):
    """Return the dashboard figures of an analysis."""
    return {"score": (data.get("risk") or {}).get("score"), "level": (data.get("risk") or {}).get("level"),
            "rules": len(data.get("rules") or []), "findings": len(data.get("audit") or []),
            "critical": (data.get("severities") or {}).get("CRITICAL", 0)}


def refresh(db, gateway_names=None):
    """
    Re-evaluate the latest analysis of the gateways (all by default) after a change of the
    exceptions, and update the dashboard figures.
    """
    exceptions = db.exceptions()
    for gw in db.gateways():
        if gateway_names is not None and gw["name"] not in gateway_names:
            continue
        analyses = db.analyses(gw["id"])
        if not analyses:
            continue
        analysis = db.analysis(analyses[0]["id"])
        data = apply(analysis["data"], exceptions, gw["name"])
        db.update_analysis_data(analysis["id"], data)
        db.update_gateway_summary(gw["id"], summary(data))


def regeneration_sources(db, gateway_names=None):
    """
    Analysis sources that regenerate the reports (PDF, HTML, Excel, CSV) of the gateways, so that
    they follow a change of the accepted risks: API firewalls are read again, configuration
    files are analysed again from the stored file.
    """
    sources = []
    firewalls = {f["id"]: f for f in db.firewalls()}
    for gw in db.gateways():
        if gateway_names is not None and gw["name"] not in gateway_names:
            continue
        if gw["kind"] == "api" and firewalls.get(gw["firewall_id"], {}).get("enabled"):
            sources.append({"kind": "api", "firewall_id": gw["firewall_id"], "force": True})
        elif gw["kind"] == "upload" and gw.get("upload_id"):
            sources.append({"kind": "upload", "upload_id": gw["upload_id"]})
    return sources


def regenerate(app, db, gateway_names, user_id):
    """Queue the regeneration of the reports. Return the run id, or None when there is nothing to do."""
    sources = regeneration_sources(db, gateway_names)
    if not sources or getattr(app, "runner", None) is None:
        return None
    label = "Reports updated for the accepted risks"
    return app.runner.submit("manual", label, sources, user_id)
