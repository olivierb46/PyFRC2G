"""
Who is in charge of what: for each owner (person or team), the firewalls, the rules, the findings being fixed and the
accepted risks they are responsible for. The owners are the names typed in the firewall settings, in the rule review
and in the remediation follow-up (compared without regard to case).
"""

import csv
import io
from datetime import date

from pyfrc2g_web import csvsafe, remediation, review

NO_OWNER = "(no owner)"
FIELDS = ["OWNER", "FIREWALLS", "RULES OWNED", "RULES TO REVIEW", "FINDINGS TO FIX", "OVERDUE", "FIXED",
          "ACCEPTED RISKS", "RISKS EXPIRING"]


def _row(name):
    return {"owner": name, "firewalls": set(), "rules": 0, "to_review": 0, "todo": 0, "overdue": 0, "fixed": 0,
            "risks": 0, "expiring": 0}


def collect(db, gateways, today=None, expiring_days=14):
    """Return the rows (one per owner, sorted by what needs attention first) for the given labelled gateways."""
    today = today or date.today()
    months = int(db.settings().get("review_months") or 0)
    rows, names = {}, {}

    def of(raw):
        text = (raw or "").strip()
        key = text.lower() or NO_OWNER
        names.setdefault(key, text or NO_OWNER)
        return rows.setdefault(key, _row(names[key]))

    visible = {gw["name"] for gw in gateways}
    for gw in gateways:
        if gw.get("owner"):
            of(gw["owner"])["firewalls"].add(gw["name"])
        analyses = db.analyses(gw["id"])
        if not analyses:
            continue
        data = db.analysis(analyses[0]["id"])["data"]
        for item in review.rows(data, db.rule_notes(gw["name"]), months, today):
            owner = of(item["note"].get("owner"))
            owner["rules"] += 1
            owner["firewalls"].add(gw["name"])
            if item["status"] in ("never", "overdue"):
                owner["to_review"] += 1
    for item in db.remediations(visible):
        owner = of(item["assignee"])
        owner["firewalls"].add(item["gateway"])
        if item["status"] in remediation.ACTIVE:
            owner["todo"] += 1
            owner["overdue"] += remediation.is_overdue(item, today)
        elif item["status"] == "fixed":
            owner["fixed"] += 1
    from pyfrc2g_web import exceptions

    risks = [e for e in db.exceptions() if e.get("status", "approved") == "approved"
             and (not e.get("gateway") or e["gateway"] in visible)]
    soon = {e["id"] for e, _ in exceptions.expiring(risks, expiring_days, today)}
    for risk in risks:
        owner = of(risk.get("owner"))
        owner["risks"] += 1
        owner["expiring"] += risk["id"] in soon
        if risk.get("gateway"):
            owner["firewalls"].add(risk["gateway"])
    result = list(rows.values())
    for row in result:
        row["firewalls"] = sorted(row["firewalls"])
    # What needs attention first: overdue, then to review; the rules nobody owns last (they are a to-do of their own).
    return sorted(result, key=lambda r: (r["owner"] == NO_OWNER, -r["overdue"], -r["to_review"], -r["todo"],
                                         r["owner"].lower()))


def to_csv(rows):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(FIELDS)
    for r in rows:
        writer.writerow([csvsafe.cell(x) for x in (r["owner"], " ".join(r["firewalls"]), r["rules"], r["to_review"],
                                                   r["todo"], r["overdue"], r["fixed"], r["risks"], r["expiring"])])
    return out.getvalue()
