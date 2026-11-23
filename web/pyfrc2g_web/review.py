"""
Rule ownership and periodic review: each rule of a firewall can carry an owner, a ticket reference and a
comment, and a review date. A rule not reviewed for `review_months` months is overdue.

Rules are identified by their RULE ID, else by their text (the same key as the accepted risks), so the notes
survive new analyses.
"""

from datetime import date

from pyfrc2g.analysis.exceptions import rule_key


def months_between(start, end):
    return (end.year - start.year) * 12 + end.month - start.month - (1 if end.day < start.day else 0)


def status(note, months, today=None):
    """Return 'never', 'overdue' or 'ok' for the note of a rule (None = no note); 'off' when reviews are disabled."""
    if not months:
        return "off"
    reviewed = (note or {}).get("reviewed")
    if not reviewed:
        return "never"
    try:
        last = date.fromisoformat(reviewed)
    except ValueError:
        return "never"
    return "overdue" if months_between(last, today or date.today()) >= months else "ok"


def rows(data, notes, months, today=None):
    """Return the enabled, non-automatic rules of an analysis with their note and review status."""
    out = []
    for rule in data.get("rules") or []:
        if str(rule.get("DISABLED") or "") in ("True", "1") or str(rule.get("AUTOMATIC") or "") in ("True", "1"):
            continue
        key = rule_key(rule)
        note = notes.get(key)
        out.append({"key": key, "rule": rule, "note": note or {}, "status": status(note, months, today)})
    return out


def counts(items):
    result = {"never": 0, "overdue": 0, "ok": 0, "off": 0}
    for item in items:
        result[item["status"]] += 1
    return result


def remind(db, today=None):
    """Audit event once per firewall when its number of rules to review changes. Return the events raised."""
    months = int(db.settings().get("review_months") or 0)
    if not months:
        return 0
    raised = 0
    for gw in db.gateways():
        analyses = db.analyses(gw["id"])
        if not analyses:
            continue
        data = db.analysis(analyses[0]["id"])["data"]
        stats = counts(rows(data, db.rule_notes(gw["name"]), months, today))
        due = stats["never"] + stats["overdue"]
        key = f"review_due:{gw['name']}"
        if due and db.get_meta(key) != str(due):
            db.add_event("system", "rules to review", f"{gw['name']}: {stats['overdue']} overdue, "
                         f"{stats['never']} never reviewed (review every {months} months)")
            raised += 1
        db.set_meta(key, str(due))
    return raised
