"""
Remediation tracking: a finding of the audit can be assigned to somebody with a due date, and followed until it is
gone.

The status is kept up to date by the analyses: a tracked finding that is no longer among the findings of the latest
analysis is "fixed" (the analysis is the proof); one that is only hidden because the risk was accepted is "accepted";
one that comes back is "reopened". "open" and "in progress" are set by people, and so is "cancelled".
"""

from datetime import date, datetime

from pyfrc2g.analysis.exceptions import rule_key

STATUSES = (("open", "Open"), ("in_progress", "In progress"), ("reopened", "Reopened"), ("fixed", "Fixed"),
            ("accepted", "Risk accepted"), ("cancelled", "Cancelled"))
ACTIVE = ("open", "in_progress", "reopened")  # Still to do.
MANUAL = ("open", "in_progress", "cancelled")  # What a person can choose.


def finding_key(finding):
    return finding.get("CHECK", ""), rule_key(finding)


def is_overdue(item, today=None):
    return bool(item.get("due")) and item["status"] in ACTIVE and item["due"] < (today or date.today()).isoformat()


def days_open(item, today=None):
    """Days since the tracking started (until the fix for a fixed one)."""
    try:
        start = datetime.strptime(item["created"], "%Y-%m-%d %H:%M:%S").date()
        end = (datetime.strptime(item["fixed"], "%Y-%m-%d %H:%M:%S").date() if item.get("fixed")
               else (today or date.today()))
    except (TypeError, ValueError):
        return None
    return max(0, (end - start).days)


def stats(items, today=None):
    """Counts by status, overdue items and the mean number of days to fix."""
    counts = {key: 0 for key, _ in STATUSES}
    for item in items:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    times = [d for i in items if i["status"] == "fixed" and (d := days_open(i, today)) is not None]
    return {"counts": counts, "active": sum(counts[s] for s in ACTIVE),
            "overdue": sum(1 for i in items if is_overdue(i, today)),
            "mean_days_to_fix": round(sum(times) / len(times), 1) if times else None}


def sync(db, gateway, data, moment=None):
    """Update the tracked findings of a firewall from its latest analysis. Return the list of changes made."""
    items = [i for i in db.remediations([gateway])]
    if not items:
        return []
    present = {finding_key(f) for f in data.get("audit") or []}
    hidden = {finding_key(f) for f in data.get("accepted") or []}
    stamp = moment or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    changes = []
    for item in items:
        key = (item["check_name"], item["rule_key"])
        status = item["status"]
        if key in present:
            if status in ("fixed", "accepted"):
                db.update_remediation(item["id"], status="reopened", fixed=None)
                changes.append((item, "reopened"))
        elif status in ACTIVE or status == "reopened":
            new = "accepted" if key in hidden else "fixed"
            db.update_remediation(item["id"], status=new, fixed=stamp if new == "fixed" else None)
            changes.append((item, new))
        elif status == "accepted" and key not in hidden:
            db.update_remediation(item["id"], status="fixed", fixed=stamp)  # The accepted rule was removed.
            changes.append((item, "fixed"))
    for item, new in changes:
        db.add_event("system", f"remediation {new}", f"{gateway}: {item['check_name']} (assigned to "
                     f"{item['assignee'] or 'nobody'})")
    return changes


def remind(db, today=None):
    """Audit event once for each item that becomes overdue. Return the number raised."""
    raised = 0
    for item in db.remediations():
        key = f"remediation_overdue:{item['id']}"
        if is_overdue(item, today) and db.get_meta(key) != item["due"]:
            db.set_meta(key, item["due"])
            db.add_event("system", "remediation overdue", f"{item['gateway']}: {item['check_name']} was due on "
                         f"{item['due']} (assigned to {item['assignee'] or 'nobody'})")
            raised += 1
    return raised
