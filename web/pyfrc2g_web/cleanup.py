"""
Cleanup plan of a firewall: the findings about rules that can usually be removed or tidied (unused, shadowed,
redundant, disabled...), grouped by category, with the risk score the firewall would get without them.
"""

import csv
import io

from pyfrc2g.analysis import risk

from pyfrc2g_web import csvsafe

# check -> (label, advice)
CATEGORIES = {
    "UNUSED": ("Unused rule", "No traffic during the observation period: confirm with the owner, then remove."),
    "NO_RECENT_TRAFFIC": ("No recent traffic", "Traffic seen before but not recently: review, disable, then remove."),
    "SHADOWED": ("Shadowed rule", "An earlier rule always decides first, so this rule is never reached: remove it."),
    "REDUNDANT": ("Redundant rule", "An earlier rule already does the same: remove it."),
    "PARTIAL_OVERLAP": ("Partial overlap", "Part of the traffic is decided earlier by a rule with another action: "
                                             "review the order."),
    "DISABLED": ("Disabled rule", "Disabled but still in the configuration: remove it if no longer needed."),
    "NO_DESCRIPTION": ("No description", "Document the purpose and the owner of the rule."),
}
FIELDS = ["CATEGORY", "CHECK", "SEVERITY", "GATEWAY", "RULE ORDER", "RULE", "ADVICE", "DETAIL"]


def plan(data):
    """Return {'items': [...], 'groups': [{check, label, advice, count, gain}], 'score', 'score_after', 'gain'}."""
    findings = data.get("audit") or []
    score = risk.score(findings)
    items = [f for f in findings if f.get("CHECK") in CATEGORIES]
    groups = []
    for check, (label, advice) in CATEGORIES.items():
        mine = [f for f in items if f["CHECK"] == check]
        if mine:
            gain = score - risk.score([f for f in findings if f.get("CHECK") != check])
            groups.append({"check": check, "label": label, "advice": advice, "count": len(mine), "gain": gain})
    after = risk.score([f for f in findings if f.get("CHECK") not in CATEGORIES])
    return {"items": items, "groups": groups, "score": score, "score_after": after, "gain": score - after}


def to_csv(result):
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=FIELDS, extrasaction="ignore")
    writer.writeheader()
    for item in result["items"]:
        label, advice = CATEGORIES[item["CHECK"]]
        row = {"CATEGORY": label, "ADVICE": advice, **item}
        writer.writerow({k: csvsafe.cell(v) for k, v in row.items()})
    return out.getvalue()
