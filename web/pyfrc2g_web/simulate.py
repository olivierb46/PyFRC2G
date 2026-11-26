"""
What-if for a firewall rule: add a rule to the stored rules of a firewall and see what the audit says about the
result (new findings, findings that go away, rules that become shadowed or redundant, and the risk score).

The audit is the one of the engine, run on the stored rules (with the alias tables saved with the analysis). It
covers the checks on the rules themselves; the compliance policy and the traffic counters (unused rules) are not
part of it. The rule is only simulated: nothing is sent to the firewall.
"""

from collections import Counter
from types import SimpleNamespace

from pyfrc2g.analysis import risk
from pyfrc2g.analysis.audit import audit_rules
from pyfrc2g.analysis.exceptions import rule_key
from pyfrc2g.model.rules import interface_of

from pyfrc2g_web import flows

PROPOSED = "(proposed rule)"
IGNORED = ("UNUSED", "NO_RECENT_TRAFFIC")  # Traffic counters say nothing about a rule that does not exist yet.
FIELDS = 200
MAX_RULES = 5000
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


class SimulationError(ValueError):
    pass


def interfaces(data):
    """Return [(display name, GATEWAY value)] of the interfaces holding rules, floating rules included."""
    seen = {}
    for row in data.get("rules") or []:
        seen.setdefault(interface_of(row), row.get("GATEWAY", ""))
    return list(seen.items())


def _config(data, settings):
    return SimpleNamespace(gateway_type=data.get("gateway_type") or "pfsense",
                           admin_ports=list(settings.get("admin_ports") or []),
                           sensitive_ports=list(settings.get("sensitive_ports") or []),
                           wan_interfaces=list(settings.get("wan_interfaces") or ["wan"]))


def _rows(data):
    """Copies of the stored rules (the audit works on dicts it may complete)."""
    return [dict(r) for r in data.get("rules") or []]


def _proposed_row(group, rule):
    return {"GATEWAY": group, "RULE ORDER": "0", "ACTION": rule["action"], "SOURCE": rule["source"],
            "DESTINATION": rule["destination"], "PROTOCOL": rule["protocol"], "PORT": rule["port"],
            "COMMENT": rule["comment"], "DISABLED": "False", "FLOATING": "False", "RULE ID": PROPOSED,
            "IP VERSION": flows._version_label(rule["source"] + " " + rule["destination"]) or "IPv4",
            "AUTOMATIC": "False", "DIRECTION": "in"}


def _insert(rows, row, position):
    """Insert the proposed rule in its interface at `position` (1-based, None = last) and renumber that interface."""
    group = [i for i, r in enumerate(rows) if r.get("GATEWAY") == row["GATEWAY"]]
    orders = [int(rows[i].get("RULE ORDER") or 0) for i in group]
    at = max(orders, default=0) + 1 if position is None else max(1, min(position, max(orders, default=0) + 1))
    index = next((i for i in group if int(rows[i].get("RULE ORDER") or 0) >= at),
                 (group[-1] + 1) if group else len(rows))
    for i in group:
        if int(rows[i].get("RULE ORDER") or 0) >= at:
            rows[i]["RULE ORDER"] = str(int(rows[i]["RULE ORDER"]) + 1)
    row["RULE ORDER"] = str(at)
    rows.insert(index, row)
    return at


def _audit(rows, config):
    findings = audit_rules(rows, config)
    return [f for f in findings if f.get("CHECK") not in IGNORED and not f["CHECK"].startswith("POLICY")]


def _key(finding):
    return finding["CHECK"], rule_key(finding)


def _pick(findings, keys):
    """The first finding of each key."""
    return [next(f for f in findings if _key(f) == key) for key in keys]


def run(data, settings, interface, rule, position=None):
    """Simulate adding `rule` to `interface`, at `position` (1-based, None = last).

    Return {"new", "gone", "order", "score_before", "score_after", "warning"}: the findings that appear and those
    that disappear (audit findings), the order the rule gets, and the risk score before and after.
    Raises SimulationError (or flows.FlowError when an analysis holds the engine for too long).
    """
    names = ("action", "source", "destination", "protocol", "port", "comment")
    rule = {k: str(rule.get(k, "")).strip() for k in names}
    if rule["action"] not in ("pass", "block", "reject"):
        raise SimulationError("Action: pass, block or reject.")
    if not rule["source"] or not rule["destination"] or max(len(v) for v in rule.values()) > FIELDS:
        raise SimulationError("Give a source and a destination (address, network or alias), 200 characters at most.")
    rule["protocol"] = rule["protocol"].lower() or "any"
    if rule["protocol"] not in flows.PROTOCOLS:
        raise SimulationError("Protocol: any, tcp, udp or icmp.")
    rule["port"] = rule["port"] or "any"
    group = dict(interfaces(data)).get(interface)
    if group is None:
        raise SimulationError("Choose one of the interfaces of the firewall.")
    if len(data.get("rules") or []) > MAX_RULES:
        raise SimulationError(f"Too many rules to simulate ({MAX_RULES} at most).")
    config = _config(data, settings)
    with flows.maps_installed(data):
        before = _audit(_rows(data), config)
        rows = _rows(data)
        order = _insert(rows, _proposed_row(group, rule), position)
        after = _audit(rows, config)
    was, now = Counter(map(_key, before)), Counter(map(_key, after))
    new = sorted(_pick(after, now - was), key=lambda f: SEVERITY_ORDER.get(f["SEVERITY"], 9))
    gone = sorted(_pick(before, was - now), key=lambda f: SEVERITY_ORDER.get(f["SEVERITY"], 9))
    return {"new": new, "gone": gone, "order": order, "score_before": risk.score(before),
            "score_after": risk.score(after), "warning": "" if data.get("maps") else flows.NO_MAPS}
