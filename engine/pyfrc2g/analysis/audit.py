"""
Risk detection on firewall rules (works on the normalized CSV rows).

Checks:
    ANY_ANY            pass rule from any source to any destination
    WAN_EXPOSED        pass rule on an Internet-facing interface opening admin/sensitive ports
    SHADOWED           rule never reached: an earlier rule on the same interface matches first
    REDUNDANT          rule fully covered by an earlier rule with the same action
    DISABLED           disabled rule still present in the configuration
    NO_DESCRIPTION     rule without description
"""

import re

from pyfrc2g import utils

AUDIT_FIELDNAMES = ["SEVERITY", "CHECK", "GATEWAY", "RULE ORDER", "RULE ID", "RULE", "DETAIL"]
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

_ANY_VALUES = frozenset({"", "any", "*", "(any)"})
_ANY_IP_VERSIONS = frozenset({"", "any", "inet46", "ipv4+ipv6", "ipv4+6"})
_FIREWALL_SELF_MARKERS = ("address", "(self)", "this firewall", "this_firewall")
_PORT_TOKEN = re.compile(r"^(\d{1,5})(?:\s*[:\-]\s*(\d{1,5}))?$")


def is_any(value):
    return (value or "").strip().lower() in _ANY_VALUES


def parse_ports(value):
    """
    Parse a port field ("443", "80, 443", "1000:2000", "80 443") into a list of (low, high)
    ranges. Returns None for "any", and [] when the value is not numeric (unresolved alias).
    """
    if is_any(value):
        return None
    ranges = []
    for token in re.split(r"[,\s]+", str(value).strip()):
        if not token:
            continue
        match = _PORT_TOKEN.match(token)
        if not match:
            return []
        low = int(match.group(1))
        high = int(match.group(2) or low)
        ranges.append((min(low, high), max(low, high)))
    return ranges


def _ports_intersect(ranges, ports):
    """Return sorted ports of `ports` included in ranges (None = any port)."""
    if ranges is None:
        return sorted(ports)
    return sorted(p for p in ports if any(lo <= p <= hi for lo, hi in ranges))


def _ports_cover(a, b):
    """True if port field a matches every port matched by b."""
    if is_any(a):
        return True
    if (a or "").strip().lower() == (b or "").strip().lower():
        return True
    ra, rb = parse_ports(a), parse_ports(b)
    if not ra or rb is None or not rb:
        return False
    return all(any(alo <= lo and hi <= ahi for alo, ahi in ra) for lo, hi in rb)


def _split_protocol(value):
    """'inet tcp' -> ('inet', 'tcp'); 'tcp' -> ('', 'tcp')."""
    parts = (value or "").strip().lower().split()
    if len(parts) >= 2:
        return parts[0], parts[-1]
    if parts and parts[0].startswith(("inet", "ipv")):
        return parts[0], "any"
    return "", parts[0] if parts else "any"


def _protocol_cover(a, b):
    ip_a, proto_a = _split_protocol(a)
    ip_b, proto_b = _split_protocol(b)
    ip_ok = ip_a in _ANY_IP_VERSIONS or ip_a == ip_b
    proto_ok = (proto_a == "any" or proto_a == proto_b
                or (proto_a == "tcp/udp" and proto_b in ("tcp", "udp")))
    return ip_ok and proto_ok


def _address_cover(a, b):
    return is_any(a) or (a or "").strip().lower() == (b or "").strip().lower()


def _covers(a, b):
    """True if rule a matches every packet matched by rule b (conservative)."""
    return (_address_cover(a.get("SOURCE"), b.get("SOURCE"))
            and _address_cover(a.get("DESTINATION"), b.get("DESTINATION"))
            and _protocol_cover(a.get("PROTOCOL"), b.get("PROTOCOL"))
            and _ports_cover(a.get("PORT"), b.get("PORT")))


def _is_true(value):
    return (value or "").strip() in ("True", "1")


def _interface_names(gateway):
    """'fw/WAN, LAN' -> {'wan', 'lan'}."""
    iface = gateway.split("/", 1)[1] if "/" in gateway else gateway
    return {part.strip().lower() for part in iface.split(",") if part.strip()}


def _wan_names(config):
    names = {n.lower() for n in getattr(config, "wan_interfaces", ["wan"])}
    wan_descr = utils.API_INTERFACE_MAP.get("wan")
    if wan_descr:
        names.add(str(wan_descr).lower())
    return names


def _rule_summary(row):
    return (f"{row.get('ACTION', '')} {row.get('SOURCE', '')} -> {row.get('DESTINATION', '')} "
            f"[{row.get('PROTOCOL', '')} {row.get('PORT', '')}]")


def _finding(severity, check, row, detail):
    return {
        "SEVERITY": severity,
        "CHECK": check,
        "GATEWAY": row.get("GATEWAY", ""),
        "RULE ORDER": row.get("RULE ORDER", ""),
        "RULE ID": row.get("RULE ID", ""),
        "RULE": _rule_summary(row),
        "DETAIL": detail,
    }


def _check_rule(row, config, wan_names):
    """Checks that only look at one rule."""
    findings = []
    action = (row.get("ACTION") or "").strip().lower()
    enabled = not _is_true(row.get("DISABLED"))

    if not enabled:
        findings.append(_finding("LOW", "DISABLED", row,
                                 "Disabled rule still present: remove it if it is no longer needed."))
    comment = (row.get("COMMENT") or "").strip()
    if not comment or comment.lower() == "any":
        findings.append(_finding("LOW", "NO_DESCRIPTION", row,
                                 "Rule without description: purpose cannot be audited."))
    if not enabled or action != "pass":
        return findings

    any_any = is_any(row.get("SOURCE")) and is_any(row.get("DESTINATION"))
    if any_any:
        if is_any(row.get("PORT")):
            findings.append(_finding("CRITICAL", "ANY_ANY", row,
                                     "Any source to any destination on all ports."))
        else:
            findings.append(_finding("MEDIUM", "ANY_ANY", row,
                                     f"Any source to any destination (ports {row.get('PORT')})."))

    is_floating = _is_true(row.get("FLOATING"))
    if not is_floating and _interface_names(row.get("GATEWAY", "")) & wan_names:
        if not is_any(row.get("SOURCE")):
            return findings
        ranges = parse_ports(row.get("PORT"))
        if ranges == []:
            return findings  # Unresolved alias: cannot tell.
        destination = (row.get("DESTINATION") or "").lower()
        to_firewall = any(marker in destination for marker in _FIREWALL_SELF_MARKERS)
        admin = _ports_intersect(ranges, config.admin_ports)
        sensitive = _ports_intersect(ranges, config.sensitive_ports)
        if ranges is None and not any_any:
            findings.append(_finding("HIGH", "WAN_EXPOSED", row,
                                     "All ports open from the Internet."))
        elif admin and to_firewall:
            findings.append(_finding("CRITICAL", "WAN_EXPOSED", row,
                                     f"Firewall administration exposed to the Internet "
                                     f"(ports {', '.join(map(str, admin))})."))
        elif admin or sensitive:
            ports = ", ".join(map(str, sorted(set(admin) | set(sensitive))))
            findings.append(_finding("HIGH", "WAN_EXPOSED", row,
                                     f"Administration/sensitive ports open from the Internet "
                                     f"({ports})."))
    return findings


def _check_shadowing(rows):
    """First-match analysis per interface (floating rules are excluded: last-match by default)."""
    findings = []
    by_gateway = {}
    for row in rows:
        if _is_true(row.get("FLOATING")) or _is_true(row.get("DISABLED")):
            continue
        by_gateway.setdefault(row.get("GATEWAY", ""), []).append(row)

    def order(row):
        try:
            return int(row.get("RULE ORDER") or 0)
        except ValueError:
            return 0

    for gateway_rows in by_gateway.values():
        gateway_rows.sort(key=order)
        for index, rule in enumerate(gateway_rows):
            for earlier in gateway_rows[:index]:
                if not _covers(earlier, rule):
                    continue
                same_action = (earlier.get("ACTION") or "").lower() == (rule.get("ACTION") or "").lower()
                if same_action:
                    findings.append(_finding(
                        "LOW", "REDUNDANT", rule,
                        f"Already covered by rule #{earlier.get('RULE ORDER')} (same action)."))
                else:
                    findings.append(_finding(
                        "MEDIUM", "SHADOWED", rule,
                        f"Never reached: rule #{earlier.get('RULE ORDER')} "
                        f"({earlier.get('ACTION')}) matches the same traffic first."))
                break
    return findings


def audit_rules(rows, config):
    """
    Run all checks on normalized rule rows.

    Returns:
        list: Findings (dicts with AUDIT_FIELDNAMES keys), most severe first.
    """
    wan_names = _wan_names(config)
    findings = []
    for row in rows:
        findings.extend(_check_rule(row, config, wan_names))
    findings.extend(_check_shadowing(rows))
    rank = {s: i for i, s in enumerate(SEVERITIES)}

    def sort_key(f):
        try:
            order = int(f["RULE ORDER"] or 0)
        except ValueError:
            order = 0
        return rank.get(f["SEVERITY"], 99), f["GATEWAY"], order

    return sorted(findings, key=sort_key)


def count_by_severity(findings):
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f["SEVERITY"]] = counts.get(f["SEVERITY"], 0) + 1
    return counts
