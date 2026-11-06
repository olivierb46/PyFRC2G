"""
Inter-zone matrix: for each (source interface, destination zone) pair, is traffic
ALLOWED (all traffic), BLOCKED, or PARTIAL (some services / hosts only)?

Zones are the firewall interfaces (resolved through their networks, or symbolically when the
rule uses the interface network itself, e.g. "LAN net"), plus "Firewall" (the firewall's own
addresses) and "Internet" (anything outside the internal networks). IPv4 rules only;
outbound rules are ignored, non-quick rules (pf last match) only decide when no quick rule
matches. Only for pfSense / OPNsense / FortiGate (rules are attached to an ingress interface).
"""

from pyfrc2g import utils
from pyfrc2g.model import netmodel

MATRIX_FIELDNAMES = ["SOURCE ZONE", "DESTINATION ZONE", "STATUS", "DETAIL"]
STATUS_COLORS = {"ALLOWED": "#d4edda", "BLOCKED": "#f8d7da", "PARTIAL": "#fff3cd", "-": "#eeeeee"}
FIREWALL_ZONE = "Firewall"
INTERNET_ZONE = "Internet"


def _zone_name(iface):
    return str(utils.API_INTERFACE_MAP.get(iface) or iface.upper())


def _zone_set(iface):
    nets = [n for n in netmodel.interface_networks(iface) if n.version == 4]
    return netmodel.AddrSet(iface, items=[netmodel.Item(f"net:{iface}", nets)])


def _is_firewall_item(item):
    return item.key == "self" or item.key.startswith("addr:")


def _relation(rule_set, zone, firewall=False):
    """full / partial / none / unknown relation between a rule field and a zone."""
    if not firewall and not rule_set.negated and not rule_set.any and rule_set.items \
            and all(_is_firewall_item(item) for item in rule_set.items):
        return "none"  # "LAN address", "This firewall": traffic to the firewall itself.
    if firewall and not rule_set.negated and rule_set.items \
            and all(_is_firewall_item(item) for item in rule_set.items):
        # Firewall addresses are firewall addresses even when unknown (DHCP WAN).
        return "full" if any(item.key == "self" for item in rule_set.items) else "partial"
    if zone == INTERNET_ZONE:
        return _internet_relation(rule_set)
    if netmodel.addr_covers(rule_set, zone):
        return "full"
    result = netmodel.addr_intersects(rule_set, zone)
    return {True: "partial", False: "none"}.get(result, "unknown")


def _internet_relation(rule_set):
    local = netmodel.local_networks() + netmodel.interface_addresses()
    if rule_set.any:
        return "none" if rule_set.negated else "full"
    inner = rule_set.inner()
    internal_keys = {f"net:{i}" for i in netmodel.interface_ids() if i not in netmodel.wan_interfaces()}
    all_internal = all(item.key in internal_keys or item.key == "self" or item.key.startswith("addr:")
                       or (item.known and netmodel._nets_cover(local, item.nets)) for item in inner.items)
    if rule_set.negated:
        return "full" if all_internal else "unknown"
    if all_internal:
        return "none"
    if any(item.known for item in inner.items):
        return "partial"
    return "unknown"


def _ref(rule):
    """'LAN #11' (rule numbers restart in each group: interfaces, floating rules)."""
    group = rule.group.rsplit("/", 1)[-1]
    return f"{'Floating' if rule.floating else group} #{rule.order}"


def _blocked_text(blocks):
    shown = "; ".join(blocks[:4]) + ("; ..." if len(blocks) > 4 else "")
    return f"except: {shown}"


def _service(rule):
    proto = "any" if rule.protos is None else "/".join(sorted(rule.protos))
    return f"{proto} {rule.row.get('PORT')}" if not rule.ports.any else proto


def _egress_ok(rule, dst_id, wan):
    """FortiGate policies also select the egress interface (dstintf)."""
    if not rule.out_ifaces or "any" in rule.out_ifaces or dst_id == FIREWALL_ZONE:
        return True
    if dst_id == INTERNET_ZONE:
        return bool(rule.out_ifaces & wan)
    return dst_id in rule.out_ifaces


def _cell(rules, src_zone, dst_zone, dst_id=None, wan=frozenset()):
    pass_partial, block_partial = [], []
    fallback = None  # Last fully matching non-quick rule: the decision when no quick rule matches.
    for rule in rules:
        if 4 not in rule.ipver or not _egress_ok(rule, dst_id, wan):
            continue
        rs = _relation(rule.src, src_zone)
        rd = _relation(rule.dst, dst_zone, firewall=dst_id == FIREWALL_ZONE)
        if "none" in (rs, rd):
            continue
        full = rs == "full" and rd == "full" and rule.protos is None and rule.ports.any
        if not rule.quick:
            if full:
                fallback = rule
            continue
        if full:
            if rule.action == "pass":
                if block_partial:
                    return "PARTIAL", f"allowed by {_ref(rule)} {_blocked_text(block_partial)}"
                return "ALLOWED", _ref(rule)
            if pass_partial:
                return "PARTIAL", "; ".join(pass_partial)
            return "BLOCKED", _ref(rule)
        if rule.action == "pass":
            uncertain = "?" if "unknown" in (rs, rd) else ""
            pass_partial.append(f"{_ref(rule)}{uncertain} {_service(rule)}")
        else:
            label = (rule.row.get("COMMENT") or _service(rule)).strip()
            block_partial.append(f"{_ref(rule)} {label[:40]}")
    if fallback is not None and fallback.action == "pass":
        if block_partial:
            return "PARTIAL", f"allowed by {_ref(fallback)} {_blocked_text(block_partial)}"
        return "ALLOWED", _ref(fallback)
    if pass_partial:
        return "PARTIAL", "; ".join(pass_partial)
    if fallback is not None:
        return "BLOCKED", _ref(fallback)
    return "BLOCKED", "default deny"


PF_LIKE = ("pfsense", "opnsense", "fortigate")


def rules_for_interface(rules, gateway_type, interface):
    """Rules evaluated for traffic entering on interface, in evaluation order."""
    rules = [r for r in rules if not r.established_only and r.direction != "out"]
    if gateway_type == "opnsense":
        # Rows follow the real OPNsense evaluation order (sort_order), floating rules included.
        return sorted((r for r in rules if not r.ifaces or interface in r.ifaces), key=lambda r: r.seq)
    if gateway_type == "fortigate":
        # Policies are evaluated top-down whatever their interfaces: keep the global order.
        return sorted((r for r in rules if not r.ifaces or interface in r.ifaces), key=lambda r: r.seq)
    floating = [r for r in rules if r.floating and (not r.ifaces or interface in r.ifaces)]
    own = [r for r in rules if not r.floating and interface in r.ifaces]
    return floating + sorted(own, key=lambda r: r.order)


def build_matrix(rows, gateway_type):
    """
    Returns:
        dict or None: {"sources": [zone names], "destinations": [zone names],
                       "cells": {(src, dst): (status, detail)}, "rows": [CSV rows]}
    """
    if gateway_type not in PF_LIKE:
        return None
    rules = [r for r in netmodel.compile_rules(rows) if r.enabled]
    used = {iface for r in rules for iface in r.ifaces}
    wan = netmodel.wan_interfaces() | ({"wan"} if "wan" in netmodel.interface_ids() else set())
    ifaces = sorted((netmodel.interface_ids() | used) - {"floating", ""},
                    key=lambda i: (i not in wan, i != "lan", i))
    if not ifaces:
        return None

    firewall = netmodel.AddrSet("self", items=[netmodel.Item(
        "self", [a for a in netmodel.interface_addresses() if a.version == 4])])
    destinations = [(i, _zone_set(i)) for i in ifaces if i not in wan]
    if gateway_type != "fortigate":  # FortiGate: traffic to the box is ruled by local-in policies.
        destinations.append((FIREWALL_ZONE, firewall))
    destinations.append((INTERNET_ZONE, INTERNET_ZONE))

    matrix = {"sources": [], "destinations": [_zone_name(d) if d not in (FIREWALL_ZONE, INTERNET_ZONE)
                                              else d for d, _ in destinations],
              "cells": {}, "rows": []}
    for iface in ifaces:
        src_zone = INTERNET_ZONE if iface in wan else _zone_set(iface)
        src_name = _zone_name(iface)
        matrix["sources"].append(src_name)
        candidates = rules_for_interface(rules, gateway_type, iface)
        for (dst_id, dst_zone), dst_name in zip(destinations, matrix["destinations"]):
            if dst_id == iface:
                status, detail = "-", "same network (not filtered by the firewall)"
            elif iface in wan and dst_zone == INTERNET_ZONE:
                status, detail = "-", ""
            else:
                status, detail = _cell(candidates, src_zone, dst_zone, dst_id, wan)
            matrix["cells"][(src_name, dst_name)] = (status, detail)
            matrix["rows"].append({"SOURCE ZONE": src_name, "DESTINATION ZONE": dst_name,
                                   "STATUS": status, "DETAIL": detail})
    return matrix
