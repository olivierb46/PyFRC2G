"""
Flow search: "can A reach B on port P?" evaluated on the rules of a stored analysis.

The rules of each interface are read in order and the first one that matches the whole flow decides. Aliases
and interface names are resolved with the lookup maps saved with the analysis (data["maps"]); a rule using
something that cannot be resolved (FQDN, URL table, geo-IP...) is reported as uncertain, never as a match.
The result is an aid for change requests and audits, not a proof: NAT, routing and the real traffic are not
simulated.
"""

import ipaddress
import json
from collections import OrderedDict

LOCK_WAIT = 3  # Seconds to wait for a running analysis (the engine keeps its lookup maps in globals).
PROTOCOLS = ("any", "tcp", "udp", "icmp")


class FlowError(ValueError):
    pass


def snapshot():
    """Lookup maps of the analysis being built (called by the runner while the engine maps are installed)."""
    from pyfrc2g import utils

    maps = {"interface_map": utils.API_INTERFACE_MAP, "interface_nets": utils.API_INTERFACE_NETS,
            "alias_details": utils.API_ALIAS_DETAILS}
    return json.loads(json.dumps(maps, default=str))  # A copy that is certain to be storable.


def _version_label(text):
    for part in str(text).replace(",", " ").split():
        try:
            return "IPv6" if ipaddress.ip_network(part.strip("!"), strict=False).version == 6 else "IPv4"
        except ValueError:
            continue
    return ""


def _describe(row):
    return {"order": row.get("RULE ORDER"), "action": (row.get("ACTION") or "").lower(),
            "source": row.get("SOURCE"), "destination": row.get("DESTINATION"), "protocol": row.get("PROTOCOL"),
            "port": row.get("PORT"), "comment": row.get("COMMENT") or ""}


def _evaluate(data, source, destination, protocol, port):
    from pyfrc2g.model import netmodel
    from pyfrc2g.model.rules import interface_of, interface_part

    query = netmodel.CompiledRule({"SOURCE": source, "DESTINATION": destination, "PROTOCOL": protocol,
                                   "PORT": port, "ACTION": "pass", "IP VERSION": _version_label(source)})
    groups = OrderedDict()
    for row in data.get("rules") or []:
        rule = netmodel.CompiledRule(dict(row))  # A copy: the rows of the analysis stay untouched.
        if not rule.enabled or rule.established_only:
            continue
        group = groups.setdefault(interface_of(row), {"decision": None, "partial": []})
        if group["decision"] is not None:
            continue
        if netmodel.rule_covers(rule, query):
            group["decision"] = row
        elif netmodel.rule_intersects(rule, query) is not False:
            group["partial"].append(row)
    results = []
    for name, group in groups.items():
        iface = netmodel.interface_id(interface_part(name))
        nets = netmodel.interface_networks(iface) if iface else []
        likely = bool(nets) and query.src.known and any(
            n.version == m.version and n.overlaps(m) for n in query.src.nets for m in nets)
        row = group["decision"]
        results.append({"interface": name, "likely": likely,
                        "verdict": (row.get("ACTION") or "").lower() if row else "none",
                        "rule": _describe(row) if row else None,
                        "partial": [_describe(r) for r in group["partial"][:5]]})
    return results


def search(data, source, destination, protocol="any", port=""):
    """Return {'results': [per interface], 'warning': text or ''} for one analysis. Raises FlowError."""
    from pyfrc2g import utils

    from pyfrc2g_web.jobs import RUN_LOCK

    source, destination = source.strip(), destination.strip()
    protocol = (protocol or "any").strip().lower()
    port = (port or "").strip() or "any"
    if not source or not destination or max(len(source), len(destination), len(port)) > 200:
        raise FlowError("Give a source and a destination (address, network or alias).")
    if protocol not in PROTOCOLS:
        raise FlowError("Protocol: any, tcp, udp or icmp.")
    maps = data.get("maps")
    if not RUN_LOCK.acquire(timeout=LOCK_WAIT):
        raise FlowError("An analysis is running: try again in a moment.")
    previous = (utils.API_INTERFACE_MAP, utils.API_NET_MAP, utils.API_ADDRESS_MAP, utils.API_PORT_MAP,
                utils.API_ALIAS_DETAILS, utils.API_INTERFACE_NETS)
    try:
        maps = maps or {}
        utils.update_api_maps(maps.get("interface_map", {}), {}, {}, {}, maps.get("alias_details", {}),
                              maps.get("interface_nets", {}))
        results = _evaluate(data, source, destination, protocol, port)
    finally:
        utils.update_api_maps(*previous)
        RUN_LOCK.release()
    warning = "" if maps else ("This analysis was stored without its alias tables: aliases and interface names "
                               "cannot be resolved. Analyse the firewall again.")
    return {"results": results, "warning": warning}
