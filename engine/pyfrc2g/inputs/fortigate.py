"""
FortiGate full configuration backup (FortiOS 6.x / 7.x "show full-configuration" / backup .conf).

Read: system global (hostname), system interface / zone (names, aliases, addresses, role wan),
firewall address / address6 / addrgrp / addrgrp6, firewall service custom / group, firewall
policy (in configuration order: FortiGate evaluates policies top-down, first match) and
firewall vip (port forwards / static NAT). With VDOMs, the first VDOM is used.

A policy with services of several protocols is split into one rule per protocol.
"""

import ipaddress
import shlex
from collections import OrderedDict

from pyfrc2g.inputs import register_alias
from pyfrc2g.model.netmodel import WELL_KNOWN_PORTS
from pyfrc2g.utils import add_interface_address, empty_maps

_PREDEFINED_SERVICES = {
    "all": ("any", None), "all_tcp": ("tcp", None), "all_udp": ("udp", None),
    "all_icmp": ("icmp", None), "ping": ("icmp", None), "all_icmp6": ("ipv6-icmp", None),
    "dns": ("tcp/udp", "53"), "ntp": ("tcp/udp", "123"), "snmp": ("udp", "161-162"),
    "syslog": ("udp", "514"), "dhcp": ("udp", "67-68"), "samba": ("tcp", "139"),
    "smb": ("tcp", "445"), "ike": ("udp", "500,4500"), "rdp": ("tcp", "3389"),
}


def _node():
    return {"set": {}, "edits": OrderedDict(), "configs": OrderedDict()}


def _split(line):
    try:
        return shlex.split(line, posix=True)
    except ValueError:
        return line.split()


def parse_config(text):
    """Parse FortiOS configuration text into nested nodes."""
    root = _node()
    stack = [root]
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = _split(line)
        if not tokens:
            continue
        cmd = tokens[0]
        if cmd == "config" and len(tokens) > 1:
            node = _node()
            stack[-1]["configs"][" ".join(tokens[1:])] = node
            stack.append(node)
        elif cmd == "edit" and len(tokens) > 1:
            node = _node()
            stack[-1]["edits"][tokens[1]] = node
            stack.append(node)
        elif cmd in ("next", "end"):
            if len(stack) > 1:
                stack.pop()
        elif cmd == "set" and len(tokens) > 1:
            stack[-1]["set"][tokens[1]] = tokens[2:]
    return root


def _find(root, name):
    """Find a config section at the top level or inside the first VDOM."""
    if name in root["configs"]:
        return root["configs"][name]
    global_scope = root["configs"].get("global")
    if global_scope and name in global_scope["configs"]:
        return global_scope["configs"][name]
    vdoms = root["configs"].get("vdom")
    if vdoms:
        for vdom in vdoms["edits"].values():
            if name in vdom["configs"]:
                return vdom["configs"][name]
    return None


def _edits(root, name):
    section = _find(root, name)
    return section["edits"].items() if section else []


def _value(node, key, default=""):
    values = node["set"].get(key)
    return " ".join(values) if values else default


def _list(node, key):
    return list(node["set"].get(key) or [])


def _prefix(mask):
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return None


def _parse_interfaces(root, maps):
    for name, node in _edits(root, "system interface"):
        key = name.lower()
        alias = _value(node, "alias")
        maps["interface_map"][key] = alias or name
        role = _value(node, "role").lower()
        ip = _list(node, "ip")
        address, prefix = (ip[0], _prefix(ip[1])) if len(ip) >= 2 else ("", None)
        if len(ip) == 1 and "/" in ip[0]:
            address, prefix = ip[0], None
        add_interface_address(maps["interface_nets"], key, address, prefix,
                              wan=role == "wan" or key.startswith("wan"))
        ipv6 = node["configs"].get("ipv6")
        if ipv6:
            add_interface_address(maps["interface_nets"], key, _value(ipv6, "ip6-address"))
    for name, node in _edits(root, "system zone"):
        key = name.lower()
        maps["interface_map"][key] = name
        zone = maps["interface_nets"].setdefault(key, {"nets": [], "addrs": [], "wan": False})
        for member in _list(node, "interface"):
            info = maps["interface_nets"].get(member.lower()) or {}
            zone["nets"].extend(info.get("nets", []))
            zone["addrs"].extend(info.get("addrs", []))
            zone["wan"] = zone["wan"] or info.get("wan", False)


def _parse_addresses(root, maps):
    for section in ("firewall address", "firewall address6"):
        for name, node in _edits(root, section):
            kind = _value(node, "type", "ipmask").lower()
            comment = _value(node, "comment")
            if kind == "iprange":
                content, alias_type = f"{_value(node, 'start-ip')}-{_value(node, 'end-ip')}", "network"
            elif kind == "fqdn":
                content, alias_type = _value(node, "fqdn"), "fqdn"
            elif section.endswith("6"):
                content, alias_type = _value(node, "ip6", "::/0"), "network"
            else:
                subnet = _list(node, "subnet") or ["0.0.0.0", "0.0.0.0"]
                if len(subnet) == 2:
                    prefix = _prefix(subnet[1])
                    content = f"{subnet[0]}/{prefix}" if prefix is not None else subnet[0]
                else:
                    content = subnet[0]
                alias_type = "host" if content.endswith("/32") else "network"
            if content in ("0.0.0.0/0", "::/0"):
                content = "any"
            register_alias(maps, name, alias_type, content, comment)
    for section in ("firewall addrgrp", "firewall addrgrp6"):
        for name, node in _edits(root, section):
            register_alias(maps, name, "network", ", ".join(_list(node, "member")),
                           _value(node, "comment"))


def _parse_services(root):
    """{service name lower: [(protocol, ports or None)]}."""
    services = {}
    for name, node in _edits(root, "firewall service custom"):
        protocol = _value(node, "protocol", "TCP/UDP/SCTP").upper()
        items = []
        if protocol in ("ICMP", "ICMP6"):
            items.append(("icmp" if protocol == "ICMP" else "ipv6-icmp", None))
        elif protocol == "IP":
            number = _value(node, "protocol-number", "0")
            items.append(("any" if number in ("0", "") else number, None))
        else:
            for proto in ("tcp", "udp", "sctp"):
                ranges = _list(node, f"{proto}-portrange")
                ports = [r.split(":", 1)[0] for r in ranges]  # dst[:src]
                if ports:
                    items.append((proto, ",".join(ports)))
        services[name.lower()] = items or [("any", None)]
    groups = {name.lower(): [m.lower() for m in _list(node, "member")]
              for name, node in _edits(root, "firewall service group")}
    return services, groups


def _resolve_service(name, services, groups, depth=0):
    key = name.lower()
    if key in services:
        return services[key]
    if key in groups and depth < 10:
        return [item for member in groups[key] for item in _resolve_service(member, services, groups,
                                                                             depth + 1)]
    if key in _PREDEFINED_SERVICES:
        return [_PREDEFINED_SERVICES[key]]
    if key in WELL_KNOWN_PORTS:
        return [("tcp", str(WELL_KNOWN_PORTS[key]))]
    return [("tcp", key)]  # Unknown predefined service: unresolved port name.


def _group_services(items):
    """Merge (proto, ports) items into {proto: ports string}; any protocol wins."""
    if any(proto == "any" for proto, _ in items):
        return {"any": None}
    by_proto = OrderedDict()
    for proto, ports in items:
        current = by_proto.setdefault(proto, [])
        if ports is None:
            by_proto[proto] = None
        elif current is not None:
            current.append(ports)
    merged = OrderedDict()
    for proto, ports in by_proto.items():
        merged[proto] = ",".join(dict.fromkeys(ports)) if ports else None
    if merged.get("tcp") is not None and merged.get("tcp") == merged.get("udp"):
        ports = merged.pop("tcp")
        merged.pop("udp")
        merged = OrderedDict([("tcp/udp", ports), *list(merged.items())])
    return merged


def _addresses(node, key4, key6):
    values = _list(node, key4) + _list(node, key6)
    if not values or any(v.lower() in ("all", "any") for v in values):
        return "any"
    return ",".join(values)


def _parse_policies(root, services, groups):
    entries = []
    for policy_id, node in _edits(root, "firewall policy"):
        srcintf = [i.lower() for i in _list(node, "srcintf")]
        dstintf = [i.lower() for i in _list(node, "dstintf")]
        action = _value(node, "action", "deny").lower()
        action = {"accept": "pass", "deny": "block", "ipsec": "pass"}.get(action, action)
        name = _value(node, "name")
        comment = _value(node, "comments")
        description = " - ".join(part for part in (name, comment) if part)
        if dstintf:
            description = f"{description} (to {', '.join(dstintf)})".strip()
        if _value(node, "nat") == "enable":
            description += " [NAT]"
        has_v4 = bool(_list(node, "srcaddr") or not _list(node, "srcaddr6"))
        has_v6 = bool(_list(node, "srcaddr6"))
        ipprotocol = "inet46" if has_v4 and has_v6 else ("inet6" if has_v6 else "inet")
        service_items = [item for svc in (_list(node, "service") or ["ALL"])
                         for item in _resolve_service(svc, services, groups)]
        uuid = _value(node, "uuid") or f"policy-{policy_id}"
        grouped = _group_services(service_items)
        for proto, ports in grouped.items():
            entries.append({
                "action": action, "type": action,
                "interface": ",".join(i for i in srcintf if i != "any") or None,
                "source": _addresses(node, "srcaddr", "srcaddr6"),
                "destination": _addresses(node, "dstaddr", "dstaddr6"),
                "protocol": None if proto == "any" else proto,
                "destination_port": ports,
                "description": description,
                "enabled": _value(node, "status", "enable") != "disable",
                "uuid": uuid if len(grouped) == 1 else f"{uuid}:{proto}",
                "ipprotocol": ipprotocol,
                "floating": False,
                "out_iface": ",".join(i for i in dstintf if i != "any"),
                "_policy_id": policy_id,
            })
    return entries


def _parse_vips(root, maps):
    nat = []
    for name, node in _edits(root, "firewall vip"):
        mapped = (_list(node, "mappedip") or [""])[0]
        if "-" in mapped:
            low, high = mapped.split("-", 1)
            mapped = low if low == high else mapped
        register_alias(maps, name, "host" if "-" not in mapped else "network", mapped,
                       _value(node, "comment"))
        portforward = _value(node, "portforward") == "enable"
        nat.append({
            "_nat_type": "PORT FORWARD" if portforward else "1:1",
            "interface": _value(node, "extintf") or None,
            "protocol": _value(node, "protocol", "tcp") if portforward else None,
            "source": "any",
            "destination": _value(node, "extip") or "any",
            "destination_port": _value(node, "extport") or None,
            "target": mapped,
            "local_port": _value(node, "mappedport") or None,
            "descr": _value(node, "comment") or name,
            "disabled": False,
            "uuid": _value(node, "uuid") or None,
        })
        if not portforward:
            nat[-1]["target"], nat[-1]["source"] = _value(node, "extip"), mapped
    return nat


def parse(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        root = parse_config(f.read())
    if _find(root, "firewall policy") is None:
        raise ValueError("no 'config firewall policy' section found")
    maps = empty_maps()
    _parse_interfaces(root, maps)
    _parse_addresses(root, maps)
    services, groups = _parse_services(root)
    entries = _parse_policies(root, services, groups)
    nat = _parse_vips(root, maps)
    hostname = None
    global_section = _find(root, "system global")
    if global_section:
        hostname = _value(global_section, "hostname") or None
    return maps, entries, hostname, nat
