"""
nftables ruleset in JSON ("nft -j list ruleset"; counters are read when rules use "counter").

Filter chains (and regular chains used as jump targets) become rule groups named after the
chain, evaluated top-down with the chain policy added as a last rule. Named sets become
objects; "ct state established,related"-only rules are flagged; dnat / snat / masquerade
statements in nat chains give NAT rules.
"""

import hashlib
import json

from pyfrc2g.inputs import register_alias
from pyfrc2g.utils import empty_maps

_VERDICTS = {"accept": "pass", "drop": "block", "reject": "reject", "return": "return"}


def _value(right):
    """Convert an nft JSON value (string, number, prefix, range, set) into text."""
    if isinstance(right, (str, int)):
        return str(right)
    if isinstance(right, dict):
        if "prefix" in right:
            return f"{right['prefix'].get('addr')}/{right['prefix'].get('len')}"
        if "range" in right:
            low, high = right["range"]
            return f"{_value(low)}-{_value(high)}"
        if "set" in right:
            return ",".join(_value(v) for v in right["set"])
    if isinstance(right, list):
        return ",".join(_value(v) for v in right)
    return str(right)


def _set_name(value):
    return value[1:] if isinstance(value, str) and value.startswith("@") else None


def _rule_id(rule, body):
    return "nft-" + hashlib.sha1(f"{rule.get('table')}|{rule.get('chain')}|{body}".encode(),
                                 usedforsecurity=False).hexdigest()[:12]


def _parse_expr(exprs):
    spec = {"negate": set(), "hits": None}
    for expr in exprs or []:
        if not isinstance(expr, dict):
            continue
        if "match" in expr:
            match = expr["match"]
            left, right, op = match.get("left") or {}, match.get("right"), match.get("op", "==")
            key = None
            if "payload" in left:
                payload = left["payload"]
                proto, field = payload.get("protocol"), payload.get("field")
                if field in ("saddr", "daddr"):
                    key = "source" if field == "saddr" else "destination"
                    spec["family"] = proto
                elif field == "dport":
                    key = "dport"
                    if proto in ("tcp", "udp"):
                        spec.setdefault("protocol", proto)
                    elif proto == "th":
                        spec.setdefault("protocol", "tcp/udp")
                elif field in ("protocol", "nexthdr"):
                    key = "protocol"
            elif "meta" in left:
                meta = left["meta"].get("key")
                key = {"l4proto": "protocol", "iifname": "in_iface", "iif": "in_iface",
                       "oifname": "out_iface", "oif": "out_iface", "nfproto": "nfproto"}.get(meta)
            elif "ct" in left and left["ct"].get("key") == "state":
                states = right if isinstance(right, list) else (right.get("set") if isinstance(right, dict)
                                                                else [right])
                spec["state"] = {str(s).lower() for s in states}
                continue
            if key:
                set_name = _set_name(right)
                spec[key] = set_name or _value(right)
                if op == "!=":
                    spec["negate"].add(key)
        elif "counter" in expr and isinstance(expr["counter"], dict):
            spec["hits"] = {"packets": int(expr["counter"].get("packets", 0)),
                            "bytes": int(expr["counter"].get("bytes", 0))}
        elif "jump" in expr or "goto" in expr:
            spec["verdict"] = "jump"
            spec["jump"] = (expr.get("jump") or expr.get("goto")).get("target")
        elif "dnat" in expr or "snat" in expr or "masquerade" in expr or "redirect" in expr:
            kind = next(k for k in ("dnat", "snat", "masquerade", "redirect") if k in expr)
            spec["nat"] = (kind, expr[kind] or {})
        else:
            for verdict in _VERDICTS:
                if verdict in expr:
                    spec["verdict"] = verdict
    return spec


def _addr(spec, key):
    value = spec.get(key)
    if not value:
        return "any"
    return f"!{value}" if key in spec["negate"] else value


def parse(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    items = data.get("nftables", []) if isinstance(data, dict) else []
    maps = empty_maps()
    chains, rules, nat = {}, [], []
    for item in items:
        if "chain" in item:
            chain = item["chain"]
            chains[(chain.get("family"), chain.get("table"), chain.get("name"))] = chain
        elif "set" in item:
            nset = item["set"]
            elems = ",".join(_value(e.get("elem", {}).get("val") if isinstance(e, dict) and "elem" in e else e)
                             for e in nset.get("elem", []))
            set_type = str(nset.get("type"))
            register_alias(maps, nset.get("name", ""), "port" if "service" in set_type else "network", elems)
        elif "rule" in item:
            rules.append(item["rule"])

    entries = []
    for rule in rules:
        key = (rule.get("family"), rule.get("table"), rule.get("chain"))
        chain = chains.get(key, {})
        family = rule.get("family")
        if family not in ("ip", "ip6", "inet"):
            continue
        spec = _parse_expr(rule.get("expr"))
        body = json.dumps(rule.get("expr"), sort_keys=True)
        name = rule.get("chain", "")
        if chain.get("type") == "nat" or "nat" in spec:
            if "nat" not in spec:
                continue
            kind, args = spec["nat"]
            if kind in ("dnat", "redirect"):
                nat.append({"_nat_type": "PORT FORWARD", "interface": spec.get("in_iface"),
                            "protocol": spec.get("protocol"), "source": _addr(spec, "source"),
                            "destination": _addr(spec, "destination"),
                            "destination_port": spec.get("dport"),
                            "target": _value(args.get("addr")) if args.get("addr") else "firewall",
                            "local_port": _value(args.get("port")) if args.get("port") else None,
                            "descr": rule.get("comment", ""), "uuid": _rule_id(rule, body)})
            else:
                nat.append({"_nat_type": "OUTBOUND", "interface": spec.get("out_iface"),
                            "protocol": spec.get("protocol"), "source": _addr(spec, "source"),
                            "destination": _addr(spec, "destination"),
                            "target": _value(args.get("addr")) if args.get("addr") else None,
                            "descr": rule.get("comment", ""), "uuid": _rule_id(rule, body)})
            continue
        verdict = spec.get("verdict")
        action = _VERDICTS.get(verdict, verdict or "log")
        states = spec.get("state") or set()
        established_only = bool(states) and "new" not in states and "invalid" not in states
        comment = rule.get("comment", "")
        if action == "jump":
            comment = f"{comment} -> {spec.get('jump')}".strip()
        if states:
            comment = f"{comment} [ct state {','.join(sorted(states))}]".strip()
        for iface_key, label in (("in_iface", "in"), ("out_iface", "out")):
            if spec.get(iface_key):
                comment = f"{comment} [{label} {spec[iface_key]}]".strip()
        ipprotocol = {"ip": "inet", "ip6": "inet6"}.get(spec.get("family") or family, "inet46")
        if spec.get("nfproto") in ("ipv4", "ipv6"):
            ipprotocol = "inet" if spec["nfproto"] == "ipv4" else "inet6"
        entries.append({
            "action": action, "type": action, "interface": name,
            "source": _addr(spec, "source"), "destination": _addr(spec, "destination"),
            "protocol": spec.get("protocol"), "destination_port": spec.get("dport"),
            "description": comment, "enabled": True, "uuid": _rule_id(rule, body),
            "floating": False, "in_iface": spec.get("in_iface"), "out_iface": spec.get("out_iface"),
            "established_only": established_only,
            "ipprotocol": ipprotocol, "_hits": spec["hits"],
        })

    for (family, table, name), chain in chains.items():
        if chain.get("type") == "filter" and chain.get("hook") and chain.get("policy"):
            action = _VERDICTS.get(chain["policy"], "block")
            entries.append({"action": action, "type": action, "interface": name, "source": "any",
                            "destination": "any", "protocol": None, "destination_port": None,
                            "description": f"Chain {table}/{name} default policy ({chain['policy']})",
                            "enabled": True, "uuid": f"policy-{family}-{table}-{name}",
                            "floating": False,
                            "ipprotocol": {"ip": "inet", "ip6": "inet6"}.get(family, "inet46")})
    for entry in entries:
        maps["interface_map"].setdefault(entry["interface"].lower(), entry["interface"])
    return maps, entries, None, nat
