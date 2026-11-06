"""
iptables-save / ip6tables-save output (use "iptables-save -c" to include hit counters).

Each chain of the filter table is a rule group ("INPUT", "FORWARD", "OUTPUT", user chains),
evaluated top-down; the chain policy is added as a last rule. "-i" / "-o" are kept as
input / output interface conditions, "-m set --match-set" references are unresolved objects,
jumps to user chains are shown in the comment, and "ESTABLISHED,RELATED"-only rules are
flagged (they never match a new connection). The nat table gives port forwards (DNAT) and
outbound NAT (SNAT / MASQUERADE).
"""

import hashlib
import re
import shlex

from pyfrc2g.utils import empty_maps

_COUNTERS = re.compile(r"^\[(\d+):(\d+)\]\s*")
_ACTIONS = {"ACCEPT": "pass", "DROP": "block", "REJECT": "reject", "RETURN": "return",
            "LOG": "log", "NFLOG": "log", "ULOG": "log", "MARK": "log", "CONNMARK": "log"}
_BUILTIN = ("INPUT", "FORWARD", "OUTPUT", "PREROUTING", "POSTROUTING")


def _rule_id(table, chain, spec):
    return "ipt-" + hashlib.sha1(f"{table}|{chain}|{spec}".encode(), usedforsecurity=False).hexdigest()[:12]


_OPTION_KEYS = {
    "-s": "source", "--source": "source", "--src-range": "source",
    "-d": "destination", "--destination": "destination", "--dst-range": "destination",
    "-p": "protocol", "--protocol": "protocol",
    "-i": "in_iface", "--in-interface": "in_iface", "-o": "out_iface", "--out-interface": "out_iface",
    "--dport": "dport", "--destination-port": "dport", "--dports": "dport", "--destination-ports": "dport",
    "--sport": "sport", "--source-port": "sport", "--sports": "sport", "--source-ports": "sport",
    "-A": "chain", "--append": "chain", "-j": "target", "--jump": "target", "-g": "target",
    "--goto": "target", "--comment": "comment", "--ctstate": "state", "--state": "state",
    "--to-destination": "to", "--to-source": "to", "--to-ports": "to", "--to": "to",
}
_NEGATABLE = {"source", "destination", "protocol", "in_iface", "out_iface", "dport", "sport"}


def _parse_spec(tokens):
    """Parse the options of one -A line into a dict ("!" negations kept in spec["negate"])."""
    spec = {"negate": set()}
    i, negate = 0, False
    while i < len(tokens):
        tok = tokens[i]
        if tok == "!":
            negate = True
            i += 1
            continue
        if tok == "--match-set" and i + 2 < len(tokens):
            key = "source" if tokens[i + 2].startswith("src") else "destination"
            spec[key] = tokens[i + 1]
            if negate:
                spec["negate"].add(key)
            negate = False
            i += 3
            continue
        has_arg = tok.startswith("-") and i + 1 < len(tokens) and tokens[i + 1] != "!" \
            and not tokens[i + 1].startswith("-")
        key = _OPTION_KEYS.get(tok)
        if key and has_arg:
            spec[key] = tokens[i + 1]
            if key == "state":
                spec[key] = tokens[i + 1].upper()
            if negate and key in _NEGATABLE:
                spec["negate"].add(key)
        negate = False
        i += 2 if has_arg else 1
    return spec


def _addr(spec, key):
    value = spec.get(key)
    if not value:
        return "any"
    return f"!{value}" if key in spec["negate"] else value


def _ports(value):
    return value.replace(":", "-") if value else None


def parse(path):
    maps = empty_maps()
    entries, nat = [], []
    policies = []
    table = None
    ipv6 = False
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            table = line[1:].strip()
            continue
        if line == "COMMIT":
            continue
        if line.startswith(":"):
            parts = line[1:].split()
            if table == "filter" and len(parts) >= 2 and parts[1] != "-":
                policies.append((parts[0], parts[1], _COUNTERS.match(parts[2] if len(parts) > 2 else "")))
            continue
        hits = None
        match = _COUNTERS.match(line)
        if match:
            hits = {"packets": int(match.group(1)), "bytes": int(match.group(2))}
            line = line[match.end():]
        try:
            tokens = shlex.split(line)
        except ValueError:
            tokens = line.split()
        spec = _parse_spec(tokens)
        chain = spec.get("chain")
        if not chain:
            continue
        for key in ("source", "destination"):
            if ":" in (spec.get(key) or ""):
                ipv6 = True
        target = spec.get("target", "")
        body = " ".join(tokens[2:])

        if table == "nat":
            if target == "DNAT":
                to = spec.get("to", "")
                address, _, port = to.rpartition(":") if to.count(":") == 1 else (to, "", "")
                nat.append({"_nat_type": "PORT FORWARD", "interface": spec.get("in_iface"),
                            "protocol": spec.get("protocol"), "source": _addr(spec, "source"),
                            "destination": _addr(spec, "destination"),
                            "destination_port": _ports(spec.get("dport")), "target": address or to,
                            "local_port": port or None, "descr": spec.get("comment", ""),
                            "uuid": _rule_id(table, chain, body)})
            elif target in ("SNAT", "MASQUERADE"):
                nat.append({"_nat_type": "OUTBOUND", "interface": spec.get("out_iface"),
                            "protocol": spec.get("protocol"), "source": _addr(spec, "source"),
                            "destination": _addr(spec, "destination"),
                            "target": spec.get("to") if target == "SNAT" else None,
                            "descr": spec.get("comment", ""), "uuid": _rule_id(table, chain, body)})
            continue
        if table != "filter":
            continue

        action = _ACTIONS.get(target, "jump" if target else "log")
        state = spec.get("state", "")
        established_only = bool(state) and "NEW" not in state and "INVALID" not in state \
            and "UNTRACKED" not in state
        comment = spec.get("comment", "")
        if action == "jump":
            comment = f"{comment} -> {target}".strip()
        if state:
            comment = f"{comment} [state {state.lower()}]".strip()
        if spec.get("in_iface"):
            comment = f"{comment} [in {spec['in_iface']}]".strip()
        if spec.get("out_iface"):
            comment = f"{comment} [out {spec['out_iface']}]".strip()
        entries.append({
            "action": action, "type": action, "interface": chain,
            "source": _addr(spec, "source"), "destination": _addr(spec, "destination"),
            "protocol": spec.get("protocol"), "destination_port": _ports(spec.get("dport")),
            "description": comment, "enabled": True, "uuid": _rule_id(table, chain, body),
            "floating": False, "in_iface": spec.get("in_iface"), "out_iface": spec.get("out_iface"),
            "established_only": established_only,
            "_hits": hits,
        })

    for chain, policy, counters in policies:
        if chain not in _BUILTIN:
            continue
        hits = {"packets": int(counters.group(1)), "bytes": int(counters.group(2))} if counters else None
        action = _ACTIONS.get(policy, "block")
        entries.append({"action": action, "type": action, "interface": chain, "source": "any",
                        "destination": "any", "protocol": None, "destination_port": None,
                        "description": f"Chain {chain} default policy ({policy})", "enabled": True,
                        "uuid": f"policy-{chain}", "floating": False, "_hits": hits})

    for entry in entries:
        entry["ipprotocol"] = "inet6" if ipv6 else "inet"
        maps["interface_map"].setdefault(entry["interface"].lower(), entry["interface"])
    return maps, entries, None, nat
