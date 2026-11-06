"""
Stormshield SNS filter policy (EXPERIMENTAL, best effort).

Input: an extracted configuration directory (containing Filter/ and object, or ConfigFiles/),
or one filter slot file (ConfigFiles/Filter/NN). The active slot is read from Filter/slotinfo
when present, otherwise the first slot is used. Objects ([Host], [Network], [Range], [Service],
[Group], [ServiceGroup] sections of the "object" file) are loaded when found.

Filter lines look like:
    pass ipproto tcp from network_internals on in1 to srv_web port https rulename "web" # comment
    off block from any to any # disabled rule
The whole slot is one ordered policy (first match), named "Filter".
"""

import contextlib
import hashlib
import os
import re
import shlex

from pyfrc2g.inputs import register_alias
from pyfrc2g.utils import empty_maps

_ACTIONS = {"pass": "pass", "block": "block", "drop": "block", "reset": "reject", "deny": "block"}
_SECTION = re.compile(r"^\[(.+)\]$")
_KEYWORDS = {"from", "to", "port", "ipproto", "proto", "on", "rulename", "type", "srcport",
             "inspection", "noconnlog", "log", "all", "firewall", "ips", "ids", "state", "loglevel"}


def _find_files(path):
    """Return (filter file, object file or None)."""
    if os.path.isfile(path):
        base = os.path.dirname(os.path.dirname(os.path.abspath(path)))
        obj = os.path.join(base, "object")
        return path, obj if os.path.isfile(obj) else None
    root = path
    if os.path.isdir(os.path.join(path, "ConfigFiles")):
        root = os.path.join(path, "ConfigFiles")
    filter_dir = os.path.join(root, "Filter")
    if not os.path.isdir(filter_dir):
        raise ValueError(f"no Filter directory in {path}")
    slots = sorted(f for f in os.listdir(filter_dir) if f.isdigit())
    active = None
    slotinfo = os.path.join(filter_dir, "slotinfo")
    if os.path.isfile(slotinfo):
        with open(slotinfo, encoding="utf-8", errors="replace") as f:
            match = re.search(r"^\s*Active\s*=\s*(\d+)", f.read(), re.MULTILINE | re.IGNORECASE)
        if match:
            active = next((s for s in slots if int(s) == int(match.group(1))), None)
    chosen = active or (slots[0] if slots else None)
    if chosen is None:
        raise ValueError(f"no filter slot in {filter_dir}")
    obj = os.path.join(root, "object")
    return os.path.join(filter_dir, chosen), obj if os.path.isfile(obj) else None


def _parse_objects(path, maps):
    section = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith(("#", ";")):
                continue
            match = _SECTION.match(line)
            if match:
                section = match.group(1).lower()
                continue
            if "=" not in line:
                continue
            name, value = line.split("=", 1)
            first = value.split(",", 1)[0].strip()
            if section in ("host", "network", "range"):
                if section == "network" and "/" in first:
                    address, mask = first.split("/", 1)
                    if "." in mask:
                        import ipaddress
                        with contextlib.suppress(ValueError):
                            first = f"{address}/{ipaddress.IPv4Network(f'0.0.0.0/{mask}').prefixlen}"
                register_alias(maps, name.strip(), "host" if section == "host" else "network",
                               first)
            elif section == "service":
                port = first.split("/", 1)[0]
                register_alias(maps, name.strip(), "port", port)
            elif section in ("group", "servicegroup"):
                members = ", ".join(m.strip() for m in value.split(",") if m.strip())
                register_alias(maps, name.strip(), "port" if section == "servicegroup" else "network",
                               members)


def _parse_line(line):
    comment = ""
    if "#" in line:
        line, comment = line.split("#", 1)
        comment = comment.strip()
    try:
        tokens = shlex.split(line)
    except ValueError:
        tokens = line.split()
    if not tokens:
        return None
    enabled = True
    if tokens[0].lower() == "off":
        enabled = False
        tokens = tokens[1:]
    if not tokens or tokens[0].lower() not in _ACTIONS:
        return None
    rule = {"action": _ACTIONS[tokens[0].lower()], "enabled": enabled, "comment": comment}
    i = 1
    while i < len(tokens):
        tok = tokens[i].lower()
        nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
        if tok in ("from", "to", "port", "ipproto", "on", "rulename"):
            rule[tok] = nxt
            i += 2
            continue
        i += 1
    return rule


def parse(path):
    filter_file, object_file = _find_files(path)
    maps = empty_maps()
    if object_file:
        _parse_objects(object_file, maps)
    entries = []
    seen = {}
    in_filter = False
    with open(filter_file, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    has_sections = any(_SECTION.match(line.strip()) for line in lines)
    for raw in lines:
        line = raw.strip()
        match = _SECTION.match(line)
        if match:
            in_filter = match.group(1).lower() == "filter"
            continue
        if has_sections and not in_filter:
            continue
        if not line or line.startswith(("separator", ";")):
            continue
        rule = _parse_line(line)
        if rule is None:
            continue
        seen[line] = seen.get(line, -1) + 1  # Identical lines get distinct ids.
        ports = rule.get("port")
        description = " - ".join(p for p in (rule.get("rulename"), rule.get("comment")) if p)
        entries.append({
            "action": rule["action"], "type": rule["action"], "interface": "Filter",
            "source": (rule.get("from") or "any").replace("|", ","),
            "destination": (rule.get("to") or "any").replace("|", ","),
            "protocol": rule.get("ipproto"),
            "destination_port": ports.replace("|", ",") if ports else None,
            "description": description, "enabled": rule["enabled"],
            "uuid": "sns-" + hashlib.sha1(f"{line}|{seen[line]}".encode(), usedforsecurity=False).hexdigest()[:12],
            "floating": False, "in_iface": rule.get("on"), "ipprotocol": "inet46",
        })
    maps["interface_map"]["filter"] = "Filter"
    return maps, entries, None, []
