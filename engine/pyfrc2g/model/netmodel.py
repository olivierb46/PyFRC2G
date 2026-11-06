"""
Network model: resolve rule fields (aliases, interface networks, IP addresses, port aliases)
into comparable sets. Used by the audit (shadowing / overlap with aliases expanded), the
compliance policy and the inter-VLAN matrix.

Every comparison is conservative: when something cannot be resolved (FQDN alias, URL table,
DHCP interface without known subnet...) "covers" answers False and "intersects" answers None
(unknown) instead of guessing.

Resolutions and compiled rules are cached until the alias maps change (utils.MAPS_VERSION):
the audit, policy and matrix share the same CompiledRule of each row.
"""

import ipaddress
import re

from pyfrc2g import utils

_ANY_TOKENS = frozenset({"", "any", "*", "(any)", "all", "0.0.0.0/0", "::/0"})
_SELF_TOKENS = frozenset({"(self)", "self", "this firewall", "this_firewall", "thisfirewall",
                          "firewall", "firewall_all"})
_ADDR_SUFFIXES = (":ip", "ip", " address", ":address")
_NET_SUFFIXES = (" net", ":net", " subnet", ":network")
_SPLIT = re.compile(r"\s*[,|]\s*|\s+")
_PORT_RANGE = re.compile(r"^(\d{1,5})(?:\s*[:\-]\s*(\d{1,5}))?$")
_MAX_DEPTH = 10

# Service names used by FortiGate / Stormshield / iptables configurations.
WELL_KNOWN_PORTS = {
    "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "dns": 53, "domain": 53, "http": 80,
    "www": 80, "pop3": 110, "ntp": 123, "imap": 143, "snmp": 161, "ldap": 389, "https": 443,
    "smb": 445, "microsoft-ds": 445, "syslog": 514, "smtps": 465, "submission": 587,
    "ldaps": 636, "imaps": 993, "pop3s": 995, "mssql": 1433, "ms-sql-s": 1433, "openvpn": 1194,
    "radius": 1812, "nfs": 2049, "mysql": 3306, "rdp": 3389, "ms-wbt-server": 3389,
    "postgresql": 5432, "postgres": 5432, "vnc": 5900, "redis": 6379, "http-alt": 8080,
    "https-alt": 8443,
}


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

_CACHE = {"version": None, "address": {}, "ports": {}}


def _cache(kind):
    if _CACHE["version"] != utils.MAPS_VERSION:
        _CACHE.update(version=utils.MAPS_VERSION, address={}, ports={})
    return _CACHE[kind]


# ---------------------------------------------------------------------------
# Interfaces
# ---------------------------------------------------------------------------

def interface_ids():
    """Known interface identifiers (lan, opt1, port1...)."""
    return set(utils.API_INTERFACE_MAP) | set(utils.API_INTERFACE_NETS)


def interface_id(name):
    """Return the interface id for an id or a description ('LAN', 'DMZ'), else None."""
    key = str(name or "").strip().lower()
    if not key:
        return None
    if key in interface_ids():
        return key
    for iface, descr in utils.API_INTERFACE_MAP.items():
        if str(descr).strip().lower() == key:
            return iface
    return None


def interface_networks(iface):
    """ip_network objects of an interface ([] if unknown, e.g. DHCP)."""
    info = utils.API_INTERFACE_NETS.get(str(iface).lower()) or {}
    return [_net(n) for n in info.get("nets", []) if _net(n) is not None]


def interface_addresses(iface=None):
    """Firewall addresses (/32, /128 networks) of one interface or of all interfaces."""
    sources = ([utils.API_INTERFACE_NETS.get(str(iface).lower()) or {}] if iface
               else utils.API_INTERFACE_NETS.values())
    out = []
    for info in sources:
        for addr in info.get("addrs", []):
            net = _net(addr)
            if net is not None:
                out.append(net)
    return out


def wan_interfaces():
    """Interface ids flagged as Internet-facing by the parser (FortiGate role wan, DHCP wan...)."""
    return {iface for iface, info in utils.API_INTERFACE_NETS.items() if info.get("wan")}


def local_networks():
    """All networks directly attached to the firewall (non-WAN interfaces)."""
    nets = []
    for iface, info in utils.API_INTERFACE_NETS.items():
        if info.get("wan"):
            continue
        nets.extend(interface_networks(iface))
    return nets


def _net(text):
    try:
        return ipaddress.ip_network(str(text).strip(), strict=False)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Addresses
# ---------------------------------------------------------------------------

class Item:
    """One element of an address set: a symbolic key and its networks when known."""

    __slots__ = ("key", "known", "nets")

    def __init__(self, key, nets=(), known=True):
        self.key = key
        self.nets = tuple(nets)
        self.known = known and bool(self.nets)

    def __repr__(self):
        return f"Item({self.key!r}, {[str(n) for n in self.nets]}, known={self.known})"


class AddrSet:
    """Resolved source/destination field."""

    __slots__ = ("any", "items", "negated", "raw")

    def __init__(self, raw="", any_=False, negated=False, items=()):
        self.raw = raw
        self.any = any_
        self.negated = negated
        self.items = list(items)

    @property
    def known(self):
        return self.any or all(item.known for item in self.items)

    @property
    def nets(self):
        return [net for item in self.items if item.known for net in item.nets]

    def inner(self):
        """The same set without negation."""
        return AddrSet(self.raw.lstrip("!"), self.any, False, self.items)

    def restrict(self, versions):
        """Keep only the networks of the given IP versions ({4}, {6}, {4, 6})."""
        if self.any or set(versions) >= {4, 6}:
            return self
        items = []
        for item in self.items:
            if not item.known:
                items.append(item)
                continue
            nets = [net for net in item.nets if net.version in versions]
            if nets:
                items.append(Item(item.key, nets))
        return AddrSet(self.raw, self.any, self.negated, items)

    def __repr__(self):
        return f"AddrSet({self.raw!r}, any={self.any}, negated={self.negated}, items={self.items})"


def _range_networks(text):
    low, high = (part.strip() for part in text.split("-", 1))
    try:
        first, last = ipaddress.ip_address(low), ipaddress.ip_address(high)
        return list(ipaddress.summarize_address_range(first, last))
    except (ValueError, TypeError):
        return None


def _iface_suffix(token, suffixes):
    for suffix in suffixes:
        if token.endswith(suffix) and len(token) > len(suffix):
            iface = interface_id(token[: -len(suffix)])
            if iface:
                return iface
    return None


def _resolve_token(token, depth, seen):
    """Return a list of Items for one token (alias names are expanded recursively)."""
    low = token.strip().lower()
    if low in _SELF_TOKENS:
        return [Item("self", interface_addresses())]

    net = _net(low) if any(ch.isdigit() for ch in low) else None
    if net is not None:
        return [Item(f"ip:{net}", [net])]
    if "-" in low and low[0].isdigit():
        nets = _range_networks(low)
        if nets:
            return [Item(f"range:{low}", nets)]

    iface = _iface_suffix(low, _ADDR_SUFFIXES)
    if iface:
        return [Item(f"addr:{iface}", interface_addresses(iface))]
    iface = _iface_suffix(low, _NET_SUFFIXES) or interface_id(low)
    if iface and low not in utils.API_ALIAS_DETAILS:
        return [Item(f"net:{iface}", interface_networks(iface))]

    alias = utils.API_ALIAS_DETAILS.get(low)
    if alias and depth < _MAX_DEPTH and low not in seen:
        alias_type = str(alias.get("type") or "").lower()
        content = str(alias.get("content") or "")
        if alias_type in ("url", "urltable", "url_ports", "urltable_ports", "geoip", "dynipv6host",
                          "external", "asn", "mac", "authgroup", "internal"):
            return [Item(f"alias:{low}", known=False)]
        items = []
        for part in _SPLIT.split(content):
            if part:
                items.extend(_resolve_token(part, depth + 1, seen | {low}))
        if not items:
            return [Item(f"alias:{low}", known=False)]
        if any(i.key == "any" for i in items):
            return [Item("any")]
        return items
    if low in _ANY_TOKENS:
        return [Item("any")]
    return [Item(f"name:{low}", known=False)]  # FQDN, unknown alias, ipset...


def resolve_address(raw):
    """Resolve a raw source/destination value ('lan', '!opt1', 'srv_web', '10.0.0.0/8')."""
    text = str(raw if raw is not None else "").strip()
    cache = _cache("address")
    if text not in cache:
        cache[text] = _resolve_address(text)
    return cache[text]


def _resolve_address(text):
    negated = text.startswith("!")
    body = text[1:].strip() if negated else text
    if body.lower() in _ANY_TOKENS:
        return AddrSet(text, any_=True, negated=negated)
    tokens = [t for t in _SPLIT.split(body) if t]
    # Keep multi-word interface forms ("LAN net", "LAN address") together.
    if len(tokens) == 2 and tokens[1].lower() in ("net", "address", "subnet"):
        tokens = [body]
    items = []
    for token in tokens:
        items.extend(_resolve_token(token, 0, frozenset()))
    if any(item.key == "any" for item in items):
        return AddrSet(text, any_=True, negated=negated)
    return AddrSet(text, negated=negated, items=items)


def _nets_cover(container, nets):
    """True if every network of nets is inside the union of container networks."""
    for net in nets:
        same = [c for c in container if c.version == net.version]
        if any(net.subnet_of(c) for c in same):
            continue
        # Union coverage: remove covering parts one by one.
        remaining = [net]
        for c in same:
            nxt = []
            for part in remaining:
                if part.subnet_of(c):
                    continue
                if c.subnet_of(part):
                    nxt.extend(part.address_exclude(c))
                else:
                    nxt.append(part)
            remaining = nxt
            if not remaining:
                break
        if remaining:
            return False
    return True


def _nets_overlap(a, b):
    return any(x.version == y.version and x.overlaps(y) for x in a for y in b)


def _same_raw(a, b):
    return a.raw.strip().lower() == b.raw.strip().lower() and a.raw.strip() != ""


def addr_covers(a, b):
    """True if every address matched by b is matched by a (False when unknown)."""
    if _same_raw(a, b):
        return True
    if a.any and not a.negated:
        return True
    if a.negated and b.negated:
        return addr_covers(b.inner(), a.inner())
    if a.negated:
        return addr_intersects(a.inner(), b) is False
    if b.any or b.negated:
        return False
    a_keys = {item.key for item in a.items}
    a_nets = a.nets
    for item in b.items:
        if item.key in a_keys:
            continue
        if not item.known or not _nets_cover(a_nets, item.nets):
            return False
    return True


def addr_intersects(a, b):
    """True / False / None (unknown) whether a and b share at least one address."""
    if (a.any and not a.negated) or (b.any and not b.negated):
        return True
    if a.negated and b.negated:
        return True
    if a.negated or b.negated:
        neg, pos = (a, b) if a.negated else (b, a)
        if addr_covers(neg.inner(), pos):
            return False
        return True if pos.known and neg.inner().known else None
    if {i.key for i in a.items} & {i.key for i in b.items}:
        return True
    if _nets_overlap(a.nets, b.nets):
        return True
    return False if a.known and b.known else None


# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------

class PortSet:
    """Resolved port field: any, list of (low, high) ranges, unresolved names."""

    __slots__ = ("any", "ranges", "raw", "unresolved")

    def __init__(self, raw="", any_=False, ranges=(), unresolved=()):
        self.raw = raw
        self.any = any_
        self.ranges = sorted(ranges)
        self.unresolved = list(unresolved)

    @property
    def known(self):
        return self.any or not self.unresolved

    def ports(self, limit=1000):
        """Expanded list of ports (None for any; truncated to limit)."""
        if self.any:
            return None
        out = []
        for low, high in self.ranges:
            out.extend(range(low, min(high, low + limit) + 1))
        return out

    def __repr__(self):
        return f"PortSet({self.raw!r}, any={self.any}, ranges={self.ranges}, unresolved={self.unresolved})"


def _resolve_port_token(token, depth, seen):
    low = token.strip().lower()
    match = _PORT_RANGE.match(low)
    if match:
        a, b = int(match.group(1)), int(match.group(2) or match.group(1))
        return [(min(a, b), max(a, b))], []
    if low in WELL_KNOWN_PORTS:
        port = WELL_KNOWN_PORTS[low]
        return [(port, port)], []
    alias = utils.API_ALIAS_DETAILS.get(low)
    if alias and depth < _MAX_DEPTH and low not in seen:
        ranges, unresolved = [], []
        content = str(alias.get("content") or "")
        if str(alias.get("type") or "").lower() in ("url_ports", "urltable_ports") or not content:
            return [], [low]
        for part in _SPLIT.split(content):
            if part:
                r, u = _resolve_port_token(part, depth + 1, seen | {low})
                ranges.extend(r)
                unresolved.extend(u)
        return ranges, unresolved
    if low in _ANY_TOKENS:
        return [(0, 65535)], []
    return [], [low]


def resolve_ports(raw):
    """Resolve a raw port value ('443', '80,443', '1000:2000', 'web_ports', None = any)."""
    text = str(raw if raw is not None else "").strip()
    cache = _cache("ports")
    if text not in cache:
        cache[text] = _resolve_ports(text)
    return cache[text]


def _resolve_ports(text):
    if text.lower() in _ANY_TOKENS:
        return PortSet(text, any_=True)
    ranges, unresolved = [], []
    for token in _SPLIT.split(text):
        if token:
            r, u = _resolve_port_token(token, 0, frozenset())
            ranges.extend(r)
            unresolved.extend(u)
    merged = _merge_ranges(ranges)
    if merged == [(0, 65535)] and not unresolved:
        return PortSet(text, any_=True)
    return PortSet(text, ranges=merged, unresolved=unresolved)


def _merge_ranges(ranges):
    merged = []
    for low, high in sorted(ranges):
        if merged and low <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], high))
        else:
            merged.append((low, high))
    return merged


def ports_covers(a, b):
    if a.raw.strip().lower() == b.raw.strip().lower():
        return True
    if a.any:
        return True
    if b.any or b.unresolved or not b.ranges:
        return False
    return all(any(alo <= lo and hi <= ahi for alo, ahi in a.ranges) for lo, hi in b.ranges)


def ports_intersects(a, b):
    if a.any or b.any:
        return True
    if any(lo <= bhi and blo <= hi for lo, hi in a.ranges for blo, bhi in b.ranges):
        return True
    if set(a.unresolved) & set(b.unresolved):
        return True
    return False if a.known and b.known else None


# ---------------------------------------------------------------------------
# Protocols and IP versions
# ---------------------------------------------------------------------------

_PROTO_ALIASES = {"icmpv6": "ipv6-icmp", "icmp6": "ipv6-icmp", "tcp-udp": "tcp/udp",
                  "tcpudp": "tcp/udp", "ip": "any", "all": "any", "*": "any", "": "any"}


def resolve_protocol(raw):
    """None for any protocol, else a frozenset of protocol names ('tcp/udp' -> {tcp, udp})."""
    text = str(raw or "").strip().lower()
    parts = text.split()
    if parts and parts[0].startswith(("inet", "ipv4", "ipv6")) and len(parts) > 1:
        text = parts[-1]
    elif parts and parts[0].startswith(("inet", "ipv4", "ipv6")):
        text = "any"
    text = _PROTO_ALIASES.get(text, text)
    if text == "any":
        return None
    protos = set()
    for part in re.split(r"[/,\s]+", text):
        if part:
            protos.add(_PROTO_ALIASES.get(part, part))
    return frozenset(protos) if protos and "any" not in protos else None


def protocol_covers(a, b):
    return a is None or (b is not None and b <= a)


def protocol_intersects(a, b):
    return a is None or b is None or bool(a & b)


def ip_versions(raw, default="inet"):
    """{4}, {6} or {4, 6} from an ipprotocol value (inet, inet6, inet46, IPv4+IPv6...)."""
    text = str(raw or default).strip().lower().replace(" ", "")
    if text in ("inet46", "ipv4+ipv6", "ipv4+6", "any", "inet4+6", "both"):
        return {4, 6}
    if text in ("inet6", "ipv6", "6"):
        return {6}
    return {4}


def ip_version_label(versions):
    versions = set(versions)
    if versions == {4, 6}:
        return "IPv4+IPv6"
    return "IPv6" if versions == {6} else "IPv4"


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

class CompiledRule:
    """Resolved view of a normalized rule row (see model.rules private keys)."""

    __slots__ = (
        "action",
        "automatic",
        "direction",
        "dst",
        "enabled",
        "established_only",
        "floating",
        "group",
        "ifaces",
        "in_iface",
        "ipver",
        "order",
        "out_ifaces",
        "ports",
        "protos",
        "quick",
        "row",
        "seq",
        "src",
    )

    def __init__(self, row):
        self.row = row
        self.src = resolve_address(row.get("_SRC", row.get("SOURCE")))
        self.dst = resolve_address(row.get("_DST", row.get("DESTINATION")))
        self.ports = resolve_ports(row.get("_PORT", row.get("PORT")))
        self.protos = resolve_protocol(row.get("_PROTO", row.get("PROTOCOL")))
        self.ipver = set(row.get("_IPVER") or ip_versions_from_label(row.get("IP VERSION")))
        # An IPv4 rule on "LAN net" only concerns the IPv4 subnet of the LAN.
        self.src = self.src.restrict(self.ipver)
        self.dst = self.dst.restrict(self.ipver)
        self.action = (row.get("ACTION") or "").strip().lower()
        self.enabled = (row.get("DISABLED") or "").strip() not in ("True", "1")
        self.floating = (row.get("FLOATING") or "").strip() in ("True", "1")
        self.ifaces = set(row.get("_IFACES") or ())
        self.in_iface = (row.get("_IN_IFACE") or "").lower() or None
        self.out_ifaces = {i.strip().lower() for i in str(row.get("_OUT_IFACE") or "").split(",")
                           if i.strip()}
        # iptables/nftables "ct state established,related" rules never match a new flow.
        self.established_only = bool(row.get("_ESTABLISHED"))
        # Generated by the firewall (OPNsense automatic rules): no finding of their own.
        self.automatic = (row.get("AUTOMATIC") or "").strip() in ("True", "1")
        # pf semantics: non-quick rules only decide when no later rule matches; "out" rules
        # filter traffic leaving the firewall.
        self.quick = row.get("_QUICK", True) is not False
        self.direction = (row.get("_DIRECTION") or row.get("DIRECTION") or "in").strip().lower() or "in"
        try:
            self.order = int(row.get("RULE ORDER") or 0)
        except ValueError:
            self.order = 0
        self.seq = row.get("_SEQ", self.order)
        self.group = row.get("GATEWAY", "")

    @property
    def label(self):
        return f"{self.group} #{self.row.get('RULE ORDER', '')}"


def ip_versions_from_label(label):
    text = str(label or "").strip().lower()
    if not text:
        return {4, 6}
    return {4, 6} if "+" in text else ({6} if "6" in text else {4})


def compiled(row):
    """CompiledRule of a row, cached in row["_RULE"] until the alias maps change."""
    cached = row.get("_RULE")
    if cached is not None and cached[0] == utils.MAPS_VERSION:
        return cached[1]
    rule = CompiledRule(row)
    row["_RULE"] = (utils.MAPS_VERSION, rule)
    return rule


def compile_rules(rows):
    return [compiled(row) for row in rows]


def rule_covers(a, b):
    """True if rule a matches every packet matched by rule b."""
    return (b.ipver <= a.ipver
            and protocol_covers(a.protos, b.protos)
            and addr_covers(a.src, b.src)
            and addr_covers(a.dst, b.dst)
            and ports_covers(a.ports, b.ports))


def rule_intersects(a, b):
    """True / False / None whether two rules can match a common packet."""
    if not (a.ipver & b.ipver) or not protocol_intersects(a.protos, b.protos):
        return False
    results = [addr_intersects(a.src, b.src), addr_intersects(a.dst, b.dst),
               ports_intersects(a.ports, b.ports)]
    if False in results:
        return False
    return None if None in results else True
