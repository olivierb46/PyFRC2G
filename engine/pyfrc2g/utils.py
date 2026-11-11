"""
Utility functions for PyFRC2G.
"""

import re

# Global API alias maps (populated by APIClient).
API_INTERFACE_MAP = {}
API_NET_MAP = {}
API_ADDRESS_MAP = {}
API_PORT_MAP = {}
API_ALIAS_DETAILS = {}  # Full alias details: {name: {type, content, description}}.
# Interface addressing: {iface_id: {"nets": ["192.168.1.0/24"], "addrs": ["192.168.1.1"], "wan": bool}}.
API_INTERFACE_NETS = {}
# Incremented by update_api_maps(): invalidates the caches of netmodel.
MAPS_VERSION = 0


def extract_base_url(api_url):
    """Return base URL from API endpoint URL."""
    if "/api/" in api_url:
        return api_url.rsplit("/api/", 1)[0]
    return api_url.rsplit("/api", 1)[0]


def normalize_ports(port_field, any_value="Any"):
    """Return normalized port field value."""
    if not port_field:
        return any_value
    # "80 443" / "80, 443" -> "80,443" (spaces separate ports in pfSense aliases).
    return re.sub(r"\s*,\s*|\s+", ",", str(port_field).strip()) or any_value


def safe_filename(name):
    """Return a filesystem-safe version of the string (no / , space < > in filename)."""
    return (name or "").replace('/', '_').replace(' ', '_').replace(',', '_').replace('<', '').replace('>', '')


def normalize_interface(entry_interface):
    """Return interface as string (API may return list e.g. pfSense). Handles None, list, str."""
    if entry_interface is None:
        return ""
    if isinstance(entry_interface, list):
        return ",".join(str(x).strip() for x in entry_interface) if entry_interface else ""
    return str(entry_interface).strip()


# Floating: API/backup use same semantics (tag "yes"/"1"/"true" or flag True/1).
FLOATING_FLAG_VALUES = frozenset({True, "1", "yes", "true"})  # 1 == True


def is_interface_floating(raw_interface):
    """
    True if interface value means floating: empty, "floating", "0", or multiple (e.g. "lan,wan").
    Used by API client and XML parser for consistent tagging.
    """
    if raw_interface is None:
        return True
    if isinstance(raw_interface, (int, float)) and raw_interface == 0:
        return True
    iface = normalize_interface(raw_interface).lower()
    if not iface or iface in ("floating", "0"):
        return True
    return "," in iface


def is_floating_flag(value):
    """True if API/XML floating flag is set (True, 1, '1', 'yes', 'true')."""
    if value is None:
        return False
    return (str(value).strip().lower() if isinstance(value, str) else value) in FLOATING_FLAG_VALUES


def extract_host_from_url(url):
    """Return host (IP or domain) from URL."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path.split('/')[0]
        # Remove port if present.
        if ':' in host:
            host = host.split(':')[0]
        # Remove placeholder values.
        if host in ["<OPNS_ADDRESS>", "<PFS_ADDRESS>", "<GW_NAME>", ""]:
            return "unknown"
        return host or "unknown"
    except Exception:
        return "unknown"


def get_source_val(entry):
    """Return source from rule entry (API dict or XML backup format)."""
    src = entry.get("source")
    if isinstance(src, dict):
        return src.get("network") or src.get("address") or src.get("any")
    return src or entry.get("source_net")


def get_dest_val(entry):
    """Return destination from rule entry (API dict or XML backup format)."""
    dst = entry.get("destination")
    if isinstance(dst, dict):
        return dst.get("network") or dst.get("address") or dst.get("any")
    return dst or entry.get("destination_net") or entry.get("%destination_net")


def get_port_val(entry):
    """Return destination port from rule entry."""
    dst = entry.get("destination")
    if isinstance(dst, dict):
        return dst.get("port")
    return entry.get("destination_port")


def map_value(value, field=None, any_value="Any"):
    """
    Map value using API aliases (alias takes precedence over raw value).
    """
    if value is None:
        return any_value
    if isinstance(value, list):
        value = ", ".join(map(str, value))

    # Negated address ("!lan"): map the address, keep the negation marker.
    if field in ("source", "destination") and isinstance(value, str) and value.startswith("!"):
        return f"!{map_value(value[1:], field, any_value)}"

    # Interface and source mapping.
    if field in ("source", "interface"):
        val = str(value).strip().lower()
        if "," in val:
            # Multiple interfaces (e.g. "lan,wan") → map each and rejoin
            parts = [p.strip() for p in val.split(",") if p.strip()]
            mapped = [API_INTERFACE_MAP.get(p, p.upper()) for p in parts]
            return ", ".join(mapped)
        if val in API_INTERFACE_MAP:
            return API_INTERFACE_MAP[val]

    # Port mapping.
    if field == "destination_port":
        val = str(value)
        if val in API_PORT_MAP:
            return API_PORT_MAP[val]

    # Destination mapping (networks, addresses, interfaces).
    if field == "destination":
        val = str(value).lower()
        # Gateway address pattern (e.g. lan:ip, opt1:ip, lanip) maps to "{Interface Description} Address".
        interface_name = None
        if ':' in val and val.endswith(':ip'):
            # Pattern "lan:ip" -> extract "lan".
            interface_name = val.rsplit(':', 1)[0]
        elif val.endswith('ip') and len(val) > 2:
            # Pattern "lanip", "opt1ip" -> remove "ip" suffix and match interface.
            potential_interface = val[:-2]  # Remove "ip" suffix
            # Check if it is a known interface (wan, lan, optX).
            if potential_interface in API_INTERFACE_MAP:
                interface_name = potential_interface
            # Also try opt1, opt2, etc.
            elif potential_interface.startswith('opt') and potential_interface[3:].isdigit():
                # For opt1ip, opt2ip, etc.
                interface_name = potential_interface

        if interface_name and interface_name in API_INTERFACE_MAP:
            interface_desc = API_INTERFACE_MAP[interface_name]
            # Return "{Interface Description} Address".
            return f"{interface_desc} Address"

        # Check interface map (interfaces can be destinations but not gateway addresses).
        if val in API_INTERFACE_MAP:
            return API_INTERFACE_MAP[val]
        if val in API_NET_MAP:
            return API_NET_MAP[val]
        if val in API_ADDRESS_MAP:
            return API_ADDRESS_MAP[val]

    return value


def update_api_maps(interface_map, net_map, address_map, port_map, alias_details=None,
                    interface_nets=None):
    """Update global API alias maps with the given data (interface_nets is reset when omitted)."""
    global API_INTERFACE_MAP, API_NET_MAP, API_ADDRESS_MAP, API_PORT_MAP, API_ALIAS_DETAILS
    global API_INTERFACE_NETS, MAPS_VERSION
    MAPS_VERSION += 1
    API_INTERFACE_MAP = interface_map
    API_NET_MAP = net_map
    API_ADDRESS_MAP = address_map
    API_PORT_MAP = port_map
    if alias_details is not None:
        API_ALIAS_DETAILS = alias_details
    API_INTERFACE_NETS = interface_nets or {}


def empty_maps():
    """Lookup maps filled by the parsers / API client and installed with update_api_maps()."""
    return {"interface_map": {}, "net_map": {}, "address_map": {}, "port_map": {},
            "alias_details": {}, "interface_nets": {}}


def register_alias(maps, name, alias_type, content, description="", display=None):
    """
    Store one alias / object in the lookup maps.

    display: text shown in the reports instead of the alias name (default: description or
    content for addresses, content for ports).
    """
    key = str(name).lower()
    maps["alias_details"][key] = {"name": str(name), "type": alias_type, "content": content,
                                  "description": description}
    if alias_type == "port":
        maps["port_map"][key] = display or content or description
        return
    shown = display or description or content
    maps["net_map"][key] = shown
    if alias_type in ("host", "network"):
        maps["address_map"][key] = shown


def add_interface_address(nets, iface, address, prefix=None, wan=None):
    """
    Record an interface address in an interface_nets dict.
    address may be "192.168.1.1", "192.168.1.1/24" or a non-static value ("dhcp", "pppoe"...),
    which only registers the interface. prefix is the subnet length when address has none.
    """
    import ipaddress

    entry = nets.setdefault(str(iface).lower(), {"nets": [], "addrs": [], "wan": False})
    if wan is not None:
        entry["wan"] = entry["wan"] or bool(wan)
    text = str(address or "").strip()
    if not text:
        return entry
    if "/" not in text and prefix not in (None, ""):
        text = f"{text}/{prefix}"
    try:
        iface_obj = ipaddress.ip_interface(text)
    except ValueError:
        return entry  # dhcp, pppoe, track6...
    if str(iface_obj.ip) not in entry["addrs"]:
        entry["addrs"].append(str(iface_obj.ip))
    has_net = iface_obj.network.prefixlen != iface_obj.network.max_prefixlen or "/" in text
    if has_net and str(iface_obj.network) not in entry["nets"]:
        entry["nets"].append(str(iface_obj.network))
    return entry


def get_alias_details(value):
    """Return alias details for a value if it is an alias, else None."""
    if not value:
        return None
    val = str(value).lower().strip().lstrip("!")
    # Direct lookup.
    if val in API_ALIAS_DETAILS:
        return API_ALIAS_DETAILS[val]
    # Try without spaces and special characters.
    val_clean = val.replace(' ', '').replace(',', '')
    if val_clean in API_ALIAS_DETAILS:
        return API_ALIAS_DETAILS[val_clean]
    # Try each part if comma-separated list.
    if ',' in val:
        for part in val.split(','):
            part_clean = part.strip().lower()
            if part_clean in API_ALIAS_DETAILS:
                return API_ALIAS_DETAILS[part_clean]
    return None


def format_alias_label(value, default_label=None):
    """Return label with alias details if available."""
    if not value:
        return default_label or value

    alias_info = get_alias_details(value)
    if alias_info:
        parts = []
        # Add alias name (keep the "!" negation marker if present).
        negation = "!" if str(value).strip().startswith("!") else ""
        parts.append(negation + alias_info.get("name", value))
        # Add type.
        alias_type = alias_info.get("type", "")
        if alias_type:
            parts.append(f"[{alias_type}]")
        # Add content if available.
        content = alias_info.get("content", "")
        if content:
            parts.append(f"({content})")
        # Add description if different from name.
        description = alias_info.get("description", "")
        if description and description != alias_info.get("name", ""):
            parts.append(f"- {description}")
        return " ".join(parts)

    return default_label or value


# ---------------------------------------------------------------------------
# Parallel loading of several firewalls
# ---------------------------------------------------------------------------

THREAD_PREFIX = "fetch:"
_prefix_installed = False


def install_thread_prefix():
    """Log records of the loading threads (named 'fetch:<firewall>') start with '[<firewall>] '."""
    global _prefix_installed
    if _prefix_installed:
        return
    import logging
    import threading

    previous = logging.getLogRecordFactory()

    def factory(*args, **kwargs):
        record = previous(*args, **kwargs)
        name = threading.current_thread().name
        if name.startswith(THREAD_PREFIX) and isinstance(record.msg, str):
            record.msg = f"[{name[len(THREAD_PREFIX):]}] {record.msg}"
        return record

    logging.setLogRecordFactory(factory)
    _prefix_installed = True


def load_in_parallel(items, load, workers):
    """
    Run load(item) -> result for every item in up to `workers` threads (network bound: reading a
    firewall API) and return the results in the order of items. An exception becomes the result.
    load must not touch process-wide state (alias maps are installed again before the analysis).

    items: [(name, payload)]; load receives the payload.
    """
    import threading
    from concurrent.futures import ThreadPoolExecutor

    install_thread_prefix()

    def task(item):
        name, payload = item
        threading.current_thread().name = f"{THREAD_PREFIX}{name}"
        try:
            return load(payload)
        except Exception as e:  # Reported by the caller, in order.
            return e
        finally:
            threading.current_thread().name = "pyfrc2g-fetch"

    with ThreadPoolExecutor(max_workers=max(1, int(workers)), thread_name_prefix="pyfrc2g-fetch") as pool:
        return list(pool.map(task, items))
