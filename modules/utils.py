"""
Utility functions for PyFRC2G.
"""

import re
import hashlib
import logging

# Global API alias maps (populated by APIClient).
API_INTERFACE_MAP = {}
API_NET_MAP = {}
API_ADDRESS_MAP = {}
API_PORT_MAP = {}
API_ALIAS_DETAILS = {}  # Full alias details: {name: {type, content, description}}.


def calculate_md5(file_path):
    """Return MD5 hash of a file."""
    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5.update(chunk)
    return md5.hexdigest()


def extract_base_url(api_url):
    """Return base URL from API endpoint URL."""
    if "/api/" in api_url:
        return api_url.rsplit("/api/", 1)[0]
    return api_url.rsplit("/api", 1)[0]


def normalize_ports(port_field, any_value="Any"):
    """Return normalized port field value."""
    if not port_field:
        return any_value
    return re.sub(r'\s+', '', str(port_field).strip()) or any_value


def safe_filename(name):
    """Return a filesystem-safe version of the string."""
    return name.replace('/', '_').replace(' ', '_').replace('<', '').replace('>', '')

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
    
    # Interface and source mapping.
    if field in ("source", "interface"):
        val = str(value).lower()
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


def update_api_maps(interface_map, net_map, address_map, port_map, alias_details=None):
    """Update global API alias maps with the given data."""
    global API_INTERFACE_MAP, API_NET_MAP, API_ADDRESS_MAP, API_PORT_MAP, API_ALIAS_DETAILS
    API_INTERFACE_MAP = interface_map
    API_NET_MAP = net_map
    API_ADDRESS_MAP = address_map
    API_PORT_MAP = port_map
    if alias_details is not None:
        API_ALIAS_DETAILS = alias_details


def get_alias_details(value):
    """Return alias details for a value if it is an alias, else None."""
    if not value:
        return None
    val = str(value).lower().strip()
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
        # Add alias name.
        parts.append(alias_info.get("name", value))
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

