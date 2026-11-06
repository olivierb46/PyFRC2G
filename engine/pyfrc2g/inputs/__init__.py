"""
Inputs: firewall API client (api_client) and configuration file parsers. Every format is
converted to the same model as the pfSense / OPNsense XML parser (pfsense_xml):

    (maps, rule_entries, gateway_type, gateway_name, nat_entries)

maps: interface_map, net_map, address_map, port_map, alias_details, interface_nets
rule_entries: dicts with action, interface, source, destination, protocol, destination_port,
              description, enabled, uuid, ipprotocol, floating, in_iface, out_iface, _hits...

Formats: pfsense / opnsense (config.xml), fortigate (full configuration backup),
iptables (iptables-save / ip6tables-save output, -c for counters), nftables ("nft -j list
ruleset" JSON), stormshield (filter slot file or extracted ConfigFiles directory, experimental).
"""

import logging
import os

from pyfrc2g import utils

FORMATS = ("auto", "pfsense", "opnsense", "fortigate", "iptables", "nftables", "stormshield")


def detect_format(path):
    """Guess the configuration format from the file content. Returns a FORMATS value or None."""
    if os.path.isdir(path):
        return "stormshield"
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            head = f.read(65536)
    except OSError:
        return None
    stripped = head.lstrip()
    if stripped.startswith("<"):
        return "xml"
    if stripped.startswith("{") and '"nftables"' in head:
        return "nftables"
    if "config firewall policy" in head or head.startswith("#config-version=") \
            or "config system global" in head:
        return "fortigate"
    lines = [line.strip() for line in head.splitlines() if line.strip()]
    if any(line.startswith(("*filter", "*nat")) for line in lines) \
            and any(line.startswith(":") or "-A " in line for line in lines):
        return "iptables"
    if any(line.lower() == "[filter]" for line in lines):
        return "stormshield"
    return None


def register_alias(maps, name, alias_type, content, description=""):
    """Register an object of a non-pfSense configuration (displayed by its name)."""
    utils.register_alias(maps, name, alias_type, content, description or str(name), display=str(name))


def load_backup(path, fmt="auto"):
    """
    Load a configuration file in any supported format.

    Returns:
        tuple: (maps, entries, gateway_type, gateway_name, nat_entries); maps is None on error.
    """
    from pyfrc2g.inputs.pfsense_xml import parse_xml_backup

    if not os.path.exists(path):
        logging.error(f"Backup file not found: {path}")
        return None, [], None, None, []
    detected = detect_format(path) if fmt in (None, "auto") else fmt
    if detected in ("xml", "pfsense", "opnsense"):
        result = parse_xml_backup(path)
        if fmt in ("pfsense", "opnsense") and result[2] and result[2] != fmt:
            logging.warning(f"--format {fmt} but the file looks like a {result[2]} backup")
        return result
    if detected is None:
        logging.error(f"Unknown configuration format for {path} (use --format)")
        return None, [], None, None, []

    from pyfrc2g.inputs import fortigate, iptables, nftables, stormshield

    parser = {"fortigate": fortigate.parse, "iptables": iptables.parse,
              "nftables": nftables.parse, "stormshield": stormshield.parse}[detected]
    logging.info(f"Detected {detected} configuration, parsing...")
    try:
        maps, entries, name, nat = parser(path)
    except (OSError, ValueError) as e:
        logging.error(f"Cannot parse {path} as {detected}: {e}")
        return None, [], None, None, []
    logging.info(f"✓ Parsed {len(entries)} rules and {len(maps['alias_details'])} objects"
                 + (f" ({len(nat)} NAT rule(s))" if nat else ""))
    return maps, entries, detected, name, nat
