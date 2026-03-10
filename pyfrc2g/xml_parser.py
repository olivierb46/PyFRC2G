"""
Parse pfSense and OPNSense XML backup files.
Extracts rules and aliases in API-compatible format from config.xml backups.
"""

import logging
import xml.etree.ElementTree as ET
from pathlib import Path

from pyfrc2g.utils import is_interface_floating, is_floating_flag


def detect_backup_type(xml_path):
    """
    Detect whether the XML backup is from pfSense or OPNSense.

    Returns:
        str: 'pfsense', 'opnsense', or None if unknown.
    """
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        root_tag = root.tag.lower() if root.tag else ""

        if root_tag == "pfsense":
            return "pfsense"
        if root_tag == "opnsense":
            return "opnsense"

        if root.find(".//filter/rule") is not None:
            return "pfsense"
        if root.find(".//firewall/filter/rule") is not None:
            return "opnsense"
        if root.find("OPNsense/Firewall/Filter/rules/rule") is not None:
            return "opnsense"

        logging.warning(f"Could not detect backup type from root tag: {root_tag}")
        return None
    except ET.ParseError as e:
        logging.error(f"Invalid XML file: {e}")
        return None


def _get_text(element, default=""):
    """Return text from XML element, or default if None or empty."""
    if element is None:
        return default
    return (element.text or "").strip() if element.text else default


def _get_child_text(parent, tag, default=""):
    """Return text from child element, or default if missing."""
    if parent is None:
        return default
    child = parent.find(tag)
    return _get_text(child, default) if child is not None else default


def get_gateway_name_from_xml(xml_path):
    """
    Extract gateway name from backup XML (system hostname).
    Both pfSense and OPNSense use <system><hostname>...</hostname>.

    Returns:
        str or None: Hostname if found, None on error or if not found.
    """
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        system = root.find("system")
        if system is None:
            return None
        hostname = _get_child_text(system, "hostname", "").strip()
        if not hostname:
            return None
        return hostname
    except (ET.ParseError, OSError):
        return None


def _extract_address(source_or_dest):
    """
    Extract address from source or destination XML element.
    Handles <any/>, empty <any>, <any>1</any>, <network>, and <address>.
    """
    if source_or_dest is None:
        return None
    any_elem = source_or_dest.find("any")
    if any_elem is not None:
        return "any"
    for child in source_or_dest:
        if child.tag == "network" and child.text:
            return child.text.strip()
        if child.tag == "address" and child.text:
            return child.text.strip()
    network = source_or_dest.find("network")
    if network is not None and network.text:
        return network.text.strip()
    address = source_or_dest.find("address")
    if address is not None and address.text:
        return address.text.strip()
    return None


def _extract_port(dest_elem):
    """Return port from destination element, e.g. <destination><port>53</port></destination>."""
    if dest_elem is None:
        return None
    port = dest_elem.find("port")
    if port is not None and port.text:
        return port.text.strip()
    return None


def parse_pfsense_backup(xml_path):
    """
    Parse pfSense config.xml backup.

    Returns:
        tuple: (aliases_dict, rules_list) in API-compatible format.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    interface_map = {}
    net_map = {}
    address_map = {}
    port_map = {}
    alias_details = {}

    aliases = root.find("aliases")
    if aliases is not None:
        for alias in aliases.findall("alias"):
            name = _get_child_text(alias, "name", "").lower()
            if not name:
                continue
            alias_type = _get_child_text(alias, "type", "")
            descr = _get_child_text(alias, "descr", "") or alias.get("name", "")

            addr_elem = alias.find("address")
            if addr_elem is not None and addr_elem.text:
                content = addr_elem.text.strip().replace("\n", ", ")
            else:
                content = ""

            alias_details[name] = {
                "name": _get_child_text(alias, "name", ""),
                "type": alias_type,
                "content": content,
                "description": descr
            }
            if alias_type in ("host", "network"):
                net_map[name] = address_map[name] = descr or content
            elif alias_type == "port":
                port_map[name] = content or descr
            else:
                net_map[name] = descr or content

    for iface in root.findall("interfaces/*"):
        if iface.tag in ("wan", "lan") or (iface.tag or "").startswith("opt"):
            iface_id = iface.tag.lower()
            if iface_id in ("lo0", "enc0", "pflog0"):
                continue
            descr = _get_child_text(iface, "descr", "")
            interface_map[iface_id] = descr or iface_id.upper()

    rules = []
    filter_elem = root.find("filter")
    if filter_elem is not None:
        for rule in filter_elem.findall("rule"):
            entry = _parse_pfsense_rule(rule)
            if entry:
                rules.append(entry)

    floating = root.find("floatingrules")
    if floating is not None:
        for rule in floating.findall("rule"):
            entry = _parse_pfsense_rule(rule)
            if entry:
                entry["floating"] = True
                entry["interface"] = None
                rules.append(entry)

    return {
        "interface_map": interface_map,
        "net_map": net_map,
        "address_map": address_map,
        "port_map": port_map,
        "alias_details": alias_details,
    }, rules


def _parse_pfsense_rule(rule_elem):
    """Parse a single pfSense rule element into an API-compatible dict."""
    rule_type = _get_child_text(rule_elem, "type", "pass")
    interface = _get_child_text(rule_elem, "interface", "")
    disabled = _get_child_text(rule_elem, "disabled", "")
    floating_tag = _get_child_text(rule_elem, "floating", "")
    is_floating = is_floating_flag(floating_tag) or is_interface_floating(interface)

    source = rule_elem.find("source")
    dest = rule_elem.find("destination")
    source_val = _extract_address(source) or "any"
    dest_val = _extract_address(dest) or "any"
    dst_port = _extract_port(dest) or _get_child_text(rule_elem, "destination_port", "")
    ipprotocol = _get_child_text(rule_elem, "ipprotocol", "")
    protocol = _get_child_text(rule_elem, "protocol", "")
    descr = _get_child_text(rule_elem, "descr", "")
    tracker = _get_child_text(rule_elem, "tracker", "")

    return {
        "type": rule_type,
        "interface": interface if interface else None,
        "source": source_val,
        "destination": dest_val,
        "ipprotocol": ipprotocol or None,
        "protocol": protocol or None,
        "destination_port": dst_port or None,
        "descr": descr,
        "tracker": tracker,
        "disabled": disabled == "1",
        "floating": is_floating,
    }


def parse_opnsense_backup(xml_path):
    """
    Parse OPNSense config.xml backup.
    Filter is at root: <opnsense><filter><rule>...</rule></filter>.

    Returns:
        tuple: (aliases_dict, rules_list) in API-compatible format.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    interface_map = {}
    net_map = {}
    address_map = {}
    port_map = {}
    alias_details = {}

    for aliases_elem in root.findall(".//aliases"):
        for alias in aliases_elem.findall("alias"):
            name = _get_child_text(alias, "name", "").lower()
            if not name:
                continue
            alias_type = _get_child_text(alias, "type", "")
            descr = _get_child_text(alias, "description", "") or _get_child_text(alias, "descr", "") or name

            content_elem = alias.find("content")
            if content_elem is not None and content_elem.text:
                content = content_elem.text.strip().replace("\n", ", ")
            else:
                addr = alias.find("address")
                content = (addr.text or "").strip() if addr is not None else ""

            alias_details[name] = {
                "name": _get_child_text(alias, "name", ""),
                "type": alias_type,
                "content": content,
                "description": descr
            }
            if alias_type in ("host", "network"):
                net_map[name] = address_map[name] = descr or content
            elif alias_type == "port":
                port_map[name] = content or descr
            else:
                net_map[name] = descr or content

    for iface in root.findall("interfaces/*"):
        if iface.tag in ("wan", "lan") or (iface.tag or "").startswith("opt"):
            iface_id = iface.tag.lower()
            if iface_id in ("lo0", "enc0", "pflog0"):
                continue
            descr = _get_child_text(iface, "descr", "")
            if _get_child_text(iface, "enable", "1") == "1":
                interface_map[iface_id] = descr or iface_id.upper()

    rules = []
    rules_new = root.find("OPNsense/Firewall/Filter/rules")
    if rules_new is not None:
        for rule in rules_new.findall("rule"):
            entry = _parse_opnsense_rule_26_1(rule)
            if entry:
                rules.append(entry)
        if rules:
            logging.debug("Using OPNsense 26.1+ firewall rules (new) format")
    if not rules:
        filter_elem = root.find("filter")
        if filter_elem is not None:
            for rule in filter_elem.findall("rule"):
                entry = _parse_opnsense_rule(rule)
                if entry:
                    rules.append(entry)

    return {
        "interface_map": interface_map,
        "net_map": net_map,
        "address_map": address_map,
        "port_map": port_map,
        "alias_details": alias_details,
    }, rules


def _parse_opnsense_rule(rule_elem):
    """Parse a single OPNSense rule element (backup XML uses <type> and <descr>)."""
    action = _get_child_text(rule_elem, "type", "") or _get_child_text(rule_elem, "action", "pass")
    interface = _get_child_text(rule_elem, "interface", "")
    floating_tag = _get_child_text(rule_elem, "floating", "")
    is_floating = is_floating_flag(floating_tag) or is_interface_floating(interface)

    source = rule_elem.find("source")
    dest = rule_elem.find("destination")
    source_val = _extract_address(source) or "any"
    dest_val = _extract_address(dest) or "any"
    dst_port = _extract_port(dest) or _get_child_text(rule_elem, "destination_port", "")
    ipprotocol = _get_child_text(rule_elem, "ipprotocol", "")
    protocol = _get_child_text(rule_elem, "protocol", "")
    descr = _get_child_text(rule_elem, "descr", "") or _get_child_text(rule_elem, "description", "")

    return {
        "action": action or "pass",
        "type": action or "pass",
        "interface": interface if interface else None,
        "source": source_val,
        "destination": dest_val,
        "ipprotocol": ipprotocol or None,
        "protocol": protocol or None,
        "destination_port": dst_port or None,
        "description": descr,
        "floating": is_floating,
        "source_net": source_val,
        "destination_net": dest_val,
    }


def _parse_opnsense_rule_26_1(rule_elem):
    """
    Parse a single OPNsense 26.1+ rule (new format with action, source_net, destination_net, description, enabled).
    """
    action = _get_child_text(rule_elem, "action", "pass")
    interface = _get_child_text(rule_elem, "interface", "")
    floating_tag = _get_child_text(rule_elem, "floating", "")
    is_floating = is_floating_flag(floating_tag) or is_interface_floating(interface)

    source_val = _get_child_text(rule_elem, "source_net", "") or "any"
    dest_val = _get_child_text(rule_elem, "destination_net", "") or "any"
    dst_port = _get_child_text(rule_elem, "destination_port", "")
    ipprotocol = _get_child_text(rule_elem, "ipprotocol", "")
    protocol = _get_child_text(rule_elem, "protocol", "")
    descr = _get_child_text(rule_elem, "description", "")
    enabled = _get_child_text(rule_elem, "enabled", "1") == "1"
    return {
        "action": action or "pass",
        "type": action or "pass",
        "interface": interface if interface else None,
        "source": source_val if source_val else "any",
        "destination": dest_val if dest_val else "any",
        "ipprotocol": ipprotocol or None,
        "protocol": protocol or None,
        "destination_port": dst_port or None,
        "description": descr,
        "floating": is_floating,
        "source_net": source_val if source_val else "any",
        "destination_net": dest_val if dest_val else "any",
        "enabled": enabled,
    }


def parse_xml_backup(xml_path):
    """
    Parse XML backup file (pfSense or OPNSense).

    Args:
        xml_path: Path to config.xml backup file.

    Returns:
        tuple: (aliases_dict, rules_list, gateway_type, gateway_name).
        aliases_dict: interface_map, net_map, address_map, port_map, alias_details.
        rules_list: Rule dicts in API-compatible format.
        gateway_name: Hostname from XML, or None if not found.
    """
    path = Path(xml_path)
    if not path.exists():
        logging.error(f"XML backup file not found: {xml_path}")
        return None, [], None, None

    gateway_type = detect_backup_type(xml_path)
    if not gateway_type:
        logging.error("Could not detect backup type (pfSense or OPNSense)")
        return None, [], None, None

    gateway_name = get_gateway_name_from_xml(xml_path)
    if gateway_name:
        logging.info(f"Gateway name from XML: {gateway_name}")

    logging.info(f"Detected {gateway_type} backup, parsing...")

    if gateway_type == "pfsense":
        aliases_dict, rules = parse_pfsense_backup(xml_path)
    else:
        aliases_dict, rules = parse_opnsense_backup(xml_path)

    logging.info(f"✓ Parsed {len(rules)} rules and {len(aliases_dict.get('alias_details', {}))} aliases from XML backup")
    return aliases_dict, rules, gateway_type, gateway_name
