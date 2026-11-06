"""
Parse pfSense and OPNSense XML backup files.
Extracts rules and aliases in API-compatible format from config.xml backups.
"""

import logging
import xml.etree.ElementTree as ET
from pathlib import Path

from pyfrc2g.utils import is_floating_flag, is_interface_floating

_SYSTEM_INTERFACES = frozenset({"lo0", "enc0", "pflog0"})
_FALSE_FLAG_VALUES = frozenset({"0", "no", "false", "off"})


def _detect_type_from_root(root):
    """Return 'pfsense', 'opnsense' or None from a parsed XML root element."""
    root_tag = (root.tag or "").lower()
    if root_tag in ("pfsense", "opnsense"):
        return root_tag
    if root.find("OPNsense/Firewall/Filter/rules/rule") is not None:
        return "opnsense"
    if root.find(".//firewall/filter/rule") is not None:
        return "opnsense"
    if root.find(".//filter/rule") is not None:
        return "pfsense"
    logging.warning(f"Could not detect backup type from root tag: {root_tag}")
    return None


def detect_backup_type(xml_path):
    """
    Detect whether the XML backup is from pfSense or OPNSense.

    Returns:
        str: 'pfsense', 'opnsense', or None if unknown.
    """
    try:
        return _detect_type_from_root(ET.parse(xml_path).getroot())
    except ET.ParseError as e:
        logging.error(f"Invalid XML file: {e}")
        return None


def _get_text(element, default=""):
    """Return stripped text from XML element, or default if None or empty."""
    if element is None or not element.text:
        return default
    return element.text.strip() or default


def _get_child_text(parent, tag, default=""):
    """Return text from child element, or default if missing."""
    if parent is None:
        return default
    return _get_text(parent.find(tag), default)


def _has_flag(parent, tag):
    """
    True if a boolean flag element is set.

    pfSense writes flags as empty elements (<disabled></disabled>); OPNsense legacy
    format uses <disabled>1</disabled>. An explicit "0"/"no"/"false" means unset.
    """
    elem = parent.find(tag) if parent is not None else None
    if elem is None:
        return False
    return (elem.text or "").strip().lower() not in _FALSE_FLAG_VALUES


def _get_hostname(root):
    """Return <system><hostname> from a parsed XML root, or None."""
    return _get_child_text(root.find("system"), "hostname", "") or None


def get_gateway_name_from_xml(xml_path):
    """
    Extract gateway name from backup XML (system hostname).
    Both pfSense and OPNSense use <system><hostname>...</hostname>.

    Returns:
        str or None: Hostname if found, None on error or if not found.
    """
    try:
        return _get_hostname(ET.parse(xml_path).getroot())
    except (ET.ParseError, OSError):
        return None


def _extract_address(source_or_dest):
    """
    Extract address from source or destination XML element.
    Handles <any/>, <network>, <address> and the <not/> negation flag
    (returned with a "!" prefix, as displayed in the pfSense/OPNsense GUI).
    """
    if source_or_dest is None:
        return None
    if source_or_dest.find("any") is not None:
        value = "any"
    else:
        value = (_get_child_text(source_or_dest, "network")
                 or _get_child_text(source_or_dest, "address")
                 or None)
    if value and _has_flag(source_or_dest, "not"):
        return f"!{value}"
    return value


def _extract_port(dest_elem):
    """Return port from destination element, e.g. <destination><port>53</port></destination>."""
    return _get_child_text(dest_elem, "port") or None


def _empty_maps():
    return {
        "interface_map": {},
        "net_map": {},
        "address_map": {},
        "port_map": {},
        "alias_details": {},
    }


def _register_alias(maps, name, alias_type, content, description):
    """Store one alias in the lookup maps (shared by pfSense and OPNSense parsers)."""
    key = name.lower()
    maps["alias_details"][key] = {
        "name": name,
        "type": alias_type,
        "content": content,
        "description": description,
    }
    if alias_type in ("host", "network"):
        maps["net_map"][key] = maps["address_map"][key] = description or content
    elif alias_type == "port":
        maps["port_map"][key] = content or description
    else:
        maps["net_map"][key] = description or content


def _register_interfaces(root, maps, require_enabled=False):
    """Fill interface_map from <interfaces>: wan, lan and optN → description."""
    for iface in root.findall("interfaces/*"):
        iface_id = (iface.tag or "").lower()
        if iface_id in _SYSTEM_INTERFACES:
            continue
        if iface_id not in ("wan", "lan") and not iface_id.startswith("opt"):
            continue
        if require_enabled and _get_child_text(iface, "enable", "1") != "1":
            continue
        maps["interface_map"][iface_id] = _get_child_text(iface, "descr") or iface_id.upper()


def parse_pfsense_backup(root):
    """
    Parse pfSense config.xml backup.

    Args:
        root: Parsed XML root element (or a path, for backward compatibility).

    Returns:
        tuple: (aliases_dict, rules_list) in API-compatible format.
    """
    if not isinstance(root, ET.Element):
        root = ET.parse(root).getroot()
    maps = _empty_maps()

    for alias in root.findall("aliases/alias"):
        name = _get_child_text(alias, "name")
        if not name:
            continue
        content = _get_child_text(alias, "address").replace("\n", ", ")
        description = _get_child_text(alias, "descr")
        _register_alias(maps, name, _get_child_text(alias, "type"), content, description)

    _register_interfaces(root, maps)

    rules = [_parse_pfsense_rule(rule) for rule in root.findall("filter/rule")]
    for rule in root.findall("floatingrules/rule"):
        entry = _parse_pfsense_rule(rule)
        entry["floating"] = True
        entry["interface"] = None
        rules.append(entry)

    return maps, rules


def _parse_pfsense_rule(rule_elem):
    """Parse a single pfSense rule element into an API-compatible dict."""
    interface = _get_child_text(rule_elem, "interface")
    dest = rule_elem.find("destination")
    return {
        "type": _get_child_text(rule_elem, "type", "pass"),
        "interface": interface or None,
        "source": _extract_address(rule_elem.find("source")) or "any",
        "destination": _extract_address(dest) or "any",
        "ipprotocol": _get_child_text(rule_elem, "ipprotocol") or None,
        "protocol": _get_child_text(rule_elem, "protocol") or None,
        "destination_port": _extract_port(dest) or _get_child_text(rule_elem, "destination_port") or None,
        "descr": _get_child_text(rule_elem, "descr"),
        "tracker": _get_child_text(rule_elem, "tracker"),
        "disabled": _has_flag(rule_elem, "disabled"),
        "floating": is_floating_flag(_get_child_text(rule_elem, "floating")) or is_interface_floating(interface),
    }


def parse_opnsense_backup(root):
    """
    Parse OPNSense config.xml backup.
    Supports both the legacy <filter><rule> layout and the 26.1+ MVC layout
    (<OPNsense><Firewall><Filter><rules><rule>).

    Args:
        root: Parsed XML root element (or a path, for backward compatibility).

    Returns:
        tuple: (aliases_dict, rules_list) in API-compatible format.
    """
    if not isinstance(root, ET.Element):
        root = ET.parse(root).getroot()
    maps = _empty_maps()

    for alias in root.findall(".//aliases/alias"):
        name = _get_child_text(alias, "name")
        if not name:
            continue
        content = (_get_child_text(alias, "content") or _get_child_text(alias, "address")).replace("\n", ", ")
        description = (_get_child_text(alias, "description")
                       or _get_child_text(alias, "descr")
                       or name.lower())
        _register_alias(maps, name, _get_child_text(alias, "type"), content, description)

    _register_interfaces(root, maps, require_enabled=True)

    rules = [_parse_opnsense_rule_26_1(r) for r in root.findall("OPNsense/Firewall/Filter/rules/rule")]
    if rules:
        logging.debug("Using OPNsense 26.1+ firewall rules (new) format")
    else:
        rules = [_parse_opnsense_rule(r) for r in root.findall("filter/rule")]

    return maps, rules


def _parse_opnsense_rule(rule_elem):
    """Parse a single OPNSense legacy rule element (backup XML uses <type> and <descr>)."""
    action = _get_child_text(rule_elem, "type") or _get_child_text(rule_elem, "action", "pass")
    interface = _get_child_text(rule_elem, "interface")
    dest = rule_elem.find("destination")
    source_val = _extract_address(rule_elem.find("source")) or "any"
    dest_val = _extract_address(dest) or "any"
    return {
        "action": action,
        "type": action,
        "interface": interface or None,
        "source": source_val,
        "destination": dest_val,
        "ipprotocol": _get_child_text(rule_elem, "ipprotocol") or None,
        "protocol": _get_child_text(rule_elem, "protocol") or None,
        "destination_port": _extract_port(dest) or _get_child_text(rule_elem, "destination_port") or None,
        "description": _get_child_text(rule_elem, "descr") or _get_child_text(rule_elem, "description"),
        "floating": is_floating_flag(_get_child_text(rule_elem, "floating")) or is_interface_floating(interface),
        "source_net": source_val,
        "destination_net": dest_val,
        "enabled": not _has_flag(rule_elem, "disabled"),
        "uuid": rule_elem.get("uuid") or _get_child_text(rule_elem, "tracker") or None,
    }


def _parse_opnsense_rule_26_1(rule_elem):
    """
    Parse a single OPNsense 26.1+ rule (new format with action, source_net, destination_net,
    description, enabled, source_not/destination_not).
    """
    interface = _get_child_text(rule_elem, "interface")
    source_val = _get_child_text(rule_elem, "source_net", "any")
    dest_val = _get_child_text(rule_elem, "destination_net", "any")
    if _get_child_text(rule_elem, "source_not") == "1":
        source_val = f"!{source_val}"
    if _get_child_text(rule_elem, "destination_not") == "1":
        dest_val = f"!{dest_val}"
    action = _get_child_text(rule_elem, "action", "pass")
    return {
        "action": action,
        "type": action,
        "interface": interface or None,
        "source": source_val,
        "destination": dest_val,
        "ipprotocol": _get_child_text(rule_elem, "ipprotocol") or None,
        "protocol": _get_child_text(rule_elem, "protocol") or None,
        "destination_port": _get_child_text(rule_elem, "destination_port") or None,
        "description": _get_child_text(rule_elem, "description"),
        "floating": is_floating_flag(_get_child_text(rule_elem, "floating")) or is_interface_floating(interface),
        "source_net": source_val,
        "destination_net": dest_val,
        "enabled": _get_child_text(rule_elem, "enabled", "1") == "1",
        "uuid": rule_elem.get("uuid") or None,
    }


def _parse_nat_rule(rule_elem):
    """Parse a port forward rule (<nat><rule>, same layout on pfSense and OPNsense)."""
    source = rule_elem.find("source")
    dest = rule_elem.find("destination")
    return {
        "interface": _get_child_text(rule_elem, "interface") or None,
        "protocol": _get_child_text(rule_elem, "protocol") or None,
        "source": _extract_address(source) or "any",
        "source_port": _extract_port(source),
        "destination": _extract_address(dest) or "any",
        "destination_port": _extract_port(dest),
        "target": _get_child_text(rule_elem, "target") or None,
        "local_port": _get_child_text(rule_elem, "local-port") or None,
        "descr": _get_child_text(rule_elem, "descr"),
        "disabled": _has_flag(rule_elem, "disabled"),
        "uuid": rule_elem.get("uuid") or None,
    }


def parse_nat_rules(root):
    """Return port forward (destination NAT) rules from a parsed backup root."""
    return [_parse_nat_rule(rule) for rule in root.findall("nat/rule")]


def parse_xml_backup(xml_path):
    """
    Parse XML backup file (pfSense or OPNSense). The file is read only once.

    Args:
        xml_path: Path to config.xml backup file.

    Returns:
        tuple: (aliases_dict, rules_list, gateway_type, gateway_name, nat_rules).
        aliases_dict: interface_map, net_map, address_map, port_map, alias_details
                      (None on error).
        rules_list: Rule dicts in API-compatible format.
        gateway_name: Hostname from XML, or None if not found.
        nat_rules: Port forward rule dicts.
    """
    if not Path(xml_path).is_file():
        logging.error(f"XML backup file not found: {xml_path}")
        return None, [], None, None, []

    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError as e:
        logging.error(f"Invalid XML file: {e}")
        return None, [], None, None, []

    gateway_type = _detect_type_from_root(root)
    if not gateway_type:
        logging.error("Could not detect backup type (pfSense or OPNSense)")
        return None, [], None, None, []

    gateway_name = _get_hostname(root)
    if gateway_name:
        logging.info(f"Gateway name from XML: {gateway_name}")

    logging.info(f"Detected {gateway_type} backup, parsing...")
    parser = parse_pfsense_backup if gateway_type == "pfsense" else parse_opnsense_backup
    aliases_dict, rules = parser(root)
    nat_rules = parse_nat_rules(root)

    logging.info(
        f"✓ Parsed {len(rules)} rules and {len(aliases_dict['alias_details'])} aliases from XML backup"
        + (f" ({len(nat_rules)} NAT port forward(s))" if nat_rules else "")
    )
    return aliases_dict, rules, gateway_type, gateway_name, nat_rules
