"""
NAT rules: normalization of API/XML entries into flat rows.

TYPE column:
    PORT FORWARD  destination NAT: DESTINATION/DESTINATION PORT are rewritten to TARGET/TARGET PORT
    OUTBOUND      source NAT: SOURCE going to DESTINATION leaves with address TARGET (port TARGET PORT)
    1:1           SOURCE (internal) <-> TARGET (external address)
"""

from pyfrc2g.utils import map_value, normalize_interface

NAT_FIELDNAMES = [
    "TYPE", "INTERFACE", "PROTOCOL", "SOURCE", "SOURCE PORT", "DESTINATION", "DESTINATION PORT",
    "TARGET", "TARGET PORT", "COMMENT", "DISABLED", "RULE ID",
]


def _first(entry, *keys):
    """Return the first non-empty value among keys (supports dotted keys for nested dicts)."""
    for key in keys:
        value = entry
        for part in key.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        if value not in (None, "", [], {}):
            return value
    return None


def _address(value):
    """Normalize an address value that may be a dict ({network|address|any, not})."""
    if isinstance(value, dict):
        addr = value.get("network") or value.get("address") or ("any" if "any" in value else None)
        if addr and value.get("not") not in (None, False, "0", ""):
            return f"!{addr}"
        return addr
    return value


def _flag(value):
    return value not in (None, False, 0, "0", "", "no", "false")


def _is_disabled(entry):
    disabled = entry.get("disabled")
    if disabled is not None:
        return disabled not in (False, 0, "0", "no", "false")
    enabled = entry.get("enabled")
    return enabled is not None and str(enabled).strip().lower() in ("0", "false", "no")


def nat_entry_to_row(entry, any_value="Any"):
    """Convert one NAT entry (pfSense/OPNsense, API or XML) to a NAT CSV row."""
    source = _address(_first(entry, "source", "source_net"))
    destination = _address(_first(entry, "destination", "destination_net"))
    source_port = _first(entry, "source_port", "source.port")
    destination_port = _first(entry, "destination_port", "destination.port", "dstport")
    nat_type = entry.get("_nat_type") or "PORT FORWARD"
    target = _first(entry, "target", "target_ip", "targetip", "external")
    target_port = _first(entry, "local_port", "local-port", "target_port", "localport", "natport")
    if nat_type == "OUTBOUND":
        if _flag(entry.get("nonat")):
            target, target_port = "No NAT", None
        elif not target:
            target = "Interface address"
    return {
        "TYPE": nat_type,
        "INTERFACE": map_value(normalize_interface(_first(entry, "interface")) or None,
                               "interface", any_value),
        "PROTOCOL": str(_first(entry, "protocol") or any_value),
        "SOURCE": map_value(source, "source", any_value),
        "SOURCE PORT": map_value(source_port, "destination_port", any_value),
        "DESTINATION": map_value(destination, "destination", any_value),
        "DESTINATION PORT": map_value(destination_port, "destination_port", any_value),
        "TARGET": map_value(target, "destination", any_value),
        "TARGET PORT": map_value(target_port, "destination_port", any_value),
        "COMMENT": str(_first(entry, "descr", "description") or ""),
        "DISABLED": "True" if _is_disabled(entry) else "False",
        "RULE ID": str(_first(entry, "uuid", "tracker", "associated-rule-id") or ""),
    }
