"""
Main execution module for PyFRC2G.
"""

import os
import csv
import glob
import logging
import sys
import shutil
from modules.config import Config
from modules.api_client import APIClient
from modules.graph_generator import GraphGenerator
from modules.ciso_client import CISOCClient
from modules.utils import (
    calculate_md5,
    map_value,
    update_api_maps,
    get_source_val,
    get_dest_val,
    get_port_val,
    normalize_interface,
)


def _gateway_from_entry(entry, config):
    """Build GATEWAY cell: gateway_name/interfaces (e.g. pfSense/wan,lan). Use map_value for interface. Floating-rules only when no interface."""
    entry_interface = normalize_interface(entry.get("interface"))
    if entry_interface and entry_interface.strip().lower() == "floating":
        return f"{config.gateway_name}/Floating-rules"
    if entry_interface:
        return f"{config.gateway_name}/{map_value(entry_interface, 'interface', config.any_value)}"
    return f"{config.gateway_name}/Floating-rules"


def _protocol_from_entry(entry):
    """Build PROTOCOL cell from ipprotocol + protocol (e.g. 'IPv4 tcp', 'IPv6 Any'). Empty protocol → 'Any'."""
    ipp = (entry.get("ipprotocol") or "").strip()
    prot = (entry.get("protocol") or "").strip()
    prot_display = prot or "Any"
    if ipp:
        return f"{ipp} {prot_display}"
    return prot or "Any"


def _is_floating_entry(entry):
    """True if rule is floating (no interface or explicitly tagged). Same logic for API and backup."""
    return bool(entry.get("floating") or not entry.get("interface"))


def _entry_to_csv_row(entry, config, gateway_type, gateway, rule_order):
    """Convert one rule entry to a CSV row dict (pfSense and OPNsense share the same columns)."""
    floating = _is_floating_entry(entry)
    if gateway_type == "pfsense":
        source = entry.get("source")
        action = entry.get("type")
        port = entry.get("destination_port")
        dest = entry.get("destination")
        comment = entry.get("descr")
        disabled = "True" if entry.get("disabled") else "False"
    else:
        source = get_source_val(entry)
        action = entry.get("action") or entry.get("type")
        port = get_port_val(entry)
        dest = get_dest_val(entry)
        comment = entry.get("description")
        disabled = "True" if not entry.get("enabled", True) else "False"
    protocol = _protocol_from_entry(entry)
    return {
        "SOURCE": map_value(source, "source", config.any_value),
        "GATEWAY": gateway,
        "ACTION": map_value(action, None, config.any_value),
        "PROTOCOL": map_value(protocol, None, config.any_value),
        "PORT": map_value(port, "destination_port", config.any_value),
        "DESTINATION": map_value(dest, "destination", config.any_value),
        "COMMENT": map_value(comment, None, config.any_value),
        "DISABLED": disabled,
        "FLOATING": "True" if floating else "False",
        "RULE ORDER": rule_order,
    }


def _run_graph_and_pdf_generation(config, graph_generator, ciso_client):
    """Generate global and per-interface graphs/PDFs, remove temporary PNGs, optionally upload to CISO."""
    os.makedirs(config.graph_output_dir, exist_ok=True)
    host_name = os.path.basename(config.graph_output_dir) or "gateway"
    global_csv = os.path.join(config.graph_output_dir, f"{host_name}_ALL_flows.csv")
    shutil.copy2(config.csv_file, global_csv)
    logging.info(f"✓ Global CSV created: {global_csv}")
    logging.info("Generating global graph (all interfaces combined)...")
    graph_generator.generate_graphs(config.csv_file, config.graph_output_dir)
    logging.info("Generating per-interface graphs (separate files for each interface)...")
    graph_generator.generate_by_interface(config.csv_file, config.graph_output_dir)
    try:
        png_files = glob.glob(os.path.join(config.graph_output_dir, "*.png"))
        for png in png_files:
            if os.path.exists(png):
                os.remove(png)
                logging.debug(f"✓ PNG deleted: {png}")
        if png_files:
            logging.info(f"✓ Cleaned up {len(png_files)} temporary PNG file(s)")
    except Exception as e:
        logging.warning(f"Could not delete some PNG files: {e}")
    if ciso_client.enabled:
        logging.info("Uploading PDFs to CISO Assistant...")
        global_pdf = os.path.join(config.graph_output_dir, f"{host_name}_FLOW_MATRIX.pdf")
        stats = ciso_client.upload_global_pdf(global_pdf)
        if stats["successful"] > 0:
            logging.info(f"✓ Successfully uploaded {stats['successful']} PDF to CISO Assistant")
        if stats["failed"] > 0:
            logging.warning(f"⚠ Failed to upload {stats['failed']} PDF(s) to CISO Assistant")


def main(args=None):
    """
    Main execution function.

    Args:
        args: Optional argparse.Namespace from pyfrc2g.py (e.g. --backup, --gateway-name).
    """
    # Set up logging level (DEBUG if --debug or --verbose is present).
    log_level = logging.DEBUG if ("--debug" in sys.argv or (args and (args.debug or args.verbose))) else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    backup_file = args.backup if args and hasattr(args, "backup") and args.backup else None
    gateway_name_override = args.gateway_name if args and hasattr(args, "gateway_name") and args.gateway_name else None
    skip_config_check = bool(args and getattr(args, "skip_config_check", False))
    
    use_backup = bool(backup_file)
    
    # Configuration check for API mode.
    if not use_backup:
        from modules.config_checker import run_configuration_check
        print("=== Configuration check (API mode) ===")
        if not run_configuration_check(skip_prompt=skip_config_check):
            print("\n[ERROR] Configuration is missing or invalid. Please edit modules/config.py then run again.")
            print("   Use --backup FILE to read from an XML backup instead of the API.")
            print("   Use --skip-config-check to bypass this check (not recommended).")
            return 2
        print("[OK] Configuration check passed.\n")
    
    if use_backup:
        logging.info(f"Mode: XML backup (no API calls). File: {backup_file}")
        from pathlib import Path
        from modules.xml_parser import parse_xml_backup
        aliases_dict, entries, gateway_type, gateway_name_from_xml = parse_xml_backup(backup_file)
        if aliases_dict is None:
            return 1
        if not entries:
            logging.warning("No rules found in backup file - output may be empty")
        # Gateway name: --gateway-name overrides hostname from XML, then filename stem.
        if not gateway_name_override:
            gateway_name_override = gateway_name_from_xml or Path(backup_file).stem
        config = Config(gateway_name_override=gateway_name_override, gateway_type_override=gateway_type)
        update_api_maps(
            aliases_dict.get("interface_map", {}),
            aliases_dict.get("net_map", {}),
            aliases_dict.get("address_map", {}),
            aliases_dict.get("port_map", {}),
            aliases_dict.get("alias_details"),
        )
    else:
        config = Config(gateway_name_override=gateway_name_override)
        api_client = APIClient(config)
        api_client.fetch_aliases()
        entries = api_client.fetch_rules()
    
    graph_generator = GraphGenerator(config)
    ciso_client = CISOCClient(config)
    
    logging.debug(f"Configuration loaded: gateway_type={config.gateway_type}, gateway_name={config.gateway_name}")
    logging.info(f"Starting rule extraction for {config.gateway_type}")
    
    if not use_backup:
        if config.gateway_type.lower() == "pfsense":
            logging.debug(f"pfSense URL: {config.pfs_url}, Base URL: {config.pfs_base_url}")
        elif config.gateway_type.lower() == "opnsense":
            logging.debug(f"OPNSense Base URL: {config.opns_base_url}, Rules URL: {config.opns_url}")

    # Create output directory with gateway name.
    if not os.path.exists(config.graph_output_dir):
        os.makedirs(config.graph_output_dir)

    gateway_type_lower = config.gateway_type.lower()
    if gateway_type_lower not in ("pfsense", "opnsense"):
        logging.error(f"Unknown gateway type: {config.gateway_type}. Use 'pfsense' or 'opnsense'.")
        return

    logging.debug(f"Processing {config.gateway_type} rules...")
    if entries:
        logging.info(f"Retrieved {len(entries)} rules from {config.gateway_type}")
        logging.debug(f"First rule sample: {entries[0]}")
    else:
        logging.warning(f"No firewall rules retrieved from {config.gateway_type}")

    # Extract rules to CSV.
    with open(config.csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=config.csv_fieldnames)
        writer.writeheader()
        rule_counters = {}
        for entry in entries:
            gateway = _gateway_from_entry(entry, config)
            rule_counters[gateway] = rule_counters.get(gateway, 0) + 1
            writer.writerow(_entry_to_csv_row(entry, config, gateway_type_lower, gateway, rule_counters[gateway]))
    
    logging.info(f"✓ CSV file generated: {config.csv_file}")
    
    # Check for changes using MD5 (backup mode always generates PDF from XML).
    prev_md5 = ""
    if os.path.exists(config.md5_file):
        with open(config.md5_file, "r") as f:
            prev_md5 = f.readline().strip()
    
    actual_md5 = calculate_md5(config.csv_file)
    logging.debug(f"MD5 comparison: previous={prev_md5[:8]}..., current={actual_md5[:8]}...")
    
    changes_detected = prev_md5 != actual_md5
    if use_backup or changes_detected:
        with open(config.md5_file, "w") as f:
            f.write(f"{actual_md5}\n")
        if use_backup and not changes_detected:
            logging.info("Generating graphs from backup...")
        else:
            logging.info("Changes detected, generating graphs...")
        _run_graph_and_pdf_generation(config, graph_generator, ciso_client)
    else:
        logging.info("No rules created or modified")
    
    # Remove temporary CSV.
    if os.path.exists(config.csv_file):
        os.remove(config.csv_file)
        logging.info("Temporary CSV file deleted")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

