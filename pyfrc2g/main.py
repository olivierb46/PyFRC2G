"""
Main entry point for PyFRC2G CLI.
"""

import sys
import argparse
import os
import csv
import glob
import logging
import shutil
from pathlib import Path

from pyfrc2g.utils import (
    calculate_md5,
    map_value,
    update_api_maps,
    get_source_val,
    get_dest_val,
    get_port_val,
    normalize_interface,
)

# Lazy imports for heavy deps used only in _run(): Config, APIClient, GraphGenerator, CISOCClient


def check_dependencies():
    """
    Verify that required dependencies are installed.

    Returns:
        tuple: (ok, error_message). ok is True if all deps are installed, else False and error_message
               contains an "Install with: ..." line.
    """
    missing = []
    try:
        import requests  # noqa: F401
    except ImportError:
        missing.append("requests")
    try:
        import graphviz  # noqa: F401
    except ImportError:
        missing.append("graphviz")
    try:
        import reportlab  # noqa: F401
    except ImportError:
        missing.append("reportlab")
    if missing:
        return False, (
            f"Missing required package(s): {', '.join(missing)}.\n"
            "Install with: pip install -r requirements.txt   or   pip install requests graphviz reportlab"
        )
    return True, None


def _gateway_from_entry(entry, config):
    """Build GATEWAY cell: gateway_name/interfaces. Floating with multiple interfaces (e.g. lan,wan) shows interfaces; else Floating-rules."""
    entry_interface = normalize_interface(entry.get("interface"))
    if entry.get("floating"):
        if entry_interface and "," in entry_interface:
            return f"{config.gateway_name}/{map_value(entry_interface, 'interface', config.any_value)}"
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


def _run(args):
    """Core execution logic (API or backup mode, CSV, graphs, PDF)."""
    ok, err = check_dependencies()
    if not ok:
        print(err, file=sys.stderr)
        return 1

    from pyfrc2g.config import Config
    from pyfrc2g.api_client import APIClient
    from pyfrc2g.graph_generator import GraphGenerator
    from pyfrc2g.ciso_client import CISOCClient

    backup_file = args.backup if args and hasattr(args, "backup") and args.backup else None
    gateway_name_override = args.gateway_name if args and hasattr(args, "gateway_name") and args.gateway_name else None
    skip_config_check = bool(args and getattr(args, "skip_config_check", False))

    use_backup = bool(backup_file)

    if not use_backup:
        from pyfrc2g.config_checker import run_configuration_check
        print("=== Configuration check (API mode) ===")
        if not run_configuration_check(skip_prompt=skip_config_check):
            print("\n[ERROR] Configuration is missing or invalid. Please edit pyfrc2g/config.py then run again.")
            print("   Use --backup FILE to read from an XML backup instead of the API.")
            print("   Use --skip-config-check to bypass this check (not recommended).")
            return 2
        print("[OK] Configuration check passed.\n")

    if use_backup:
        logging.info(f"Mode: XML backup (no API calls). File: {backup_file}")
        from pyfrc2g.xml_parser import parse_xml_backup
        aliases_dict, entries, gateway_type, gateway_name_from_xml = parse_xml_backup(backup_file)
        if aliases_dict is None:
            return 1
        if not entries:
            logging.warning("No rules found in backup file - output may be empty")
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

    if not os.path.exists(config.graph_output_dir):
        os.makedirs(config.graph_output_dir)

    gateway_type_lower = config.gateway_type.lower()
    if gateway_type_lower not in ("pfsense", "opnsense"):
        logging.error(f"Unknown gateway type: {config.gateway_type}. Use 'pfsense' or 'opnsense'.")
        return 1

    logging.debug(f"Processing {config.gateway_type} rules...")
    if entries:
        logging.info(f"Retrieved {len(entries)} rules from {config.gateway_type}")
        logging.debug(f"First rule sample: {entries[0]}")
    else:
        logging.warning(f"No firewall rules retrieved from {config.gateway_type}")

    with open(config.csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=config.csv_fieldnames)
        writer.writeheader()
        rule_counters = {}
        for entry in entries:
            gateway = _gateway_from_entry(entry, config)
            rule_counters[gateway] = rule_counters.get(gateway, 0) + 1
            writer.writerow(_entry_to_csv_row(entry, config, gateway_type_lower, gateway, rule_counters[gateway]))

    logging.info(f"✓ CSV file generated: {config.csv_file}")

    prev_md5 = ""
    if os.path.exists(config.md5_file):
        with open(config.md5_file, "r", encoding="utf-8") as f:
            prev_md5 = f.readline().strip()

    actual_md5 = calculate_md5(config.csv_file)
    logging.debug(f"MD5 comparison: previous={prev_md5[:8] if prev_md5 else ''}..., current={actual_md5[:8]}...")

    changes_detected = prev_md5 != actual_md5
    if use_backup or changes_detected:
        with open(config.md5_file, "w", encoding="utf-8") as f:
            f.write(f"{actual_md5}\n")
        if use_backup and not changes_detected:
            logging.info("Generating graphs from backup...")
        else:
            logging.info("Changes detected, generating graphs...")
        _run_graph_and_pdf_generation(config, graph_generator, ciso_client)
    else:
        logging.info("No rules created or modified")

    if os.path.exists(config.csv_file):
        os.remove(config.csv_file)
        logging.info("Temporary CSV file deleted")

    return 0


def parse_args(argv=None):
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="PyFRC2G - Convert pfSense/OPNSense firewall rules to flow diagrams",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fetch rules from API (configure pyfrc2g/config.py first)
  pyfrc2g
  pyfrc2g --api

  # Skip configuration check (use only if you know config is valid)
  pyfrc2g --api --skip-config-check

  # Read rules from XML backup file (no config check needed)
  pyfrc2g --backup config-backup.xml

  # Specify gateway name for backup mode
  pyfrc2g --backup config.xml --gateway-name my-firewall

  # Enable debug logging
  pyfrc2g --api --debug
  pyfrc2g --backup config.xml --verbose
        """
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--api", "-a",
        action="store_true",
        help="Fetch rules from firewall API (default if no mode; configure pyfrc2g/config.py)"
    )
    mode.add_argument(
        "--backup", "-b",
        metavar="FILE",
        help="Read rules from XML backup file (pfSense or OPNSense config.xml)"
    )
    parser.add_argument(
        "--gateway-name", "-g",
        metavar="NAME",
        help="Gateway display name (for backup mode or when not using API)"
    )
    parser.add_argument(
        "--debug", "-d",
        action="store_true",
        help="Enable debug logging"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output (same as --debug)"
    )
    parser.add_argument(
        "--skip-config-check",
        action="store_true",
        help="Skip configuration check before running (API mode only)"
    )
    parser.add_argument(
        "--check-deps",
        action="store_true",
        help="Check that required packages are installed, then exit (0=OK, 1=missing deps)"
    )
    return parser.parse_args(argv)


def main(argv=None):
    """
    Entry point for the pyfrc2g console script.

    Args:
        argv: Optional list of arguments (default: sys.argv[1:]).

    Returns:
        int: Exit code (0 on success).
    """
    args = parse_args(argv)
    if getattr(args, "check_deps", False):
        ok, err = check_dependencies()
        if ok:
            print("All required packages are installed (requests, graphviz, reportlab).")
            return 0
        print(err, file=sys.stderr)
        return 1
    if args.debug or args.verbose:
        sys.argv = [sys.argv[0], "--debug"]
    log_level = logging.DEBUG if (args.debug or args.verbose) else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    return _run(args) or 0


if __name__ == "__main__":
    sys.exit(main())
