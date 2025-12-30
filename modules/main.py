"""
Main execution module for PyFRC2G
"""

import os
import csv
import glob
import logging
import sys
import shutil
from .config import Config
from .api_client import APIClient
from .graph_generator import GraphGenerator
from .ciso_client import CISOCClient
from .utils import calculate_md5, map_value, normalize_ports


def main():
    """Main execution function."""
    # Set up logging level (DEBUG if --debug flag is present)
    log_level = logging.DEBUG if '--debug' in sys.argv else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    config = Config()
    api_client = APIClient(config)
    graph_generator = GraphGenerator(config)
    ciso_client = CISOCClient(config)

    logging.debug(f"Configuration loaded: gateway_type={config.gateway_type}, gateway_name={config.gateway_name}")
    if config.gateway_type.lower() == "pfsense":
        logging.debug(f"pfSense URL: {config.pfs_url}, Base URL: {config.pfs_base_url}")
    elif config.gateway_type.lower() == "opnsense":
        logging.debug(f"OPNSense Base URL: {config.opns_base_url}, Rules URL: {config.opns_url}")
        logging.debug(f"OPNSense Interfaces: {config.interfaces}")

    logging.info(f"Starting rule extraction for {config.gateway_type}")

    # Fetch aliases from API
    logging.info("Fetching aliases from API...")
    logging.debug("Calling fetch_aliases()...")
    api_client.fetch_aliases()
    logging.debug(f"Aliases loaded: {len(api_client.interface_map)} interfaces, {len(api_client.net_map)} networks, {len(api_client.port_map)} ports")

    # Extract rules
    with open(config.csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=config.csv_fieldnames)
        writer.writeheader()

        if config.gateway_type.lower() == "pfsense":
            logging.debug("Fetching pfSense rules...")
            entries = api_client.fetch_rules()

            if entries:
                logging.info(f"Retrieved {len(entries)} rules from pfSense")
                logging.debug(f"First rule sample: {entries[0] if entries else 'N/A'}")
                for entry in entries:
                    writer.writerow({
                        "SOURCE": map_value(entry.get("source"), "source", config.any_value),
                        "GATEWAY": f"{config.gateway_name}/{map_value(entry.get('interface'), 'interface', config.any_value)}",
                        "ACTION": map_value(entry.get("type"), None, config.any_value),
                        "PROTOCOL": map_value(entry.get("protocol"), None, config.any_value),
                        "PORT": map_value(entry.get("destination_port"), "destination_port", config.any_value),
                        "DESTINATION": map_value(entry.get("destination"), "destination", config.any_value),
                        "COMMENT": map_value(entry.get("descr"), None, config.any_value),
                        "DISABLED": map_value(entry.get("disabled"), None, config.any_value),
                        "FLOATING": map_value(entry.get("floating"), None, config.any_value)
                    })
            else:
                logging.warning("No firewall rules retrieved from pfSense")

        elif config.gateway_type.lower() == "opnsense":
            logging.debug("Fetching OPNSense rules...")
            entries = api_client.fetch_rules()

            if not entries:
                logging.error("No rules retrieved from OPNSense")
                return

            logging.debug(f"Retrieved {len(entries)} rules from OPNSense")
            if entries:
                logging.debug(f"First rule sample: {entries[0] if entries else 'N/A'}")

            # Write entries
            for entry in entries:
                source_val = (entry.get('source', {}).get('network') or
                            entry.get('source', {}).get('address') or
                            entry.get('source_net') or
                            entry.get('source', {}).get('any'))
                destination_val = (entry.get('destination', {}).get('network') or
                                 entry.get('destination', {}).get('address') or
                                 entry.get('destination', {}).get('any') or
                                 entry.get("destination_net"))
                port_dest_val = (entry.get('destination', {}).get('port') or
                               entry.get("destination_port"))
                entry_interface = entry.get("interface")

                writer.writerow({
                    "SOURCE": map_value(source_val, "source", config.any_value),
                    "GATEWAY": f"{config.gateway_name}/{map_value(entry_interface, 'interface', config.any_value)}" if entry_interface else f"{config.gateway_name}/Floating-rules",
                    "ACTION": map_value(entry.get("action"), None, config.any_value),
                    "PROTOCOL": map_value(entry.get("protocol"), None, config.any_value),
                    "PORT": map_value(port_dest_val, "destination_port", config.any_value),
                    "DESTINATION": map_value(destination_val, "destination", config.any_value),
                    "COMMENT": map_value(entry.get("description"), None, config.any_value),
                    "DISABLED": "False",
                    "FLOATING": "True" if not entry_interface else "False"
                })
        else:
            logging.error(f"Unknown gateway type: {config.gateway_type}. Use 'pfsense' or 'opnsense'.")
            return

    logging.info(f"✓ CSV file generated: {config.csv_file}")

    # Check for changes using MD5
    prev_md5 = ""
    if os.path.exists("md5sum.txt"):
        with open("md5sum.txt", "r") as f:
            prev_md5 = f.readline().strip()

    actual_md5 = calculate_md5(config.csv_file)
    logging.debug(f"MD5 comparison: previous={prev_md5[:8]}..., current={actual_md5[:8]}...")

    if prev_md5 != actual_md5:
        with open("md5sum.txt", "w") as f:
            f.write(f"{actual_md5}\n")
        logging.info("Changes detected, generating graphs...")

        # Create global CSV file (copy of all rules)
        os.makedirs(config.graph_output_dir, exist_ok=True)
        host_name = os.path.basename(config.graph_output_dir) if os.path.basename(config.graph_output_dir) else "gateway"
        global_csv = os.path.join(config.graph_output_dir, f"{host_name}_ALL_flows.csv")
        shutil.copy2(config.csv_file, global_csv)
        logging.info(f"✓ Global CSV created: {global_csv}")

        # Generate global file (all interfaces together)
        logging.info("Generating global graph (all interfaces combined)...")
        graph_generator.generate_graphs(config.csv_file, config.graph_output_dir)

        # Generate per-interface files (separate graphs for each interface)
        logging.info("Generating per-interface graphs (separate files for each interface)...")
        graph_generator.generate_by_interface(config.csv_file, config.graph_output_dir)

        # Cleanup PNG files (after PDFs are generated)
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

        # Upload to CISO Assistant if configured
        if ciso_client.enabled:
            logging.info("Uploading PDFs to CISO Assistant...")
            global_pdf = f"{config.graph_output_dir}/{host_name}_FLOW_MATRIX.pdf"
            stats = ciso_client.upload_global_pdf(global_pdf)
            if stats["successful"] > 0:
                logging.info(f"✓ Successfully uploaded {stats['successful']} PDF to CISO Assistant")
            if stats["failed"] > 0:
                logging.warning(f"⚠ Failed to upload {stats['failed']} PDF(s) to CISO Assistant")
    else:
        logging.info("No rules created or modified")

    # Cleanup CSV
    if os.path.exists(config.csv_file):
        os.remove(config.csv_file)
        logging.info("Temporary CSV file deleted")


if __name__ == "__main__":
    main()

