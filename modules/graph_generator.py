"""
Graph generation module for PyFRC2G
"""

import os
import glob
import csv
import logging
from collections import OrderedDict
from graphviz import Digraph
from .utils import normalize_ports, safe_filename, map_value, format_alias_label
from .config import FLOATING_RULES_LABELS, UNKNOWN_LABEL, DISABLED_LABEL, ANY_VALUE


class GraphGenerator:
    """Graph generator for firewall rules"""

    def __init__(self, config):
        self.config = config

    def generate_by_interface(self, csv_path, output_dir):
        """Generate separate CSV and PDF files for each interface."""
        os.makedirs(output_dir, exist_ok=True)
        rules_by_interface = OrderedDict()

        # Group rules by interface
        with open(csv_path, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                gateway = (row.get("GATEWAY") or "").strip()
                interface_name = gateway.split("/", 1)[1] if "/" in gateway else gateway

                if interface_name not in rules_by_interface:
                    rules_by_interface[interface_name] = []
                rules_by_interface[interface_name].append(row)

        # Generate files for each interface
        for interface_name, rules in rules_by_interface.items():
            if not rules:
                continue

            interface_safe = safe_filename(interface_name)
            logging.info(f"Processing interface: {interface_name} ({len(rules)} rules)")

            # Extract host from output directory path (results/host/)
            host_name = os.path.basename(output_dir) if os.path.basename(output_dir) else "gateway"

            # Create CSV file
            interface_csv = os.path.join(output_dir, f"{host_name}_{interface_safe}_flows.csv")
            with open(interface_csv, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=self.config.csv_fieldnames)
                writer.writeheader()
                writer.writerows(rules)

            logging.info(f"  ✓ CSV created: {interface_csv}")

            # Generate graph and PDF
            self.generate_graphs(interface_csv, output_dir, interface_name)

        logging.info(f"✓ Generated files for {len(rules_by_interface)} interfaces")

    def generate_graphs(self, csv_path, output_dir, interface_filter=None):
        """Parse CSV and generate graphs. If interface_filter is specified, only generate for that interface."""
        os.makedirs(output_dir, exist_ok=True)
        flows_by_gateway = OrderedDict()
        next_id = 0

        def get_node(nodes, key, label=None, color=None, force_unique=False):
            """Create or retrieve a node, factorized by cluster/source unless force_unique."""
            nonlocal next_id
            actual_key = f"{key}__{next_id}" if force_unique else key
            if actual_key not in nodes:
                nodes[actual_key] = (f"node{next_id}", color, label or key)
                next_id += 1
            return nodes[actual_key][0]

        def get_action_color(action):
            """Get color for action type."""
            return "#a3f7a3" if action == "PASS" else "#f7a3a3" if action == "BLOCK" or action == "REJECT" else None

        def get_disabled_color(disabled):
            """Get color for disabled rules."""
            return "#ffcc00" if disabled == "True" else None

        # Parse CSV and build graph structure
        with open(csv_path, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                floating = (row.get("FLOATING") or "").strip()
                source = (row.get("SOURCE") or "").strip()
                gateway = (row.get("GATEWAY") or "").strip() if floating not in ["True", "1"] else "Floating-rules"

                # Filter by interface if specified
                if interface_filter:
                    interface_name = gateway.split("/", 1)[1] if "/" in gateway else gateway
                    if interface_name != interface_filter:
                        continue

                action = (row.get("ACTION") or "").strip().upper()
                protocol = (row.get("PROTOCOL") or "").strip() or ANY_VALUE
                ports = normalize_ports(row.get("PORT"), ANY_VALUE)
                destination = (row.get("DESTINATION") or "").strip()
                comment = (row.get("COMMENT") or "").strip()
                disabled = (row.get("DISABLED") or "").strip()

                # Create labels with alias details (clean HTML-like characters)
                source_clean = str(source).replace('<', '').replace('>', '') if source else UNKNOWN_LABEL
                gateway_clean = str(gateway).replace('<', '').replace('>', '') if gateway else UNKNOWN_LABEL
                action_clean = str(action).replace('<', '').replace('>', '') if action else UNKNOWN_LABEL
                destination_clean = str(destination).replace('<', '').replace('>', '') if destination else UNKNOWN_LABEL
                comment_clean = str(comment).replace('<', '').replace('>', '') if comment else ""

                # Format labels with alias details if available
                source_formatted = format_alias_label(source, source_clean)
                destination_formatted = format_alias_label(destination, destination_clean)
                port_formatted = format_alias_label(ports, ports)

                source_label = f"SOURCE | {source_formatted}" if source_formatted else f"SOURCE | {UNKNOWN_LABEL}"
                gateway_label = f"GATEWAY | {gateway_clean}" if gateway_clean else f"GATEWAY | {UNKNOWN_LABEL}"
                action_label = f"ACTION | {action_clean}" if action_clean else f"ACTION | {UNKNOWN_LABEL}"
                proto_label = f"PROTOCOL | {protocol}"
                port_label = f"PORT | {port_formatted}"

                if disabled == "True":
                    destination_label = f"{destination_formatted} | {comment_clean} | {DISABLED_LABEL}" if comment_clean else f"VLAN | {destination_formatted} | {DISABLED_LABEL}"
                else:
                    destination_label = f"{destination_formatted} | {comment_clean}" if comment_clean else f"VLAN | {destination_formatted}"

                # Initialize cluster/source
                if gateway not in flows_by_gateway:
                    flows_by_gateway[gateway] = OrderedDict()
                if source not in flows_by_gateway[gateway]:
                    flows_by_gateway[gateway][source] = {"nodes": OrderedDict(), "edges": set()}

                cluster = flows_by_gateway[gateway][source]

                # Create nodes
                n_source = get_node(cluster["nodes"], source_label)
                n_gateway = get_node(cluster["nodes"], gateway_label)
                n_action = get_node(cluster["nodes"], action_label, color=get_action_color(action))
                proto_key = f"{protocol}|{action}"
                n_proto = get_node(cluster["nodes"], proto_key, label=proto_label)
                port_key = f"{ports}|{proto_key}"
                n_port = get_node(cluster["nodes"], port_key, label=port_label)

                is_floating = any(label in gateway for label in FLOATING_RULES_LABELS)
                n_destination = get_node(cluster["nodes"], destination_label,
                                        force_unique=not is_floating,
                                        color=get_disabled_color(disabled))

                # Create edges
                edges = [(n_source, n_gateway), (n_gateway, n_action), (n_action, n_proto),
                        (n_proto, n_port), (n_port, n_destination)]
                cluster["edges"].update(edges)

        # Generate graphs
        for gateway, sources in flows_by_gateway.items():
            gateway_safe = safe_filename(gateway)
            filename = os.path.join(output_dir, f"{gateway_safe}.gv")
            g = Digraph('g', filename=filename, format='png')
            g.attr(fontname="Helvetica,Arial,sans-serif")
            g.attr("node", fontname="Helvetica,Arial,sans-serif", fontsize="11", shape="record")
            g.attr("edge", fontname="Helvetica,Arial,sans-serif")
            g.attr(rankdir="LR")
            # Escape HTML-like characters in gateway name for Graphviz (remove < > characters)
            gateway_label = gateway.replace('<', '').replace('>', '').strip()
            if not gateway_label:
                gateway_label = "Gateway"
            g.attr(label=f"<<b>GATEWAY : {gateway_label}</b>>", labelloc="t", fontsize="14", color="#8888ff")

            for source, cluster in sources.items():
                with g.subgraph(name=f"cluster_{source.replace(' ', '_')}") as sg:
                    sg.attr(label=f"SOURCE : {source}", style="dashed", color="#aaaaaa")
                    for nid, color, label in cluster["nodes"].values():
                        sg.node(nid, label=label, shape="record",
                               **({"style":"filled","fillcolor":color} if color else {}))
                    for src, dst in cluster["edges"]:
                        sg.edge(src, dst)

            g.render(view=False)

            # Cleanup .gv file
            try:
                if os.path.exists(filename):
                    os.remove(filename)
            except Exception as e:
                logging.warning(f"Could not delete {filename}: {e}")

            logging.info(f"✓ Graph generated: {filename}.png")

        # Generate PDF
        self.generate_pdf(output_dir, interface_filter)

    def generate_pdf(self, output_dir, interface_filter=None):
        """Generate PDF from PNG files."""
        try:
            from reportlab.pdfgen import canvas
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.utils import ImageReader

            # Get PNG files
            if interface_filter:
                interface_safe = safe_filename(interface_filter)
                all_pngs = sorted(glob.glob(os.path.join(output_dir, "*.png")))
                png_files = [png for png in all_pngs
                            if interface_safe in os.path.basename(png).replace(".gv.png", "").replace(".png", "")]
                png_files = sorted(png_files)
            else:
                png_files = sorted(glob.glob(os.path.join(output_dir, "*.png")))

            if not png_files:
                logging.warning(f"No PNG files found for interface {interface_filter}" if interface_filter else "No PNG files found for PDF")
                return

            # Extract host from output directory path (results/host/)
            host_name = os.path.basename(output_dir) if os.path.basename(output_dir) else "gateway"

            # PDF path
            if interface_filter:
                interface_safe = safe_filename(interface_filter)
                pdf_path = os.path.join(output_dir, f"{host_name}_{interface_safe}_FLOW_MATRIX.pdf")
            else:
                pdf_path = os.path.join(output_dir, f"{host_name}_FLOW_MATRIX.pdf")

            # Extract host from output directory path
            host_name = os.path.basename(output_dir) if os.path.basename(output_dir) else "gateway"

            # Create PDF
            c = canvas.Canvas(pdf_path, pagesize=A4)
            width, height = A4
            c.setTitle(f"Flow matrix for gateway {host_name}")

            for png in png_files:
                page_title = os.path.basename(png).replace(".gv.png", "").replace(".png", "")
                c.bookmarkPage(page_title)
                c.addOutlineEntry(page_title, page_title, level=0)

                img = ImageReader(png)
                img_width, img_height = img.getSize()
                scale = min(width / img_width, height / img_height)
                new_width = img_width * scale
                new_height = img_height * scale
                x = (width - new_width) / 2
                y = (height - new_height) / 2

                c.drawImage(img, x, y, width=new_width, height=new_height)
                c.showPage()

            c.save()
            if interface_filter:
                logging.info(f"✓ PDF generated: {pdf_path} (interface: {interface_filter}, {len(png_files)} page(s))")
            else:
                logging.info(f"✓ Global PDF generated: {pdf_path} (all interfaces, {len(png_files)} page(s))")

        except Exception as e:
            logging.error(f"Error generating PDF: {e}")

