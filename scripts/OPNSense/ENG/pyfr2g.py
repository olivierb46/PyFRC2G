import requests
import urllib3
import re
from collections import OrderedDict
from graphviz import Digraph
import os
import logging
import glob
import csv
from config import INTERFACE_MAP, NET_MAP, ADDRESS_MAP, PORT_MAP
import hashlib

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO)

# --- CONFIG ---
OPNS_URL = "https://<IP address or FQDM>/api/firewall/filter/search_rule"  # <----------------------
OPNS_KEY = "<OPNsense api key>"  # <----------------------
OPNS_SECRET = "OPNsense api secret>"  # <----------------------
# GATEWAY
GATEWAY = "<GATEWAY NAME>>"  # <----------------------
# CSV FILE
CSV_FILE = "output_" + GATEWAY + ".csv"
# GRAPH OUTPUT DIRECTORY
GRAPH_OUTPUT_DIR = "tmp/graphs_" + GATEWAY
# Declaration of interfaces present on OPNSense
INTERFACES = ["wan", "lan", "opt1", "opt2"]  # <---------------------- Check the number of interfaces on your router


def calculate_md5sum(path):
    md5 = hashlib.md5()
    with open(path, "rb") as f:
        # Read the file by chunks to avoid memory saturation
        for chunk in iter(lambda: f.read(4096), b""):
            md5.update(chunk)
    return md5.hexdigest()


def retrieve_rules(url, api_secret, api_key, params):
    try:
        headers = {
            "User-Agent": "curl/7.68.0",
            "Accept": "application/json"
        }
        # headers = {"accept": "application/json", "X-API-Key": token}
        response = requests.get(
            url,
            params=params,
            headers=headers,  # mimic a User-Agent
            auth=(api_key, api_secret),  # same order as -u "KEY:SECRET"
            verify=False  # equivalent of curl -k
        )
        return response.json()

    except requests.exceptions.HTTPError as e:
        print(f"⚠️ HTTP Error: {e}")
        print(f"Response Body: {response.text}")
        exit()
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        exit()


def safe_value(value, field=None):
    if isinstance(value, list):
        value = ", ".join(map(str, value))
    if field in ("source", "interface"):
        val = str(value).lower()
        if val in INTERFACE_MAP:
            return INTERFACE_MAP[val]
    if str(field) in "destination_port":
        val = str(value)
        if val in PORT_MAP:
            return PORT_MAP[val]
    if str(field) in "destination":
        val = str(value).lower()
        if val in NET_MAP:
            return NET_MAP[val]
    if str(field) in "destination":
        val = str(value).lower()
        if val in ADDRESS_MAP:
            return ADDRESS_MAP[val]
    return value


def normalize_ports(port_field):
    if not port_field:
        return "Any"
    return re.sub(r'\s+', '', port_field.strip()) or "Any"


def parse_csv_and_generate(csv_path, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    flows_by_gateway = OrderedDict()
    next_id = 0

    def get_node(nodes_local, key, label=None, color=None, force_unique=False):
        """Creates or retrieves a node factorized by cluster/source unless force_unique."""
        nonlocal next_id
        actual_key = f"{key}__{next_id}" if force_unique else key
        if actual_key not in nodes_local:
            nodes_local[actual_key] = (f"node{next_id}", color, label if label else key)
            next_id += 1
        return nodes_local[actual_key][0]

    def get_action_color(action):
        return "#a3f7a3" if action == "PASS" else "#f7a3a3" if action == "BLOCK" else None

    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            source = (row.get("SOURCE") or "").strip()
            # GATEWAY
            gateway = (row.get("GATEWAY") or "").strip()
            action = (row.get("ACTION") or "").strip().upper()
            # PROTOCOL
            protocol = (row.get("PROTOCOL") or "").strip() or "Any"
            ports = normalize_ports(row.get("PORT"))
            destination = (row.get("DESTINATION") or "").strip()
            # COMMENT
            comment = (row.get("COMMENT") or "").strip()

            source_label = f"SOURCE | {source}" if source else "SOURCE | <unknown>"
            gateway_label = f"GATEWAY | {gateway}" if gateway else "GATEWAY | <unknown>"
            action_label = f"ACTION | {action}" if action else "ACTION | <unknown>"
            proto_label = f"PROTOCOL | {protocol}"
            port_label = f"PORT | {ports}"
            # Using 'comment' in the label
            destination_label = f"{destination} | {comment}" if comment else f" VLAN | {destination}" or "<unknown>"

            # --- Initialization cluster/source ---
            if gateway not in flows_by_gateway:
                flows_by_gateway[gateway] = OrderedDict()
            if source not in flows_by_gateway[gateway]:
                flows_by_gateway[gateway][source] = {"nodes": OrderedDict(), "edges": set()}

            cluster = flows_by_gateway[gateway][source]

            # --- Node Creation ---
            n_source = get_node(cluster["nodes"], source_label)
            n_pass = get_node(cluster["nodes"], gateway_label)
            n_action = get_node(cluster["nodes"], action_label, color=get_action_color(action))
            proto_key = f"{protocol}|{action}"
            n_proto = get_node(cluster["nodes"], proto_key, label=proto_label)
            port_key = f"{ports}|{proto_key}"
            n_port = get_node(cluster["nodes"], port_key, label=port_label)
            if "Floating-rules" in gateway:
                n_destination = get_node(cluster["nodes"], destination_label)
            else:
                n_destination = get_node(cluster["nodes"], destination_label,
                                         force_unique=True)  # DESTINATION not factorized

            edges = [
                (n_source, n_pass),
                (n_pass, n_action),
                (n_action, n_proto),
                (n_proto, n_port),
                (n_port, n_destination),
            ]

            cluster["edges"].update(edges)

    # --- Graph Generation ---
    for gateway, sources in flows_by_gateway.items():
        filename = os.path.join(output_dir, f"{gateway.replace('/', '_')}.gv")
        g = Digraph('g', filename=filename, format='png')
        g.attr(fontname="Helvetica,Arial,sans-serif")
        g.attr("node", fontname="Helvetica,Arial,sans-serif", fontsize="11", shape="record")
        g.attr("edge", fontname="Helvetica,Arial,sans-serif")
        g.attr(rankdir="LR")
        g.attr(label=f"GATEWAY : {gateway}", labelloc="t", fontsize="14", color="#8888ff")

        for source, cluster in sources.items():
            with g.subgraph(name=f"cluster_{source.replace(' ', '_')}") as sg:
                sg.attr(label=f"SOURCE : {source}", style="dashed", color="#aaaaaa")
                for nid, color, label in cluster["nodes"].values():
                    sg.node(nid, label=label, shape="record",
                            **({"style": "filled", "fillcolor": color} if color else {}))
                for src, dst in cluster["edges"]:
                    sg.edge(src, dst)
        output_path = g.render(view=False)

        # Deletion of the temporary .gv file after rendering
        try:
            if os.path.exists(filename):
                os.remove(filename)
                print(f"🗑️  Temporary file deleted: {filename}")
        except Exception as e:
            print(f"⚠️  Unable to delete {filename}: {e}")

        print(f"✅ Graph generated: {filename}.png")

    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.utils import ImageReader

        # Retrieval of PNGs
        png_files = sorted(glob.glob(os.path.join(output_dir, "*.png")))
        if not png_files:
            print("⚠️ No PNG file found for the PDF.")
            return

        # PDF creation
        pdf_path = os.path.join(output_dir, GATEWAY + "_FLOW_MATRIX.pdf")

        c = canvas.Canvas(pdf_path, pagesize=A4)
        width, height = A4

        c.setTitle(f"Flow matrix for gateway {GATEWAY} ")

        for i, png in enumerate(png_files):
            # --- Title / chapter = file name ---
            page_title = os.path.basename(png).replace(".gv.png", "")

            # Adding PDF bookmark
            c.bookmarkPage(page_title)
            c.addOutlineEntry(page_title, page_title, level=0)

            # Image loading
            img = ImageReader(png)
            img_width, img_height = img.getSize()

            # Automatic scaling
            scale = min(width / img_width, height / img_height)
            new_width = img_width * scale
            new_height = img_height * scale

            # Centering
            x = (width - new_width) / 2
            y = (height - new_height) / 2

            # Drawing
            c.drawImage(img, x, y, width=new_width, height=new_height)

            c.showPage()

        c.save()
        print(f"📄 PDF with chapters generated: {pdf_path}")

        try:
            for png in png_files:
                if os.path.exists(png):
                    os.remove(png)
                    print(f"🗑️  PNG deleted: {png}")
        except Exception as e:
            print(f"⚠️  Unable to delete some PNGs: {e}")

    except Exception as e:
        print(f"⚠️ Error during PDF generation: {e}")


# --- DATA EXTRACTION ---
with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(
        f,
        # PROTOCOL and COMMENT are translated here
        fieldnames=["SOURCE", "GATEWAY", "ACTION", "PROTOCOL", "PORT", "DESTINATION", "COMMENT"]
    )
    # → Write the header once
    writer.writeheader()

    # Loop over interfaces
    for interface in INTERFACES:
        params = {
            "interface": interface,
            "show_all": "1"
        }

        data = retrieve_rules(OPNS_URL, OPNS_SECRET, OPNS_KEY, params)
        entries = data.get("rows", [])

        # Writing entries
        for entry in entries:
            source_val = (
                    entry.get('source', {}).get('network')
                    or entry.get('source', {}).get('address')
                    or entry.get('source_net')
                    or entry.get('source', {}).get('any')
            )
            destination_val = (
                    entry.get('destination', {}).get('network')
                    or entry.get('destination', {}).get('address')
                    or entry.get('destination', {}).get('any')
                    or entry.get("destination_net")
            )
            port_dest_val = (
                    entry.get('destination', {}).get('port')
                    or entry.get("destination_port")
            )
            writer.writerow({
                "SOURCE": safe_value(source_val, "source"),
                "GATEWAY": GATEWAY + "/" + safe_value(entry.get("interface"), "interface")
                if entry.get("interface")
                # Floating-rules
                else GATEWAY + "/Floating-rules",
                "ACTION": safe_value(entry.get("action")),
                "PROTOCOL": safe_value(entry.get("protocol")),
                "PORT": safe_value(port_dest_val, "destination_port"),
                "DESTINATION": safe_value(destination_val, "destination"),
                "COMMENT": safe_value(entry.get("description"))
            })

# Retrieval of the previous md5sum
with open("md5sum.txt", "r") as f:
    # .strip() removes newlines
    prev_md5sum = f.readline().strip()
# Generation of the md5sum of the generated csv file
# Calculate md5sum
actual_md5sum = calculate_md5sum(CSV_FILE)

# Comparison of md5sums.
# If different => generation of the matrix.
# If identical => script stops.
if prev_md5sum != actual_md5sum:
    with open("md5sum.txt", "w") as f:
        f.write(actual_md5sum + "\n")
    parse_csv_and_generate(CSV_FILE, GRAPH_OUTPUT_DIR)
else:
    logging.info("No rules created or modified")

if os.path.exists(CSV_FILE):
    os.remove(CSV_FILE)
