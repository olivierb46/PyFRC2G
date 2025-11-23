import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import re
from collections import OrderedDict
from graphviz import Digraph
import os
import glob
import csv
import logging
import shutil
from config import INTERFACE_MAP, NET_MAP, ADDRESS_MAP, PORT_MAP
import hashlib

logging.basicConfig(level=logging.INFO)

# --- CONFIG ---
# pfSense
PFS_URL = "https://PFS_ADDRESS/api/v2/firewall/rules"
PFS_TOKEN = "<API_TOKEN>"
PASSERELLE = "<GW_NAME>"
FICHIER_CSV = "output_"+PASSERELLE+".csv"
GRAPH_OUTPUT_DIR = "tmp/graphs_"+PASSERELLE
# CISO Assistant
CISO_URL = "https://<CISO_ASSISTANT_ADDRESS>"
CISO_TOKEN = "<CISO_ASSISTANT_TOKEN>"
CISO_EVIDENCE_PATH = f"{CISO_URL}/api/evidence-revisions/"
CISO_FORLDER_ID = "<CISO_FORLDER_ID>"
CISO_EVIDENCE_ID = "<CISO_EVIDENCE_ID>"


def md5sum(path):
    md5 = hashlib.md5()
    with open(path, "rb") as f:
        # Lire le fichier par blocs pour éviter de saturer la mémoire
        for chunk in iter(lambda: f.read(4096), b""):
            md5.update(chunk)
    return md5.hexdigest()

def recup_regles(url, token):
    try:
        headers = {"accept": "application/json", "X-API-Key": token}
        reponse = requests.get(url, headers=headers, verify=False)
        return reponse.json()
    except ValueError:
        print("Échec de la connexion:", reponse.status_code, reponse.text)
        exit()

def safe_value(value, field=None):
    if value is None:
        return "Any"
    if isinstance(value, list):
        value = ", ".join(map(str, value))
    if field in ("source", "interface"):
        val = str(value).lower()
        if val in INTERFACE_MAP:
            return INTERFACE_MAP[val]
    if str(field) in ("destination_port"):
        val = str(value)
        if val in PORT_MAP:
            return PORT_MAP[val]
    if str(field) in ("destination"):
        val = str(value).lower()
        if val in NET_MAP:
            return NET_MAP[val]
    if str(field) in ("destination"):
        val = str(value).lower()
        if val in ADDRESS_MAP:
            return ADDRESS_MAP[val]
    return value

def normalize_ports(port_field):
    if not port_field:
        return "Any"
    return re.sub(r'\s+', '', port_field.strip()) or "Any"

def export_to_ciso(url, token, folder, evidence, fichier):
    upload_headers = {
        'Authorization': f'Token {token}',
        'Accept': 'application/json',
    }
    data = {
        "is_published": True,
        "observation": "Preuve générée automatiquement",
        "folder": folder,
        "evidence": evidence
    }
    # IMPORTANT : "attachment" doit correspondre au champ attendu par l'API
    with open(fichier, 'rb') as file:
        files = {
            "attachment": (fichier.split("/")[-1], file, "application/pdf")
        }
        response = requests.post(
            url,
            headers=upload_headers,
            data=data,
            files=files,
            verify=False
        )
    if response.status_code in (200, 201):
        logging.info("Export vers Ciso réussi.")
        return True
    else:
        logging.error(f"Échec : {response.status_code} -> {response.text}")
        return False

def parse_csv_and_generate(csv_path, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    flux_par_passerelle = OrderedDict()
    next_id = 0

    def get_node(nodes_local, key, label=None, color=None, force_unique=False):
        """Crée ou récupère un nœud factorisé par cluster/source sauf si force_unique."""
        nonlocal next_id
        actual_key = f"{key}__{next_id}" if force_unique else key
        if actual_key not in nodes_local:
            nodes_local[actual_key] = (f"node{next_id}", color, label if label else key)
            next_id += 1
        return nodes_local[actual_key][0]

    def get_action_color(action):
        return "#a3f7a3" if action == "PASS" else "#f7a3a3" if action == "BLOCK" else None

    def get_destination_color(disabled):
        return "#ffcc00" if disabled == "True" else None

    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            floating = (row.get("FLOTTANT") or "").strip()
            source = (row.get("SOURCE") or "").strip()
            if floating == "False":
                passerelle = (row.get("PASSERELLE") or "").strip()
            else:
                passerelle = "Règles flottantes"
            action = (row.get("ACTION") or "").strip().upper()
            protocole = (row.get("PROTOCOLE") or "").strip() or "Any"
            ports = normalize_ports(row.get("PORT"))
            destination = (row.get("DESTINATION") or "").strip()
            descr = (row.get("COMMENTAIRE") or "").strip()
            disabled = (row.get("DESACTIVE") or "").strip()

            source_label = f"SOURCE | {source}" if source else "SOURCE | <inconnu>"
            passerelle_label = f"PASSERELLE | {passerelle}" if passerelle else "PASSERELLE | <inconnu>"
            action_label = f"ACTION | {action}" if action else "ACTION | <inconnu>"
            proto_label = f"PROTOCOLE | {protocole}"
            port_label = f"PORT | {ports}"
            if disabled == "False":
                destination_label = f"{destination} | {descr}" if descr else f" VLAN | {destination}" or "<inconnu>"
            else:
                destination_label = f"{destination} | {descr} | Règle désactivée" if descr else f" VLAN | {destination} | Règle désactivée" or "<inconnu>"

            # --- Initialisation cluster/source ---
            if passerelle not in flux_par_passerelle:
                flux_par_passerelle[passerelle] = OrderedDict()
            if source not in flux_par_passerelle[passerelle]:
                flux_par_passerelle[passerelle][source] = {"nodes": OrderedDict(), "edges": set()}

            cluster = flux_par_passerelle[passerelle][source]

            # --- Création des nœuds ---
            n_source = get_node(cluster["nodes"], source_label)
            n_pass = get_node(cluster["nodes"], passerelle_label)
            n_action = get_node(cluster["nodes"], action_label, color=get_action_color(action))
            proto_key = f"{protocole}|{action}"
            n_proto = get_node(cluster["nodes"], proto_key, label=proto_label)
            port_key = f"{ports}|{proto_key}"
            n_port = get_node(cluster["nodes"], port_key, label=port_label)
            n_destination = get_node(cluster["nodes"], destination_label, force_unique=True, color=get_destination_color(disabled))  # DESTINATION non factorisée
                
            edges = [
                (n_source, n_pass),
                (n_pass, n_action),
                (n_action, n_proto),
                (n_proto, n_port),
                (n_port, n_destination),
            ]

            cluster["edges"].update(edges)

    # --- Génération des graphes ---
    for passerelle, sources in flux_par_passerelle.items():
        filename = os.path.join(output_dir, f"{passerelle.replace('/', '_')}.gv")
        g = Digraph('g', filename=filename, format='png')
        g.attr(fontname="Helvetica,Arial,sans-serif")
        g.attr("node", fontname="Helvetica,Arial,sans-serif", fontsize="11", shape="record")
        g.attr("edge", fontname="Helvetica,Arial,sans-serif")
        g.attr(rankdir="LR")
        g.attr(label=f"<<b>PASSERELLE : {passerelle} INTERFACE</b>>", labelloc="t", fontsize="14", color="#8888ff")

        for source, cluster in sources.items():
            with g.subgraph(name=f"cluster_{source.replace(' ', '_')}") as sg:
                sg.attr(label=f"SOURCE : {source}", style="dashed", color="#aaaaaa")
                for nid, color, label in cluster["nodes"].values():
                    sg.node(nid, label=label, shape="record", **({"style":"filled","fillcolor":color} if color else {}))
                for src, dst in cluster["edges"]:
                    sg.edge(src, dst)

        output_path = g.render(view=False)
        # Suppression du fichier .gv après rendu
        try:
            if os.path.exists(filename):
                os.remove(filename)
                print(f"🗑️  Fichier temporaire supprimé : {filename}")
        except Exception as e:
            print(f"⚠️  Impossible de supprimer {filename} : {e}")

        print(f"✅ Graph généré : {filename}.png")
    
    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.utils import ImageReader

        # Récupération des PNG
        png_files = sorted(glob.glob(os.path.join(output_dir, "*.png")))
        if not png_files:
            print("⚠️ Aucun fichier PNG trouvé pour le PDF.")
            return

        pdf_path = os.path.join(output_dir, PASSERELLE+"_MATRICE_DES_FLUX.pdf")

        # Création PDF
        c = canvas.Canvas(pdf_path, pagesize=A4)
        width, height = A4

        c.setTitle(f"Matrice des flux de la passerelle {PASSERELLE} ")

        for i, png in enumerate(png_files):
            # --- Titre / chapitre = nom du fichier ---
            titre_page = os.path.basename(png).replace(".gv.png", "")

            # Ajout du signet PDF
            c.bookmarkPage(titre_page)
            c.addOutlineEntry(titre_page, titre_page, level=0)

            # Chargement de l'image
            img = ImageReader(png)
            img_width, img_height = img.getSize()

            # Mise à l’échelle automatique
            scale = min(width / img_width, height / img_height)
            new_width = img_width * scale
            new_height = img_height * scale

            # Centrage
            x = (width - new_width) / 2
            y = (height - new_height) / 2

            # Dessin
            c.drawImage(img, x, y, width=new_width, height=new_height)

            c.showPage()

        c.save()
        print(f"📄 PDF avec chapitres généré : {pdf_path}")

        # Suppression des fichiers PNG
        try:
            for png in png_files:
                if os.path.exists(png):
                    os.remove(png)
                    print(f"🗑️  PNG supprimé : {png}")
        except Exception as e:
            print(f"⚠️  Impossible de supprimer certains PNG : {e}")

    except Exception as e:
        print(f"⚠️ Erreur lors de la génération du PDF : {e}")

    if not export_to_ciso(CISO_EVIDENCE_PATH, CISO_TOKEN, CISO_FORLDER_ID, CISO_EVIDENCE_ID, pdf_path):
        logging.error("Échec de l'exportation dans Ciso.")
        return

# --- EXTRACTION DES DONNÉES ---
data = recup_regles(PFS_URL, PFS_TOKEN)
entries = data.get("data", [])

if entries:
    # --- CRÉATION DU CSV ---
    with open(FICHIER_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["SOURCE", "PASSERELLE", "ACTION", "PROTOCOLE", "PORT", "DESTINATION", "COMMENTAIRE","DESACTIVE","FLOTTANT"]
        )
        writer.writeheader()
        for entry in entries:
            writer.writerow({
                "SOURCE": safe_value(entry.get("source"), "source"),
                "PASSERELLE": "PFS01/"+safe_value(entry.get("interface"), "interface"),
                "ACTION": safe_value(entry.get("type")),
                "PROTOCOLE": safe_value(entry.get("protocol")),
                "PORT": safe_value(entry.get("destination_port"), "destination_port"),
                "DESTINATION": safe_value(entry.get("destination"), "destination"),
                "COMMENTAIRE": safe_value(entry.get("descr")),
                "DESACTIVE": safe_value(entry.get("disabled")),
                "FLOTTANT": safe_value(entry.get("floating"))
            })
    
    # Récupération de la précédente somme md5sum
    with open("md5sum.txt", "r") as f:
        prev_md5sum = f.readline().strip()  # .strip() enlève les retours à la ligne
    # Génération de la somme md5sum du fichier csv généré
    actual_md5sum = md5sum(FICHIER_CSV)

    # Comparaison des sommes md5sum. 
    # Si différentes => génération de la matrice.
    # Si identique => arrêt du script.
    if prev_md5sum != actual_md5sum:
        with open("md5sum.txt", "w") as f:
            f.write(actual_md5sum + "\n")
        parse_csv_and_generate(FICHIER_CSV,GRAPH_OUTPUT_DIR)
    else:
        logging.info("Pas de règles crées ou modifiées")
else:
    logging.info("Le script n'a récupéré aucune règle firewall")

if os.path.exists(FICHIER_CSV):
    os.remove(FICHIER_CSV)