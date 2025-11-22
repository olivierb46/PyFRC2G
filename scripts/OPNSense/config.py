# --- TABLE DE CORRESPONDANCE POUR LES INTERFACES ---
INTERFACE_MAP = {
    "wan": "WAN",
    "lan": "LAN",
    "opt1": "DMZ01",
    "(self)": "All interfaces",
    "(em0)": "WAN",
    "1": "Any",
    "<sshlockout>": "IP bannies après trop de tentatives SSH/Console Web",
    "<virusprot>": "IP bannies après comportement suspect"
}

# --- TABLE DE CORRESPONDANCE POUR LES RESEAUX ---
NET_MAP = {
    "wan": "WAN SUBNET",
    "lan": "LAN SUBNET",
    "opt1": "DMZ01 SUBNET",
    "(self)": "All interfaces",
    "1": "Any"
}

# --- TABLE DE CORRESPONDANCE POUR LES NOMS DES ADRESSES ---
ADDRESS_MAP = {
    "wanip": "WAN ADDRESS",
    "lanip": "LAN ADDRESS",
    "opt1ip": "DMZ01 ADDRESS"
}

# --- SI UTILISATION D'ALIAS POUR LES PORTS ---
PORT_MAP = {
    "WEB_ACCESS": "80/443"
}