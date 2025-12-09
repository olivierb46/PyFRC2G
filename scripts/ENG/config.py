# --- INTERFACE MAPPING TABLE ---
INTERFACE_MAP = {
    "wan": "WAN",
    "lan": "LAN",
    "opt1": "SERVER",
    "opt2": "UPSTAIRS",
    "(self)": "All interfaces",
    "(em0)": "WAN",
    "1": "Any",
    "<sshlockout>": "IPs banned after too many SSH/Web Console attempts",
    "<virusprot>": "IPs banned after suspicious behavior"
}

# --- NETWORK MAPPING TABLE  <---------------------- Check the number of interfaces on your router.
NET_MAP = {
    "wan": "<SUBNET NAME>",  # <----------------------
    "lan": "<SUBNET NAME>",  # <----------------------
    "opt1": "<SUBNET NAME>",  # <----------------------
    "opt2": "<SUBNET NAME>",  # <----------------------
    "(self)": "All interfaces",  # <----------------------
    "1": "Any"
}

# --- ADDRESSES MAPPING TABLE---
ADDRESS_MAP = {
    "wanip": "<WAN ADDRESS>",  # <----------------------
    "lanip": "<LAN ADDRESS>",  # <----------------------
    "opt1ip": "<SERVER ADDRESS>",  # <----------------------
    "opt2ip": "<UPSTAIRS ADDRESS>",  # <----------------------
    "(self)": "All interfaces",
    "1": "Any"
}

# --- PORT MAP ---
PORT_MAP = {
    "WEB_ACCESS": "80/443"
}
