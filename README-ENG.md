# PyFRC2G

Python scripts to convert PfSense and OPNSense firewall rules into a graphical view of the flows.

![pfsense](./img/convert-rules-to-graph.png)
![opnsense](./img/opnsense.png)

## 👋 Overview

This script was written to meet two objectives:

* Provide a global graphical view of firewall rules (a picture is worth a thousand words).
* Provide evidence to meet IT security requirements defined in various compliance frameworks.

## ⚡ Features

* Script based on Python (developed and tested on GNU/Linux).
* Uses pfSense's API provided by the pfSense REST API Package.
* Uses OPNSense's built-in API.
* Generates graphical flows with the Graphviz Python library.
* Produces an A4 PDF file with one page per interface.
* Distinguishes between a destination VLAN/network and a destination host.
* Mapping of interfaces, ports, and destinations.
* Color coding for PASS and BLOCK actions.
* Color coding for rules that exist but are disabled (pfSense only).
* Option to export the generated PDF to the associated evidence record in [CISO Assistant](https://intuitem.com/ciso-assistant/) as a revision to keep the history of uploaded files.

## 💾 Installation

1. Prerequisites

Install the required Python libraries:

```Bash
pip install requests graphviz reportlab
```

2. pfSense

Install **pfSense REST API Package**: [https://github.com/jaredhendrickson13/pfsense-api?tab=readme-ov-file#quickstart](https://github.com/jaredhendrickson13/pfsense-api?tab=readme-ov-file#quickstart)

Once the **pfSense REST API** package is installed, configure the listening interface(s) on **pfSense**, then generate a key that will be used for API authentication.

3. Script configuration

Download the **pyfrc2g.py**, **config.py** and **md5sum.txt** files corresponding to your gateway (pfSense or OPNSense).

Configure the **URL** of your gateway and your **credentials** in the **pyfrc2g.py** file.

Example with pfSense:
```python
# --- CONFIG ---
PFS_URL = "https://pfs01.domaine.lan/api/v2/firewall/rules"
PFS_TOKEN = "YOUR_KEY_GENERATED_WITH_PFSENSE_REST_API"
PASSERELLE = "PFS01"
```

For **OPNSense**, you also need to specify the interface names because the API does not allow retrieving rules per interface (they are displayed under Interfaces > Assignments).

Example with OPNSense:
```python
OPNS_URL = "https://<OPNS_ADDRESS>/api/firewall/filter/search_rule"
OPNS_SECRET = "<API_SECRET>"
OPNS_KEY = "<API_KEY>"
PASSERELLE = "<GW_NAME>"
(...)
# Declare the interfaces present on OPNSense
INTERFACES = ["wan", "lan", "opt1"]
```

Then configure your interfaces, networks, interface addresses, and ports in the **config.py** file.

Example with pfSense:
```python
INTERFACE_MAP = {
    "wan": "WAN",
    "lan": "ADMINISTRATION",
    "opt1": "LAN",
    "opt2": "DMZ"
}

NET_MAP = {
    "wan": "WAN SUBNET",
    "lan": "ADMINISTRATION SUBNET",
    "opt1": "LAN SUBNET",
    "opt2": "DMZ SUBNET"
}

ADDRESS_MAP = {
    "wan:ip": "WAN ADDRESS",
    "lan:ip": "ADMINISTRATION ADDRESS",
    "opt1:ip": "LAN ADDRESS",
    "opt2:ip": "DMZ ADDRESS"
}

PORT_MAP = {
    "WEB_ACCESS": "80/443"
}
```

For OPNSense, things work a bit differently. For example, in pfSense, when a rule is destined for all networks, it is shown as "destination: Any". In OPNSense it appears as:
```
Destination:
  any: 1
```

Therefore, I declared "1": "Any" in config.py so that Any appears in the source and destination fields on the graphical flow.
```python
# --- INTERFACE MAPPING TABLE ---
INTERFACE_MAP = {
    "wan": "WAN",
    "lan": "LAN",
    "opt1": "DMZ01",
    "(self)": "All interfaces",
    "(em0)": "WAN",
    "1": "Any",
    "<sshlockout>": "IPs banned after too many SSH/Web Console attempts",
    "<virusprot>": "IPs banned after suspicious behavior"
}

# --- NETWORK MAPPING TABLE ---
NET_MAP = {
    "wan": "WAN SUBNET",
    "lan": "LAN SUBNET",
    "opt1": "DMZ01 SUBNET",
    "(self)": "All interfaces",
    "1": "Any"
}
(...)
```

## 🚀 Usage

1. Basic usage

Run the **pyfrc2g.py** script. It will generate a final PDF file (after creating several intermediate files which are deleted once execution finishes). Each page is named with the gateway and interface to make navigation easier.

If no rule has been added or modified, the script does not regenerate the PDF (the script compares the md5sum between the previous CSV version and the current one). You can reset the `md5sum.txt` file with the command `echo > md5sum.txt`

2. Usage with CISO Assistant

Download the **pyfrc2g-ciso_assist.py**, **config.py**, and **md5sum.txt** files corresponding to your gateway (pfSense or OPNSense).

Configure the gateway access settings as described earlier, then fill in the CISO Assistant section:
```python
# CISO Assistant
CISO_URL = "https://<CISO_ASSISTANT_ADDRESS>"
CISO_TOKEN = "<CISO_ASSISTANT_TOKEN>"
CISO_EVIDENCE = f"{CISO_URL}/api/evidences/<EVIDENCE_ID>/upload/"
```

3. Notes

* When retrieving destination hosts, the pfSense API does not indicate which network the host belongs to. Therefore, I added comments for destination hosts in pfSense specifying which VLAN they belong to.
* For destination hosts outside my internal infrastructure, I prefixed each alias name in pfSense with EXT_.
* OPNSense exposes rules through its API in a completely different way than pfSense. As of today, I have not found a way to retrieve disabled rules. Auto-generated floating rules are also not easy to retrieve.

## 📝 Todo

* Improve the code (I’m not a developer and it shows).
* Automate the script so that graphs are regenerated only for changed rules.
* Notify admins when graphs are generated.
* Add the destination VLAN before a destination host.
* ~~Do the same for OPNSense.~~
* ~~Send evidence to CISO Assistant~~
* Retrieve timestamps and authors for rule creation/modification.
