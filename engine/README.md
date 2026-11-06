# PyFRC2G - Unified Firewall Rules to Graph Converter

Unified Python package to convert **pfSense** and **OPNSense** firewall rules into graphical flow diagrams.

![pfSense Example](./img/convert-rules-to-graph.png)
![OPNSense Example](./img/opnsense.png)

**Quick start:** Configure `pyfrc2g/config.py` then run `pyfrc2g` or `python -m pyfrc2g` (API mode), or run `pyfrc2g --backup config.xml` to use an XML backup without API config.

## 👋 Overview

PyFRC2G was designed to meet two main objectives:

* **Visual Documentation**: Provide a global graphical view of firewall rules (a picture is worth a thousand words)
* **Compliance Evidence**: Provide evidence to meet IT security requirements defined in various compliance frameworks

## ⚡ Features

### Core Features

* **Two Input Modes**: Fetch rules via **API** (pfSense/OPNSense) or read from **XML backup** (config.xml)
* **Unified Support**: Single package for both pfSense and OPNSense
* **Automatic Interface Detection**: Auto-detects all available interfaces for OPNSense
* **API-Based Alias Mapping**: Retrieves all aliases from firewall API or from the backup XML
* **Per-Interface Output**: Generates separate CSV and PDF files for each interface
* **Several Firewalls per Run**: `FIREWALLS` list in the config (API) or several `--backup` files
* **NAT Port Forwards**: Included in the PDF, HTML and Excel reports (`--no-nat` to skip)
* **Change Report**: Rules added / modified / removed since the previous run (CSV, PDF, HTML, Excel), with history of previous snapshots
* **Risk Detection (audit)**: any-to-any rules, admin/sensitive ports exposed on the WAN, shadowed or redundant rules, disabled rules, rules without description
* **Exports**: self-contained filterable HTML report and Excel workbook, in addition to PDF/CSV
* **Smart Change Detection**: Only regenerates outputs when rules have changed (SHA-256 fingerprint, `--force` to override)
* **Configuration Check**: Validates `pyfrc2g/config.py` before API mode (optional bypass with `--skip-config-check`)
* **Modular Architecture**: Clean, maintainable, and extensible codebase

### Technical Features

* **Graphical Flows**: Generates visual flow diagrams using Graphviz
* **Vector PDF**: Graphs rendered directly to PDF (sharp at any zoom, searchable text); `--raster` for the former PNG-on-A4 layout
* **Summary Page**: First page of each PDF with metadata, fingerprints, rules per interface/action, audit and change counts
* **Zones View**: Network-centric graph (source zone → destination zone, aggregated services), in addition to the per-rule view
* **Color Coding**: 
  - 🟢 Green for PASS rules
  - 🔴 Red for BLOCK rules
  - 🟡 Yellow for disabled rules
* **Network Mapping**: Distinguishes between VLANs/networks and destination hosts
* **Comprehensive Coverage**: Handles floating rules, disabled rules, and all interface types
* **CISO Assistant Integration**: Optional automatic upload of PDFs to CISO Assistant as evidence revisions

## 📋 Prerequisites

### Python Requirements

- Python 3.8 or higher
- Required packages (see Installation)

### System Requirements

- **Graphviz**: Must be installed on your system
  - **Windows**: Download from [Graphviz website](https://graphviz.org/download/)
  - **Linux**: `sudo apt-get install graphviz` (Debian/Ubuntu) or `sudo yum install graphviz` (RHEL/CentOS)
  - **macOS**: `brew install graphviz`

### Firewall API Setup

#### pfSense

1. Install **pfSense REST API Package**: [pfSense REST API Documentation](https://github.com/jaredhendrickson13/pfsense-api?tab=readme-ov-file#quickstart)
2. Configure the listening interface(s) on pfSense
3. Generate an API key for authentication

#### OPNSense

1. Create API credentials in OPNSense:
   - Go to **System > Access > Users**
   - Create or edit a user
   - Generate API key and secret in **API Keys** section

## 💾 Installation

### Option 1: Install as Package (Recommended)

```bash
# Clone the repository
git clone https://github.com/olivierb46/PyFRC2G.git
cd PyFRC2G

# Install setuptools (required by setup.py)
pip install setuptools

# Install in development mode
pip install -e .

# Or install directly
pip install .
```

### Option 2: Direct Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Use the script directly
pyfrc2g
```

## ⚙️ Configuration

Configuration is required only for **API mode**. When using `--backup`, no API config is needed.

### 1. Edit Configuration File

Edit `pyfrc2g/config.py` to configure your gateway:

#### For pfSense:

```python
GATEWAY_TYPE = "pfsense"

PFS_BASE_URL = "https://pfs01.domain.lan"
PFS_TOKEN = "YOUR_API_KEY_GENERATED_WITH_PFSENSE_REST_API"

GATEWAY_NAME = "PFS01"
```

#### For OPNSense:

```python
GATEWAY_TYPE = "opnsense"

# OPNSense Configuration
OPNS_BASE_URL = "https://opnsense.domain.lan"
OPNS_KEY = "YOUR_API_KEY"
OPNS_SECRET = "YOUR_API_SECRET"

# Option 1: Auto-detection (recommended)
INTERFACES = []  # Leave empty for automatic detection

# Option 2: Manual specification
INTERFACES = ["wan", "lan", "opt1", "opt2"]

GATEWAY_NAME = "OPNS01"  # Display name for gateway (used in labels)
```

#### Several firewalls

To process several firewalls in one run (API mode), fill the `FIREWALLS` list. When it is
non-empty, it replaces the single-firewall variables above:

```python
FIREWALLS = [
    {"name": "fw-paris", "type": "pfsense", "url": "https://10.0.0.1", "token": "..."},
    {"name": "fw-lyon", "type": "opnsense", "url": "https://10.1.0.1",
     "key": "...", "secret": "...", "interfaces": ["lan", "opt1"]},
]
```

Optional per-firewall key: `ciso_evidence_id` (upload to a specific CISO Assistant evidence).
Each firewall is processed independently: a failure on one does not stop the others.

#### Audit settings

```python
WAN_INTERFACES = ["wan"]          # Internet-facing interfaces (ids or descriptions)
ADMIN_PORTS = [22, 23, 80, 443, 161, 3389, 5900, 8080, 8443, 10443]
SENSITIVE_PORTS = [135, 139, 445, 1433, 1521, 2049, 3306, 5432, 6379, 9200, 11211, 27017]
```

### 2. Configuration Check (API Mode)

Before running in API mode, the tool checks for each firewall that the URL and credentials (`token` for pfSense, `key`/`secret` for OPNSense) are not left as placeholders. An invalid firewall is skipped with an error (exit code 2). Use `--skip-config-check` to bypass (e.g. in scripts).

### 3. CISO Assistant Integration (Optional)

If you want to automatically upload generated PDFs to CISO Assistant as evidence revisions, configure the following in `pyfrc2g/config.py`:

```python
# CISO Assistant Configuration
CISO_URL = "https://ciso-assistant.example.com"
CISO_TOKEN = "YOUR_CISO_ASSISTANT_API_TOKEN"
CISO_EVIDENCE_PATH = f"{CISO_URL}/api/evidence-revisions/"
CISO_FORLDER_ID = "<CISO_FOLDER_ID>"  # Folder ID from CISO Assistant to which the evidence is linked.
CISO_EVIDENCE_ID = "<CISO_EVIDENCE_ID>"  # Evidence ID from CISO Assistant.
```

**Note:** Leave these as default values (`<CISO_ASSISTANT_ADDRESS>`, etc.) to disable CISO Assistant integration.

### 4. Aliases (API Mode)

**In API mode, the package automatically retrieves all aliases from the firewall API:**
- Interface names and descriptions
- Network aliases
- Address aliases
- Port aliases

No manual alias mapping is required. In **backup mode**, aliases are read from the XML file.

## 🚀 Usage

### Command-Line Options (argparse)

| Option | Short | Description |
|--------|-------|-------------|
| `--api` | `-a` | Fetch rules from firewall API (default if no mode) |
| `--backup FILE [FILE ...]` | `-b` | Read rules from one or several XML backups (pfSense or OPNSense config.xml) |
| `--gateway-name NAME` | `-g` | Gateway display name (single firewall/backup only) |
| `--output-dir DIR` | `-o` | Base output directory (default `results`); files go to `DIR/<gateway>/` |
| `--force` | `-f` | Regenerate outputs even if no rule changed |
| `--interfaces LIST` | `-i` | Only these interfaces, e.g. `lan,opt1` (floating rules are kept) |
| `--view {all,rules,zones}` | | Graphs to include (default `all`) |
| `--raster` | | PNG graphs on A4 pages instead of vector PDF |
| `--no-nat` | | Do not include NAT port forwards |
| `--skip-config-check` | | Skip configuration check before API mode |
| `--check-deps` | | Check that required Python packages are installed |
| `--debug` | `-d` | Enable debug logging |
| `--verbose` | `-v` | Verbose output (same as --debug) |

### Basic Usage

#### Mode API (default)

Configure `pyfrc2g/config.py`, then run:

```bash
pyfrc2g
# or explicitly
pyfrc2g --api
```

Before running, a **configuration check** ensures that API URL and credentials are set. If the config is still using placeholders, the tool exits with a clear message. Use `--backup` to work without API config, or `--skip-config-check` to bypass (not recommended).

#### Mode XML Backup

Use a pfSense or OPNSense backup file (e.g. from Diagnostics > Backup & Restore). No API config needed.

```bash
pyfrc2g --backup config-backup.xml

# Optional: set gateway name (otherwise derived from filename)
pyfrc2g --backup config-backup.xml --gateway-name my-firewall
```

The tool detects automatically whether the backup is pfSense or OPNSense and parses rules and aliases from the XML. PDFs are generated the same way as in API mode.

#### Other Examples

```bash
# Debug / verbose
pyfrc2g --api --debug
pyfrc2g --backup config.xml --verbose

# Bypass config check (e.g. in scripts)
pyfrc2g --api --skip-config-check

# Several backups, custom output directory
pyfrc2g --backup fw1.xml fw2.xml --output-dir /srv/audit

# Only LAN and OPT1, zones view only, regenerate even without change
pyfrc2g --interfaces lan,opt1 --view zones --force
```

#### As an Installed Package:

```bash
pyfrc2g
pyfrc2g --backup config.xml
```

#### As a Python Module:

```python
from pyfrc2g.main import main

# Option 1: Use the main function (same arguments as the CLI)
main(["--backup", "config.xml", "--output-dir", "out"])

# Option 2: Use components directly
from pyfrc2g.api_client import APIClient
from pyfrc2g.audit import audit_rules
from pyfrc2g.config import Config
from pyfrc2g.main import build_rule_rows

config = Config()
api_client = APIClient(config)
api_client.fetch_aliases()
rows = build_rule_rows(api_client.fetch_rules(), config)
findings = audit_rules(rows, config)
```

### What the Script Does

**Mode API**
1. Runs a configuration check (unless `--skip-config-check` or `--backup` is used)
2. Connects to your gateway (pfSense or OPNSense)
3. Fetches all aliases and firewall rules from the API
4. Auto-detects interfaces (for OPNSense, if not specified)

**Mode Backup**
1. Parses the XML backup (pfSense or OPNSense), extracts rules and aliases
2. No API call; gateway type and name come from the file or `--gateway-name`

**Common steps**
5. Normalizes rules (and NAT port forwards), optionally filtered with `--interfaces`
6. Compares with the previous run (SHA-256 fingerprint); stops here if nothing changed (unless `--force` or backup mode)
7. Builds the change report against the previous snapshot (archived in `history/`)
8. Runs the audit checks
9. Generates graphs (Graphviz) and PDFs (ReportLab + pypdf), HTML report and Excel workbook
10. Uploads the global PDF to CISO Assistant (if configured)

### Generated Files

The script generates files in `results/<GATEWAY_NAME>/` (or `--output-dir`):

#### Global Files:
- `<GATEWAY_NAME>_FLOW_MATRIX.pdf` - Summary, changes, audit, NAT, zones view, then one page per interface (with bookmarks)
- `<GATEWAY_NAME>_REPORT.html` - Self-contained report with filterable tables (rules, audit, changes, NAT)
- `<GATEWAY_NAME>_FLOW_MATRIX.xlsx` - Excel workbook (Summary, Rules, Audit, Changes, NAT sheets with filters)
- `<GATEWAY_NAME>_ALL_flows.csv` - All rules (also the snapshot used by the next change report)
- `<GATEWAY_NAME>_AUDIT.csv` - Audit findings
- `<GATEWAY_NAME>_CHANGES.csv` - Changes since the previous run (from the second run on)
- `<GATEWAY_NAME>_NAT.csv` - NAT port forwards (when present)

#### Per-Interface Files:
- `<GATEWAY_NAME>_<interface>_flows.csv` - CSV file with rules for specific interface
- `<GATEWAY_NAME>_<interface>_FLOW_MATRIX.pdf` - Summary, zones view and graph for specific interface

#### Tracking:
- `fingerprint.txt` - SHA-256 of the last generated rules + NAT (change detection)
- `history/` - Previous `_ALL_flows.csv` snapshots, timestamped

### Example Output Structure

```
results/PFS01/
├── PFS01_FLOW_MATRIX.pdf              # Global PDF
├── PFS01_REPORT.html                  # Filterable HTML report
├── PFS01_FLOW_MATRIX.xlsx             # Excel workbook
├── PFS01_ALL_flows.csv                # All rules
├── PFS01_AUDIT.csv                    # Audit findings
├── PFS01_CHANGES.csv                  # Change report
├── PFS01_NAT.csv                      # NAT port forwards
├── PFS01_WAN_FLOW_MATRIX.pdf          # WAN interface PDF
├── PFS01_WAN_flows.csv                # WAN interface CSV
├── PFS01_LAN_FLOW_MATRIX.pdf          # LAN interface PDF
├── PFS01_LAN_flows.csv                # LAN interface CSV
├── fingerprint.txt
└── history/
    └── PFS01_ALL_flows_20261105-134003.csv
```

## 📊 Output Format

### CSV Columns

The temporary and per-interface CSV files use the same columns for both pfSense and OPNsense:

| Column      | Description |
|------------|-------------|
| SOURCE     | Source network or address (mapped from API aliases when available) |
| GATEWAY    | Gateway name and interface(s), e.g. `OPNS01/wan,lan` or `OPNS01/Floating-rules` |
| ACTION     | Pass, block, reject (mapped to display value) |
| PROTOCOL   | IP layer and protocol: `IPv4 tcp`, `IPv6 udp`, `IPv4+IPv6 Any`, etc. Empty protocol is shown as `Any`. |
| PORT       | Destination port or range |
| DESTINATION| Destination network or address |
| COMMENT    | Rule description |
| DISABLED   | True / False |
| FLOATING   | True for floating rules |
| RULE ORDER | Rule order index |
| RULE ID    | Stable rule identifier (pfSense tracker / OPNsense uuid), used by the change report |

### Audit Checks

| Check | Severity | Description |
|-------|----------|-------------|
| ANY_ANY | CRITICAL / MEDIUM | Pass rule from any source to any destination (all ports / specific ports) |
| WAN_EXPOSED | CRITICAL / HIGH | Pass rule from any source on a WAN interface: firewall administration ports, admin/sensitive ports, or all ports |
| SHADOWED | MEDIUM | Rule never reached: an earlier rule on the same interface matches the same traffic with another action |
| REDUNDANT | LOW | Rule fully covered by an earlier rule with the same action |
| DISABLED | LOW | Disabled rule still present |
| NO_DESCRIPTION | LOW | Rule without description |

Shadowing analysis is conservative (string/port-range comparison, aliases are not expanded) and
skips floating rules (last-match semantics by default).

### PDF Content

The global PDF contains (each section is a bookmark):

- **Summary page**: gateway, type, source, date, SHA-256 fingerprints, rules per interface/action, audit and change counts
- **Changes**, **Audit findings** and **NAT port forwards** tables
- **Zones view**: one node per source/destination, one arrow per flow (green pass, red block, dashed disabled)
- **One page per interface** with flow diagrams
- **One page for floating rules** when applicable
- **Graphical flow diagrams** showing:
  - **Sources**: Network/host sources
  - **Gateway/Interface**: Firewall interface name
  - **Actions**: PASS (green) / BLOCK (red) with color coding
  - **Protocols**: IP protocol (e.g. IPv4 tcp, IPv6 Any)
  - **Ports**: Destination ports or port ranges
  - **Destinations**: Network/host destinations
  - **Comments**: Rule descriptions
  - **Disabled Rules**: Highlighted in yellow

## 🏗️ Project Structure

```
PyFRC2G/
├── pyfrc2g/                   # Main package
│   ├── __init__.py            # Package initialization and exports
│   ├── config.py              # Configuration management
│   ├── config_checker.py      # Configuration validation (API mode)
│   ├── api_client.py          # API client for firewalls
│   ├── xml_parser.py          # XML backup parser (pfSense/OPNSense)
│   ├── graph_generator.py     # Graphviz rendering (rules and zones views)
│   ├── reports.py             # PDF summary/tables and PDF assembly
│   ├── exports.py             # CSV, HTML and Excel exports
│   ├── audit.py               # Risk detection
│   ├── diff.py                # Change report
│   ├── nat.py                 # NAT port forward normalization
│   ├── ciso_client.py         # CISO Assistant integration
│   ├── utils.py               # Utility functions
│   └── main.py                # CLI and main execution logic
├── pyfrc2g.py                 # Compatibility launcher (python pyfrc2g.py)
├── pyproject.toml             # Build and metadata (PEP 517/621)
├── setup.py                   # Package installation (minimal; use pyproject.toml)
├── requirements.txt           # Python dependencies
├── tests/                     # pytest test suite (pip install -e ".[dev]" && pytest)
├── README.md                  # This file
└── img/                       # Example images
```

### Module Descriptions

#### `config.py`
- Configuration class and constants
- Gateway type settings (pfSense/OPNSense)
- API credentials management
- Output paths configuration

#### `config_checker.py`
- Validates each firewall target before running in API mode
- Ensures API URL and credentials are not placeholders; `--skip-config-check` to bypass

#### `api_client.py`
- `APIClient` class for firewall API interactions
- Alias retrieval (interfaces, networks, addresses, ports)
- Firewall rules retrieval
- Interface auto-detection for both pfSense and OPNSense

#### `xml_parser.py`
- Parses pfSense and OPNSense XML backup files (config.xml)
- Auto-detects backup type from root element
- Extracts rules and aliases in API-compatible format

#### `graph_generator.py`
- `GraphGenerator` class: per-rule graphs and zones graph
- Vector PDF rendering (PNG fallback / `--raster`)

#### `reports.py` / `exports.py`
- Summary page and tables (ReportLab), merge into one PDF with bookmarks (pypdf)
- Filterable HTML report, Excel workbook (openpyxl), CSV files

#### `audit.py` / `diff.py` / `nat.py`
- Risk detection on normalized rules
- Change report against the previous snapshot
- NAT port forward normalization (API and XML)

#### `utils.py`
- Utility functions (MD5, URL extraction, filename sanitization)
- Value mapping using API aliases
- Global API alias maps management

#### `main.py`
- Main execution function (API or backup mode)
- Configuration check for API mode
- Orchestrates the entire workflow
- Several firewalls / backups per run
- Change detection (SHA-256 fingerprint)
- CISO Assistant integration

#### `ciso_client.py`
- `CISOCClient` class for CISO Assistant integration
- Uploads generated PDFs as evidence revisions
- Handles authentication and error reporting

## 🔍 pfSense: Interfaces and Rules

### Automatic Interface Detection

When `INTERFACES` is empty, the package tries to detect pfSense interfaces in this order:

1. **Interfaces API (v2)** — `GET /api/v2/interfaces`; uses `id` of each enabled interface (skips `lo0`, `enc0`, `pflog0`).
2. **Fallback (v1)** — `GET /api/v1/firewall/interface`; uses the `if` field from the response.
3. **From firewall rules** — If both above fail, interfaces are extracted from the list of rules returned by the global rules API.

If detection fails, rules are still fetched globally; for per-interface CSV/PDF you can set `INTERFACES = ["wan", "lan", "opt1"]` in `pyfrc2g/config.py`.

### Rules Fetching (pfSense)

1. **Global rules** — Fetched first from the pfSense firewall rules endpoint (`data` in the response).
2. **Per-interface rules** — If interfaces were specified or detected, rules are also requested per interface (with `interface` query when supported); entries are filtered by interface so each rule appears under the correct interface.

Rule identity uses `tracker` or `id`. The same `_normalize_floating_rules` logic applies: rules with interface `floating` or no interface are tagged as floating; the GATEWAY column shows the interface list or "Floating-rules" accordingly. The API may return `interface` as a list (e.g. multiple interfaces); it is normalized for display.

### Example Logs

```
INFO:root:Attempting auto-detection of interfaces...
INFO:root:✓ 2 interfaces detected: ['wan', 'lan']
INFO:root:  → 85 global rules retrieved
INFO:root:Fetching rules for interface: wan
INFO:root:  → 24 rules found for wan
INFO:root:Fetching rules for interface: lan
INFO:root:  → 32 rules found for lan
INFO:root:✓ Total of 85 unique rules retrieved
```

## 🔍 OPNsense: Interfaces and Rules

### Automatic Interface Detection

The package attempts multiple methods to automatically detect interfaces:

1. **Interface API**: `/api/core/interfaces/listAll` or `/api/core/interfaces/list`
2. **From Firewall Rules**: Analyzes all rules to extract used interfaces
3. **Fallback**: If auto-detection fails, specify interfaces manually in `INTERFACES`

The **floating** interface is always included so that floating rules are fetched from the API.

### Rules Fetching (OPNSense)

Rules are retrieved in two steps for accurate protocol information:

1. **Global rules** — Fetched first to get the full list (with `show_all=1`).
2. **Per-interface rules** — Fetched for each interface (lan, wan, floating, etc.). When a rule already exists (same UUID), its fields (e.g. `ipprotocol`, `protocol`) are updated from the per-interface response, which often contains complete data.

Floating rules are tagged (`floating=True`, `interface=floating`). The GATEWAY column shows `Floating-rules` for floating-only rules, or the interface list (e.g. `wan,lan`) when the rule is bound to specific interfaces.

### Detection Logs

```
INFO:root:Attempting auto-detection of interfaces...
INFO:root:✓ Auto-detected interfaces: ['lan', 'wan']
INFO:root:Including 'floating' interface to fetch floating rules
INFO:root:  → 42 global rules retrieved
INFO:root:Fetching rules for interface: lan
...
INFO:root:✓ Total of 42 unique rules retrieved
```

## 🛠️ Troubleshooting

### Configuration check fails (API mode)

If you see *"Configuration is missing or invalid"*:
- Edit `pyfrc2g/config.py` and set `PFS_BASE_URL`/`PFS_TOKEN` (pfSense) or `OPNS_BASE_URL`/`OPNS_KEY`/`OPNS_SECRET` (OPNSense) to real values.
- Or use `--backup config.xml` to read from an XML backup instead of the API.
- Or use `--skip-config-check` only if you are sure the config is valid.

### Error: "Could not auto-detect interfaces"

**Solution**: Manually specify interfaces in `pyfrc2g/config.py`:

```python
INTERFACES = ["wan", "lan", "opt1"]
```

### API Connection Error

Check:
- API URL is correct
- Credentials (token/secret/key) are valid
- SSL certificate (package ignores SSL errors with `verify=False`)
- Firewall allows API access from your IP

### No Rules Retrieved

- Verify API returns data (test with curl or browser)
- For OPNSense, check that specified interfaces exist
- Check logs for detailed error messages
- Verify API user has proper permissions

### Graphviz Not Found

**Windows**:
- Download and install Graphviz from [official website](https://graphviz.org/download/)
- Add Graphviz to system PATH

**Linux**:
```bash
sudo apt-get install graphviz  # Debian/Ubuntu
sudo yum install graphviz      # RHEL/CentOS
```

**macOS**:
```bash
brew install graphviz
```

### PDF Generation Fails

- Ensure Graphviz is properly installed (`dot -V`)
- If your Graphviz build has no PDF output, the tool falls back to PNG automatically (or use `--raster`)
- Verify write permissions in output directory

## 📝 Notes

- **Change Detection**: Package only regenerates outputs when rules or NAT have changed (SHA-256 fingerprint)
- **Force Regeneration**: Use `--force` (or delete `fingerprint.txt`)
- **Temporary Files**: Intermediate graph files are written to a temporary directory and removed automatically
- **NAT on OPNsense**: Read from the XML backup; through the API only on versions exposing `/api/firewall/d_nat/search_rule` (best effort)
- **API Aliases**: All aliases are fetched from API - no manual mapping needed
- **Performance**: Large rule sets may take several minutes to process
- **CISO Assistant**: PDFs are uploaded automatically after generation (if configured). Each upload creates a new revision in the evidence record, maintaining a history of firewall rule changes.

## 🔄 Migration from Old Versions

If you were using an older version:

1. **Configuration**: Edit `pyfrc2g/config.py`; a config check runs in API mode unless you use `--skip-config-check`.
2. **Aliases**: In API mode, aliases are fetched from the API; in backup mode, they are read from the XML.
3. **Interfaces**: For OPNSense, you can leave `INTERFACES = []` for auto-detection.
4. **Usage**: Run `pyfrc2g` or `pyfrc2g --api` for API; `pyfrc2g --backup config.xml` for XML backup.

## 🆕 What's New (recent)

### 2.1.0

- **Several firewalls per run** (`FIREWALLS`, several `--backup` files) and **NAT port forwards**
- **Change report** with snapshot history, **audit** (risk detection)
- **Vector PDF** with summary page and bookmarks, **zones view**
- **HTML** (filterable) and **Excel** exports
- New options: `--output-dir`, `--force`, `--interfaces`, `--view`, `--raster`, `--no-nat`
- Fixes: disabled rules from XML backups, `<not/>` negation, per-interface PDF content, special characters in labels, empty results published when the API fails, CISO error messages

### Major Improvements

- **Modular architecture** — Codebase split into dedicated modules (`config`, `api_client`, `xml_parser`, `graph_generator`, `ciso_client`, etc.)
- **Two input modes** — API (pfSense/OPNSense) and XML backup (`config.xml`) with `--api` / `--backup`
- **CLI (argparse)** — `--api`, `--backup`, `--gateway-name`, `--skip-config-check`, `--debug` / `--verbose`
- **Configuration check** — Validates config before API mode (`config_checker.py`, overridable with `--skip-config-check`)
- **XML backup parser** — Rules and aliases read from pfSense/OPNSense backup files without API
- **API-based aliases** — No manual alias file in API mode; aliases fetched from API
- **Per-interface output** — Separate CSV and PDF per interface; filenames sanitized
- **PROTOCOL column** — Unified format for pfSense and OPNsense: `ipprotocol` + `protocol` (e.g. `IPv4 tcp`, `IPv6 Any`). Empty protocol is displayed as `Any`.
- **CISO Assistant** — Automatic upload of generated PDFs as evidence revisions
- **Change detection** — Graphs regenerated only when rules change (MD5 comparison)
- **OPNSense support** — Full support for OPNsense firewalls

## 📝 Todo

Planned improvements:

-  **Code improvements** — Further improve code quality and structure
-  **Admin notifications** — Notify administrators when graphs are generated
-  **Destination VLAN display** — Show destination VLAN before de host in the graph
-  **Rule metadata** — Retrieve timestamps and authors for rule creation/modification
-  **Enhanced error reporting** — More detailed error messages and recovery suggestions

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

See the LICENSE file for details.

## 📧 Support

For issues, questions, or contributions, please open an issue on the GitHub repository.

---

**Made with ❤️ for network administrators and security professionals**
