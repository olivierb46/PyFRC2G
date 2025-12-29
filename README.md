# PyFRC2G - Unified Firewall Rules to Graph Converter

Unified Python package to convert **pfSense** and **OPNSense** firewall rules into graphical flow diagrams.

![pfSense Example](./img/convert-rules-to-graph.png)
![OPNSense Example](./img/opnsense.png)

## 👋 Overview

PyFRC2G was designed to meet two main objectives:

* **Visual Documentation**: Provide a global graphical view of firewall rules (a picture is worth a thousand words)
* **Compliance Evidence**: Provide evidence to meet IT security requirements defined in various compliance frameworks

## ⚡ Features

### Core Features

* **Unified Support**: Single package for both pfSense and OPNSense
* **Automatic Interface Detection**: Auto-detects all available interfaces for OPNSense
* **API-Based Alias Mapping**: Retrieves all aliases directly from firewall API (no config file needed)
* **Per-Interface Output**: Generates separate CSV and PDF files for each interface
* **Smart Change Detection**: Only regenerates graphs when rules have changed (MD5 comparison)
* **Modular Architecture**: Clean, maintainable, and extensible codebase

### Technical Features

* **Graphical Flows**: Generates visual flow diagrams using Graphviz
* **PDF Generation**: Produces A4 PDF files with one page per interface
* **Color Coding**: 
  - 🟢 Green for PASS rules
  - 🔴 Red for BLOCK rules
  - 🟡 Yellow for disabled rules
* **Network Mapping**: Distinguishes between VLANs/networks and destination hosts
* **Comprehensive Coverage**: Handles floating rules, disabled rules, and all interface types
* **CISO Assistant Integration**: Optional automatic upload of PDFs to CISO Assistant as evidence revisions

## 📋 Prerequisites

### Python Requirements

- Python 3.7 or higher
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
pip install requests graphviz reportlab

# Use the script directly
python pyfrc2g.py
```

## ⚙️ Configuration

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
OPNS_SECRET = "YOUR_API_SECRET"
OPNS_KEY = "YOUR_API_KEY"

# Option 1: Auto-detection (recommended)
INTERFACES = []  # Leave empty for automatic detection

# Option 2: Manual specification
INTERFACES = ["wan", "lan", "opt1", "opt2"]

GATEWAY_NAME = "OPNS01"  # Display name for gateway (used in labels)
```

### 2. CISO Assistant Integration (Optional)

If you want to automatically upload generated PDFs to CISO Assistant as evidence revisions, configure the following in `pyfrc2g/config.py`:

```python
# CISO Assistant Configuration
CISO_URL = "https://ciso-assistant.example.com"
CISO_TOKEN = "YOUR_CISO_ASSISTANT_API_TOKEN"
CISO_EVIDENCE_PATH = f"{CISO_URL}/api/evidence-revisions/"
CISO_FORLDER_ID = "<CISO_FOLDER_ID>" # Domain ID from CISO Assistant to which the evidence is linked.
CISO_EVIDENCE_ID = "<CISO_EVIDENCE_ID> # Evidence ID from CISO Assistant
```

**Note:** Leave these as default values (`<CISO_ASSISTANT_ADDRESS>`, etc.) to disable CISO Assistant integration.

### 3. No Config File Needed! 🎉

**The package automatically retrieves all aliases from the firewall API:**
- Interface names and descriptions
- Network aliases
- Address aliases
- Port aliases

No manual configuration file is required! Everything is fetched directly from your firewall's API.

## 🚀 Usage

### Basic Usage

#### As a Script:

```bash
python pyfrc2g.py
```

#### As an Installed Package:

```bash
pyfrc2g
```

#### As a Python Module:

```python
from pyfrc2g import Config, APIClient, GraphGenerator
from pyfrc2g.main import main

# Option 1: Use the main function
main()

# Option 2: Use components directly
config = Config()
api_client = APIClient(config)
graph_generator = GraphGenerator(config)

# Fetch aliases
api_client.fetch_aliases()

# Fetch rules
rules = api_client.fetch_rules()

# Generate graphs
graph_generator.generate_graphs(csv_path, output_dir)
```

### What the Script Does

1. Connects to your gateway (pfSense or OPNSense)
2. Fetches all aliases from the API
3. Retrieves all firewall rules from all interfaces
4. Auto-detects interfaces (for OPNSense, if not specified)
5. Generates a temporary CSV file with all rules
6. Compares with previous version (MD5 checksum)
7. If changes detected, generates graphs and PDFs
8. Uploads PDFs to CISO Assistant (if configured)

### Generated Files

The script generates files in `tmp/graphs_<GATEWAY_NAME>/`:

#### Global Files:
- `<GATEWAY_NAME>_FLOW_MATRIX.pdf` - PDF with all interfaces (one page per interface)

#### Per-Interface Files:
- `<GATEWAY_NAME>_<interface>_flows.csv` - CSV file with rules for specific interface
- `<GATEWAY_NAME>_<interface>_FLOW_MATRIX.pdf` - PDF with graphs for specific interface

#### Tracking:
- `md5sum.txt` - MD5 hash of last generated CSV (for change detection)

### Example Output Structure

```
tmp/graphs_PFS01/
├── PFS01_FLOW_MATRIX.pdf              # Global PDF (all interfaces)
├── PFS01_wan_FLOW_MATRIX.pdf          # WAN interface PDF
├── PFS01_wan_flows.csv                # WAN interface CSV
├── PFS01_lan_FLOW_MATRIX.pdf          # LAN interface PDF
├── PFS01_lan_flows.csv                # LAN interface CSV
└── PFS01_opt1_FLOW_MATRIX.pdf         # OPT1 interface PDF
```

## 📊 Output Format

The generated PDFs contain:

- **One page per interface** with flow diagrams
- **One page for floating rules**
- **Graphical flow diagrams** showing:
  - **Sources**: Network/host sources
  - **Gateway/Interface**: Firewall interface name
  - **Actions**: PASS (green) / BLOCK (red) with color coding
  - **Protocols**: IP protocol (TCP, UDP, ICMP, etc.)
  - **Ports**: Destination ports or port ranges
  - **Destinations**: Network/host destinations
  - **Comments**: Rule descriptions
  - **Disabled Rules**: Highlighted in yellow

## 🏗️ Project Structure

```
PyFRC2G-main/
├── pyfrc2g/                    # Main package
│   ├── __init__.py            # Package initialization and exports
│   ├── config.py              # Configuration management
│   ├── api_client.py          # API client for firewalls
│   ├── graph_generator.py     # Graph and PDF generation
│   ├── ciso_client.py         # CISO Assistant integration
│   ├── utils.py               # Utility functions
│   └── main.py                # Main execution logic
├── pyfrc2g.py                 # Entry point script
├── setup.py                   # Package installation
├── README.md                  # This file
└── img/                       # Example images
```

### Module Descriptions

#### `config.py`
- Configuration class and constants
- Gateway type settings (pfSense/OPNSense)
- API credentials management
- Output paths configuration

#### `api_client.py`
- `APIClient` class for firewall API interactions
- Alias retrieval (interfaces, networks, addresses, ports)
- Firewall rules retrieval
- Interface auto-detection for both pfSense and OPNSense

#### `graph_generator.py`
- `GraphGenerator` class for graph and PDF generation
- CSV parsing and grouping by interface
- Graphviz graph creation
- PDF generation from PNG files

#### `utils.py`
- Utility functions (MD5, URL extraction, filename sanitization)
- Value mapping using API aliases
- Global API alias maps management

#### `main.py`
- Main execution function
- Orchestrates the entire workflow
- Change detection using MD5
- File cleanup
- CISO Assistant integration

#### `ciso_client.py`
- `CISOCClient` class for CISO Assistant integration
- Uploads generated PDFs as evidence revisions
- Handles authentication and error reporting

## 🔍 Automatic Interface Detection (OPNSense)

The package attempts multiple methods to automatically detect interfaces:

1. **Interface API**: `/api/core/interfaces/listAll` or `/api/core/interfaces/list`
2. **From Firewall Rules**: Analyzes all rules to extract used interfaces
3. **Fallback**: If auto-detection fails, you must manually specify interfaces

### Detection Logs

```
INFO:root:Attempting auto-detection of interfaces...
INFO:root:✓ Auto-detected interfaces: ['wan', 'lan', 'opt1', 'opt2']
```

## 🛠️ Troubleshooting

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

- Ensure Graphviz is properly installed
- Check that PNG files are generated in output directory
- Verify write permissions in output directory

## 📝 Notes

- **Change Detection**: Package only regenerates PDFs when rules have changed (MD5 comparison)
- **Force Regeneration**: Delete or empty `md5sum.txt` file to force regeneration
- **Temporary Files**: CSV and PNG files are automatically cleaned up after processing
- **API Aliases**: All aliases are fetched from API - no manual mapping needed
- **Performance**: Large rule sets may take several minutes to process
- **CISO Assistant**: PDFs are uploaded automatically after generation (if configured). Each upload creates a new revision in the evidence record, maintaining a history of firewall rule changes.

## 🔄 Migration from Old Versions

If you were using version 1.x:

1. **Configuration**: Edit `pyfrc2g/config.py` instead of `pyfrc2g.py`
2. **Config File**: **No longer needed!** All aliases are fetched from API
3. **Interfaces**: For OPNSense, you can leave `INTERFACES = []` for auto-detection
4. **Usage**: Script usage remains the same: `python pyfrc2g.py`

## 🆕 What's New in v2.0

### Major Improvements

- ✅ **Modular Architecture**: Clean, organized codebase with separate modules
- ✅ **Fully English Codebase**: All code, comments, and messages in English
- ✅ **API-Based Alias Retrieval**: No config file required
- ✅ **Per-Interface File Generation**: Separate CSV and PDF for each interface
- ✅ **Optimized Code**: Reduced code size, improved performance
- ✅ **Better Error Handling**: More informative error messages
- ✅ **Package Installation**: Can be installed as a Python package
- ✅ **Module Usage**: Can be imported and used as a Python module
- ✅ **CISO Assistant Integration**: Automatic upload of generated PDFs to CISO Assistant as evidence revisions

## 📝 Todo

Future improvements and features planned for PyFRC2G:

- [ ] **Code Improvements**: Continue improving code quality and structure
- [x] **Automated Change Detection**: Graphs are regenerated only when rules have changed (MD5 comparison) ✅
- [ ] **Admin Notifications**: Notify administrators when graphs are generated
- [ ] **Destination VLAN Display**: Add the destination VLAN before a destination host in the graphical view
- [x] **OPNSense Support**: Full support for OPNSense firewalls ✅
- [x] **CISO Assistant Integration**: Automatic upload of PDFs to CISO Assistant as evidence revisions ✅
- [ ] **Rule Metadata**: Retrieve timestamps and authors for rule creation/modification
- [ ] **Enhanced Error Reporting**: More detailed error messages and recovery suggestions
- [ ] **Configuration Validation**: Validate configuration before execution
- [ ] **Multiple Gateway Support**: Support for processing multiple gateways in a single run

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

See the LICENSE file for details.

## 📧 Support

For issues, questions, or contributions, please open an issue on the GitHub repository.

---

**Made with ❤️ for network administrators and security professionals**
