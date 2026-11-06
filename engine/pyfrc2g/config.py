"""
Configuration module for PyFRC2G.
"""

# ---------------------------------------------------------------------------
# Single firewall (legacy layout, used when FIREWALLS is empty).
# ---------------------------------------------------------------------------

# Gateway type: "pfsense" or "opnsense".
GATEWAY_TYPE = "pfsense"

# pfSense configuration.
PFS_BASE_URL = "https://<PFS_ADDRESS>"
PFS_TOKEN = "<YOUR_PFSENSE_API_TOKEN>"

# OPNSense configuration.
OPNS_BASE_URL = "https://<OPNS_ADDRESS>"
OPNS_KEY = "<YOUR_OPNSENSE_API_KEY>"
OPNS_SECRET = "<YOUR_OPNSENSE_API_SECRET>"
INTERFACES = []  # Auto-detect if empty; e.g. ["wan", "lan", "opt1", "opt2"].

# Common configuration.
GATEWAY_NAME = "<GW_NAME>"  # Display name for gateway (used in labels).
# Output directory is <output dir>/<gateway name or ip>/ (default output dir: results).

# ---------------------------------------------------------------------------
# Several firewalls in one run (API mode). When non-empty, replaces the block above.
# Keys: name (optional), type ("pfsense"/"opnsense"), url, token (pfSense),
#       key + secret (OPNsense), interfaces (optional list), ciso_evidence_id (optional).
# ---------------------------------------------------------------------------
FIREWALLS = [
    # {"name": "fw-paris", "type": "pfsense", "url": "https://10.0.0.1", "token": "..."},
    # {"name": "fw-lyon", "type": "opnsense", "url": "https://10.1.0.1",
    #  "key": "...", "secret": "...", "interfaces": ["lan", "opt1"]},
]

# ---------------------------------------------------------------------------
# Audit (risk detection).
# ---------------------------------------------------------------------------
# Interface ids/names considered as Internet-facing (case-insensitive), in addition
# to the description of the "wan" interface.
WAN_INTERFACES = ["wan"]
# Administration ports: exposing them from the WAN is reported.
ADMIN_PORTS = [22, 23, 80, 443, 161, 3389, 5900, 8080, 8443, 10443]
# Sensitive service ports (databases, file sharing...).
SENSITIVE_PORTS = [135, 139, 445, 1433, 1521, 2049, 3306, 5432, 6379, 9200, 11211, 27017]

# CISO Assistant configuration (optional).
# Leave default values to disable CISO Assistant integration.
CISO_URL = "https://<CISO_ASSISTANT_ADDRESS>"
CISO_TOKEN = "<CISO_ASSISTANT_TOKEN>"
CISO_EVIDENCE_PATH = f"{CISO_URL}/api/evidence-revisions/"
CISO_FORLDER_ID = "<CISO_FOLDER_ID>"  # Folder ID from CISO Assistant.
CISO_EVIDENCE_ID = "<CISO_EVIDENCE_ID>"  # Evidence ID from CISO Assistant.

# Constants.
CSV_FIELDNAMES = [
    "SOURCE", "GATEWAY", "ACTION", "PROTOCOL", "PORT", "DESTINATION", "COMMENT",
    "DISABLED", "FLOATING", "RULE ORDER", "RULE ID",
]
FLOATING_RULES_LABELS = ["Floating-rules", "Regles-flottantes", "Règles flottantes"]
UNKNOWN_LABEL = "<unknown>"
DISABLED_LABEL = "Rule disabled"
ANY_VALUE = "Any"
DEFAULT_OUTPUT_DIR = "results"

_PLACEHOLDER_URLS = ("https://<PFS_ADDRESS>", "https://<OPNS_ADDRESS>")


def legacy_target():
    """Build a firewall target dict from the single-firewall variables above."""
    gateway_type = (GATEWAY_TYPE or "").strip().lower()
    return {
        "name": GATEWAY_NAME if GATEWAY_NAME != "<GW_NAME>" else None,
        "type": gateway_type,
        "url": PFS_BASE_URL if gateway_type == "pfsense" else OPNS_BASE_URL,
        "token": PFS_TOKEN,
        "key": OPNS_KEY,
        "secret": OPNS_SECRET,
        "interfaces": list(INTERFACES),
    }


def api_targets():
    """Return the list of firewall targets for API mode."""
    if FIREWALLS:
        return [dict(t) for t in FIREWALLS]
    return [legacy_target()]


class Config:
    """Configuration for one firewall run."""

    def __init__(self, gateway_name_override=None, gateway_type_override=None, target=None,
                 output_base=None, interfaces_override=None):
        """
        Args:
            gateway_name_override: Override gateway name (e.g. from --gateway-name or backup).
            gateway_type_override: Override gateway type (e.g. from backup file detection).
            target: Firewall target dict (see FIREWALLS); defaults to the legacy variables.
            output_base: Base output directory (default: results).
            interfaces_override: Interface list replacing the configured one.
        """
        from pyfrc2g.utils import extract_host_from_url

        target = target or legacy_target()
        self.gateway_type = (gateway_type_override or target.get("type") or "").lower()

        url = (target.get("url") or "").rstrip("/")
        self.base_url = url
        self.pfs_base_url = url or "https://<PFS_ADDRESS>"
        self.pfs_url = f"{self.pfs_base_url}/api/v2/firewall/rules"
        self.pfs_token = target.get("token") or ""
        self.opns_base_url = url or "https://<OPNS_ADDRESS>"
        self.opns_url = f"{self.opns_base_url}/api/firewall/filter/search_rule"
        self.opns_key = target.get("key") or ""
        self.opns_secret = target.get("secret") or ""
        self.interfaces = list(interfaces_override or target.get("interfaces") or [])

        self.gateway_name = gateway_name_override or target.get("name")
        if not self.gateway_name:
            host = extract_host_from_url(url) if url not in _PLACEHOLDER_URLS else "unknown"
            self.gateway_name = host if host != "unknown" else "gateway"

        # Paths for output directory, CSV, and fingerprint file.
        self.output_base = output_base or DEFAULT_OUTPUT_DIR
        self.graph_output_dir = f"{self.output_base}/{self.gateway_name}"
        self.csv_file = f"{self.graph_output_dir}/output_{self.gateway_name}.csv"
        self.md5_file = f"{self.graph_output_dir}/md5sum.txt"

        # CISO Assistant configuration.
        self.ciso_url = CISO_URL
        self.ciso_token = CISO_TOKEN
        self.ciso_evidence_path = CISO_EVIDENCE_PATH
        self.ciso_folder_id = CISO_FORLDER_ID
        self.ciso_evidence_id = target.get("ciso_evidence_id") or CISO_EVIDENCE_ID

        # Audit settings.
        self.wan_interfaces = list(WAN_INTERFACES)
        self.admin_ports = set(ADMIN_PORTS)
        self.sensitive_ports = set(SENSITIVE_PORTS)

        # Constants.
        self.csv_fieldnames = CSV_FIELDNAMES
        self.floating_rules_labels = FLOATING_RULES_LABELS
        self.unknown_label = UNKNOWN_LABEL
        self.disabled_label = DISABLED_LABEL
        self.any_value = ANY_VALUE
