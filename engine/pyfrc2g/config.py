"""
Configuration module for PyFRC2G.

Every value below can be overridden by an environment variable (PYFRC2G_*), possibly loaded
from a .env file, and any string value may reference an environment variable with ${NAME}
(e.g. "token": "${FW_PARIS_TOKEN}") so that secrets stay out of this file.
"""

import logging
import os
import re

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
# Keys: name (optional), type ("pfsense"/"opnsense"/"nfsensei"), url, token (pfSense / nfSensei API key),
#       key + secret (OPNsense), interfaces (optional list), ciso_evidence_id and ciso_folder_id (optional),
#       verify_ssl / ca_bundle (optional, override the TLS settings below),
#       hits ("api" to read pfSense rule counters through the REST API command prompt,
#             or a path to a "pfctl -vvsr" output file), hits_file (alias of the path form),
#       timeout (API requests, seconds), interface_labels ({"opt1": "DMZ"}),
#       wan_interfaces / admin_ports / sensitive_ports / unused_days (override the audit
#       settings below), meta ({"Site": "Paris", "Owner": "..."}: shown in the reports).
# Values like "${FW_PARIS_TOKEN}" are read from the environment / .env file.
# ---------------------------------------------------------------------------
FIREWALLS = [
    # {"name": "fw-paris", "type": "pfsense", "url": "https://10.0.0.1", "token": "..."},
    # {"name": "fw-lyon", "type": "opnsense", "url": "https://10.1.0.1",
    #  "key": "...", "secret": "...", "interfaces": ["lan", "opt1"]},
]

# ---------------------------------------------------------------------------
# TLS. VERIFY_SSL = False keeps the historical behaviour (self-signed certificates accepted);
# set it to True, or give CA_BUNDLE (PEM file of your internal CA), to verify certificates.
# ---------------------------------------------------------------------------
VERIFY_SSL = False
CA_BUNDLE = None

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
# Rules without traffic for this many days are reported as unused (needs hit counters).
UNUSED_DAYS = 30
# Custom compliance policy (YAML or JSON file), see README "Compliance policy".
POLICY_FILE = None
# Risk score weights per severity (score capped at 100; LOW findings count for 10 points max).
RISK_WEIGHTS = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 1}

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
    "DISABLED", "FLOATING", "RULE ORDER", "RULE ID", "IP VERSION", "AUTOMATIC", "DIRECTION",
]
FLOATING_RULES_LABELS = ["Floating-rules", "Regles-flottantes", "Règles flottantes"]
UNKNOWN_LABEL = "<unknown>"
DISABLED_LABEL = "Rule disabled"
ANY_VALUE = "Any"
DEFAULT_OUTPUT_DIR = "results"

_PLACEHOLDER_URLS = ("https://<PFS_ADDRESS>", "https://<OPNS_ADDRESS>")

# ---------------------------------------------------------------------------
# Environment variables and .env file
# ---------------------------------------------------------------------------

# Environment variable -> (module variable, type).
ENV_VARIABLES = {
    "PYFRC2G_GATEWAY_TYPE": ("GATEWAY_TYPE", str),
    "PYFRC2G_GATEWAY_NAME": ("GATEWAY_NAME", str),
    "PYFRC2G_PFS_URL": ("PFS_BASE_URL", str),
    "PYFRC2G_PFS_TOKEN": ("PFS_TOKEN", str),
    "PYFRC2G_OPNS_URL": ("OPNS_BASE_URL", str),
    "PYFRC2G_OPNS_KEY": ("OPNS_KEY", str),
    "PYFRC2G_OPNS_SECRET": ("OPNS_SECRET", str),
    "PYFRC2G_INTERFACES": ("INTERFACES", list),
    "PYFRC2G_VERIFY_SSL": ("VERIFY_SSL", bool),
    "PYFRC2G_CA_BUNDLE": ("CA_BUNDLE", str),
    "PYFRC2G_WAN_INTERFACES": ("WAN_INTERFACES", list),
    "PYFRC2G_UNUSED_DAYS": ("UNUSED_DAYS", int),
    "PYFRC2G_POLICY_FILE": ("POLICY_FILE", str),
    "PYFRC2G_CISO_URL": ("CISO_URL", str),
    "PYFRC2G_CISO_TOKEN": ("CISO_TOKEN", str),
    "PYFRC2G_CISO_FOLDER_ID": ("CISO_FORLDER_ID", str),
    "PYFRC2G_CISO_EVIDENCE_ID": ("CISO_EVIDENCE_ID", str),
}
# PYFRC2G_FIREWALLS_FILE: JSON or YAML file holding the FIREWALLS list (containers).
_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_TRUE_VALUES = {"1", "true", "yes", "on"}


def load_env_file(path=".env", override=False):
    """
    Load KEY=VALUE lines from a .env file into os.environ (no extra dependency).
    Supports comments, blank lines, "export KEY=VALUE" and single/double quotes.
    Existing environment variables win unless override is True.

    Returns:
        int: Number of variables read (0 if the file does not exist).
    """
    if not path or not os.path.isfile(path):
        return 0
    count = 0
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[len("export "):].lstrip()
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            elif " #" in value:
                value = value.split(" #", 1)[0].rstrip()
            if key and (override or key not in os.environ):
                os.environ[key] = value
            count += 1
    logging.debug(f"Loaded {count} variable(s) from {path}")
    return count


def expand_env(value):
    """Replace ${NAME} references (recursively in lists/dicts); unknown names are kept as is."""
    if isinstance(value, str):
        return _ENV_REF.sub(lambda m: os.environ.get(m.group(1), m.group(0)), value)
    if isinstance(value, list):
        return [expand_env(v) for v in value]
    if isinstance(value, dict):
        return {k: expand_env(v) for k, v in value.items()}
    return value


def unresolved_env_refs(value):
    """Names of ${NAME} references that are still present in value (variable not set)."""
    if isinstance(value, str):
        return _ENV_REF.findall(value)
    if isinstance(value, (list, tuple)):
        return [n for v in value for n in unresolved_env_refs(v)]
    if isinstance(value, dict):
        return [n for v in value.values() for n in unresolved_env_refs(v)]
    return []


def _convert(value, kind):
    if kind is bool:
        return value.strip().lower() in _TRUE_VALUES
    if kind is int:
        return int(value)
    if kind is list:
        return [part.strip() for part in value.split(",") if part.strip()]
    return value


def apply_environment():
    """Override module variables from PYFRC2G_* environment variables. Returns the names applied."""
    applied = []
    module = globals()
    for env_name, (var_name, kind) in ENV_VARIABLES.items():
        value = os.environ.get(env_name)
        if value is None:
            continue
        try:
            module[var_name] = _convert(value, kind)
            applied.append(env_name)
        except ValueError:
            logging.warning(f"Ignoring {env_name}={value!r}: invalid {kind.__name__} value")
    if "PYFRC2G_CISO_URL" in applied:
        module["CISO_EVIDENCE_PATH"] = f"{module['CISO_URL']}/api/evidence-revisions/"
    firewalls_file = os.environ.get("PYFRC2G_FIREWALLS_FILE")
    if firewalls_file:
        module["FIREWALLS"] = load_firewalls_file(firewalls_file)
        applied.append("PYFRC2G_FIREWALLS_FILE")
    return applied


def load_firewalls_file(path):
    """
    Read a FIREWALLS list from a JSON or YAML file: a list of firewall dicts, or a mapping
    with a "firewalls" key. Secrets can stay as ${VAR} references.
    """
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if path.lower().endswith((".yml", ".yaml")):
        import yaml

        data = yaml.safe_load(text)
    else:
        import json

        data = json.loads(text)
    firewalls = data.get("firewalls") if isinstance(data, dict) else data
    if not isinstance(firewalls, list) or not all(isinstance(fw, dict) for fw in firewalls):
        raise ValueError(f"{path}: expected a list of firewalls (or a 'firewalls' list)")
    return firewalls


_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(text):
    """'90' / '90s' / '30m' / '6h' / '1d' -> seconds (int). Raises ValueError."""
    value = str(text).strip().lower()
    match = re.fullmatch(r"(\d+)\s*([smhd]?)", value)
    if not match or int(match.group(1)) <= 0:
        raise ValueError(f"invalid duration {text!r} (examples: 300, 30m, 6h, 1d)")
    return int(match.group(1)) * _DURATION_UNITS[match.group(2) or "s"]


def tls_verify(target=None):
    """Value for requests' verify parameter: CA bundle path, True or False."""
    target = target or {}
    ca_bundle = target.get("ca_bundle") or CA_BUNDLE
    if ca_bundle:
        return ca_bundle
    verify = target.get("verify_ssl")
    if verify is None:
        verify = VERIFY_SSL
    if isinstance(verify, str):
        verify = verify.strip().lower() in _TRUE_VALUES
    return bool(verify)


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
    """Return the list of firewall targets for API mode (${NAME} references expanded)."""
    targets = [dict(t) for t in FIREWALLS] if FIREWALLS else [legacy_target()]
    return [expand_env(t) for t in targets]


def _positive_int(value):
    """int(value) when it is a positive number, else None."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


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

        target = expand_env(target or legacy_target())
        self.target = target
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
        self.api_key = target.get("token") or target.get("key") or ""  # nfSensei (X-API-Key)
        # nfSensei: "running" (applied, default) or "candidate" (pending changes, not committed).
        self.nfsensei_config = "candidate" if str(target.get("nfsensei_config")).lower() == "candidate" else "running"
        self.interfaces = list(interfaces_override or target.get("interfaces") or [])

        self.gateway_name = gateway_name_override or target.get("name")
        if not self.gateway_name:
            host = extract_host_from_url(url) if url not in _PLACEHOLDER_URLS else "unknown"
            self.gateway_name = host if host != "unknown" else "gateway"

        # Output directory: <output base>/<gateway name>/.
        self.output_base = output_base or DEFAULT_OUTPUT_DIR
        self.graph_output_dir = f"{self.output_base}/{self.gateway_name}"

        # CISO Assistant configuration.
        self.ciso_url = expand_env(CISO_URL)
        self.ciso_token = expand_env(CISO_TOKEN)
        self.ciso_evidence_path = expand_env(CISO_EVIDENCE_PATH)
        self.ciso_folder_id = target.get("ciso_folder_id") or expand_env(CISO_FORLDER_ID)
        self.ciso_evidence_id = target.get("ciso_evidence_id") or expand_env(CISO_EVIDENCE_ID)

        # TLS: CA bundle path, True or False (requests "verify" parameter).
        self.verify = tls_verify(target)
        self.hits_source = target.get("hits") or target.get("hits_file")

        # API requests timeout in seconds (None = per-request defaults).
        self.api_timeout = _positive_int(target.get("timeout"))
        # {interface id: display name} replacing the names read from the firewall.
        self.interface_labels = {str(k).strip().lower(): str(v).strip()
                                 for k, v in (target.get("interface_labels") or {}).items() if str(v).strip()}
        # (label, value) pairs shown in the reports (description, site, owner, tags...).
        self.extra_meta = [(str(k), str(v)) for k, v in (target.get("meta") or {}).items() if v]

        # Audit settings (a target may override them).
        self.wan_interfaces = list(target.get("wan_interfaces") or WAN_INTERFACES)
        self.admin_ports = set(target.get("admin_ports") or ADMIN_PORTS)
        self.sensitive_ports = set(target.get("sensitive_ports") or SENSITIVE_PORTS)
        self.unused_days = _positive_int(target.get("unused_days")) or UNUSED_DAYS
        self.risk_weights = dict(RISK_WEIGHTS)

        # Constants.
        self.csv_fieldnames = CSV_FIELDNAMES
        self.any_value = ANY_VALUE
