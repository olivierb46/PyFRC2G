import os
"""
Configuration module for PyFRC2G
"""

# Gateway type: "pfsense" or "opnsense"
GATEWAY_TYPE = "pfsense"

# pfSense Configuration
PFS_BASE_URL = os.environ.get("PFS_BASE_URL")
PFS_TOKEN = os.environ.get("PFS_TOKEN")

# OPNSense Configuration
OPNS_BASE_URL = "https://<OPNS_ADDRESS>"
OPNS_KEY = "<YOUR_OPNSENSE_API_KEY>"
OPNS_SECRET = "<YOUR_OPNSENSE_API_SECRET>"
INTERFACES = []  # Auto-detect if empty, e.g., ["wan", "lan", "opt1", "opt2"]

# Common Configuration
GATEWAY_NAME = "<GW_NAME>"  # Display name for gateway (used in labels)
# Output directory will be automatically set to results/<ip_or_domain>/

# CISO Assistant Configuration (optional)
# Leave as default values to disable CISO Assistant integration
CISO_URL = "https://<CISO_ASSISTANT_ADDRESS>"
CISO_TOKEN = "<CISO_ASSISTANT_TOKEN>"
CISO_EVIDENCE_PATH = f"{CISO_URL}/api/evidence-revisions/"
CISO_FORLDER_ID = "<CISO_FOLDER_ID>" # Domain ID from CISO Assistant
CISO_EVIDENCE_ID = "<CISO_EVIDENCE_ID>"  # Evidence ID from CISO Assistant

# Constants
CSV_FIELDNAMES = ["SOURCE", "GATEWAY", "ACTION", "PROTOCOL", "PORT", "DESTINATION", "COMMENT", "DISABLED", "FLOATING"]
FLOATING_RULES_LABELS = ["Floating-rules", "Regles-flottantes", "Règles flottantes"]
UNKNOWN_LABEL = "<unknown>"
DISABLED_LABEL = "Rule disabled"
ANY_VALUE = "Any"


class Config:
    """Configuration class for PyFRC2G"""
    
    def __init__(self):
        self.gateway_type = GATEWAY_TYPE
        # Use gateway name, or extract from URL if not set
        if GATEWAY_NAME != "<GW_NAME>":
            self.gateway_name = GATEWAY_NAME
        else:
            # Will be set after determining firewall host
            self.gateway_name = None
        
        # pfSense - Build URL from base URL
        self.pfs_base_url = PFS_BASE_URL
        if PFS_BASE_URL != "https://<PFS_ADDRESS>":
            self.pfs_url = f"{PFS_BASE_URL}/api/v2/firewall/rules"
        else:
            self.pfs_url = "https://<PFS_ADDRESS>/api/v2/firewall/rules"
        self.pfs_token = PFS_TOKEN
        
        # OPNSense - Build URL from base URL
        self.opns_base_url = OPNS_BASE_URL
        if OPNS_BASE_URL != "https://<OPNS_ADDRESS>":
            self.opns_url = f"{OPNS_BASE_URL}/api/firewall/filter/search_rule"
        else:
            self.opns_url = "https://<OPNS_ADDRESS>/api/firewall/filter/search_rule"
        self.opns_secret = OPNS_SECRET
        self.opns_key = OPNS_KEY
        self.interfaces = INTERFACES
        
        # Determine output directory from firewall address
        from modules.utils import extract_host_from_url, extract_base_url
        
        if self.gateway_type.lower() == "pfsense":
            base_url = self.pfs_base_url if self.pfs_base_url != "https://<PFS_ADDRESS>" else extract_base_url(self.pfs_url)
        else:
            base_url = self.opns_base_url if self.opns_base_url != "https://<OPNS_ADDRESS>" else extract_base_url(self.opns_url)
        
        firewall_host = extract_host_from_url(base_url)
        
        # Set gateway_name if not already set
        if self.gateway_name is None:
            self.gateway_name = firewall_host
        
        self.graph_output_dir = f"results/{self.gateway_name}"
        self.csv_file = f"output_{self.gateway_name}.csv"
        
        # CISO Assistant Configuration
        self.ciso_url = CISO_URL
        self.ciso_token = CISO_TOKEN
        self.ciso_evidence_path = CISO_EVIDENCE_PATH
        self.ciso_folder_id = CISO_FORLDER_ID
        self.ciso_evidence_id = CISO_EVIDENCE_ID
        
        # Constants
        self.csv_fieldnames = CSV_FIELDNAMES
        self.floating_rules_labels = FLOATING_RULES_LABELS
        self.unknown_label = UNKNOWN_LABEL
        self.disabled_label = DISABLED_LABEL
        self.any_value = ANY_VALUE

