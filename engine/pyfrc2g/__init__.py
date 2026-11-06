"""
PyFRC2G - Unified Firewall Rules to Graph Converter.
Convert firewall rules (pfSense, OPNsense, FortiGate, iptables, nftables, Stormshield) into
flow diagrams, audit and compliance reports. See pyfrc2g/main.py for the package layout.
"""

__version__ = "2.2.0"  # keep in sync with pyproject.toml
__author__ = "PyFRC2G Contributors"

from pyfrc2g.config import Config
from pyfrc2g.utils import (
    extract_base_url,
    map_value,
    normalize_ports,
    safe_filename,
)

__all__ = [
    "Config",
    "extract_base_url",
    "map_value",
    "normalize_ports",
    "safe_filename",
]
