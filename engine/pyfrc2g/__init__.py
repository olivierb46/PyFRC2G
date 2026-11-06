"""
PyFRC2G - Unified Firewall Rules to Graph Converter.
Convert pfSense and OPNSense firewall rules into graphical flow diagrams.
"""

__version__ = "2.1.0"  # keep in sync with pyproject.toml
__author__ = "PyFRC2G Contributors"

from pyfrc2g.config import Config
from pyfrc2g.utils import (
    calculate_md5,
    extract_base_url,
    map_value,
    normalize_ports,
    safe_filename,
)

__all__ = [
    "Config",
    "calculate_md5",
    "extract_base_url",
    "normalize_ports",
    "safe_filename",
    "map_value",
]
