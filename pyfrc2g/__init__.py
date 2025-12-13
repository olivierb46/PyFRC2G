"""
PyFRC2G - Unified Firewall Rules to Graph Converter
A modular Python package for converting pfSense and OPNSense firewall rules into graphical flow diagrams.
"""

__version__ = "2.0.0"
__author__ = "PyFRC2G Contributors"

from pyfrc2g.config import Config
from pyfrc2g.api_client import APIClient
from pyfrc2g.graph_generator import GraphGenerator
from pyfrc2g.utils import calculate_md5, extract_base_url, normalize_ports, safe_filename, map_value

__all__ = [
    'Config',
    'APIClient',
    'GraphGenerator',
    'calculate_md5',
    'extract_base_url',
    'normalize_ports',
    'safe_filename',
    'map_value',
]

