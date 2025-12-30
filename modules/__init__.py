"""
PyFRC2G - Unified Firewall Rules to Graph Converter
A modular Python package for converting pfSense and OPNSense firewall rules into graphical flow diagrams.
"""

__version__ = "2.0.0"
__author__ = "PyFRC2G Contributors"

from .config import Config
from .api_client import APIClient
from .graph_generator import GraphGenerator
from .ciso_client import CISOCClient
from .utils import calculate_md5, extract_base_url, normalize_ports, safe_filename, map_value

__all__ = [
    'Config',
    'APIClient',
    'GraphGenerator',
    'CISOCClient',
    'calculate_md5',
    'extract_base_url',
    'normalize_ports',
    'safe_filename',
    'map_value',
]

