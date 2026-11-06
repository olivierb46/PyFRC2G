"""
Main entry point for PyFRC2G (console script "pyfrc2g", python -m pyfrc2g).

Package layout:
    cli.py        command line, settings, loop over firewalls
    pipeline.py   load -> rows -> analysis -> outputs, for one firewall; --compare
    config.py     user configuration (+ .env / environment variables), config_checker.py
    inputs/       API client, pfSense/OPNsense XML, FortiGate, iptables, nftables, Stormshield
    model/        normalized rule rows, address/port resolution, NAT rows
    analysis/     audit, changes, hit counters, policy, risk, matrix, comparison
    outputs/      graphs, PDF, HTML, Excel, CSV, CISO Assistant upload

This module re-exports the public functions for backward compatibility.
"""

import sys

from pyfrc2g.cli import REQUIRED_PACKAGES, check_dependencies, main, parse_args
from pyfrc2g.model.rules import build_rule_rows, filter_by_interfaces, filter_by_ip_version
from pyfrc2g.pipeline import generate_outputs, process_firewall

__all__ = [
    "REQUIRED_PACKAGES", "build_rule_rows", "check_dependencies", "filter_by_interfaces",
    "filter_by_ip_version", "generate_outputs", "main", "parse_args", "process_firewall",
]

if __name__ == "__main__":
    sys.exit(main())
