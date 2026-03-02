#!/usr/bin/env python3
"""
PyFRC2G - Unified Firewall Rules to Graph Converter
Converts pfSense and OPNSense firewall rules into graphical flow diagrams.
"""

import sys
import argparse
import logging
from modules.main import main


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="PyFRC2G - Convert pfSense/OPNSense firewall rules to flow diagrams",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fetch rules from API (configure modules/config.py first)
  python pyfrc2g.py
  python pyfrc2g.py --api

  # Skip configuration check (use only if you know config is valid)
  python pyfrc2g.py --api --skip-config-check

  # Read rules from XML backup file (no config check needed)
  python pyfrc2g.py --backup config-backup.xml

  # Specify gateway name for backup mode
  python pyfrc2g.py --backup config.xml --gateway-name my-firewall

  # Enable debug logging
  python pyfrc2g.py --api --debug
  python pyfrc2g.py --backup config.xml --verbose
        """
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--api", "-a",
        action="store_true",
        help="Fetch rules from firewall API (default if no mode; configure modules/config.py)"
    )
    mode.add_argument(
        "--backup", "-b",
        metavar="FILE",
        help="Read rules from XML backup file (pfSense or OPNSense config.xml)"
    )
    parser.add_argument(
        "--gateway-name", "-g",
        metavar="NAME",
        help="Gateway display name (for backup mode or when not using API)"
    )
    parser.add_argument(
        "--debug", "-d",
        action="store_true",
        help="Enable debug logging"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output (same as --debug)"
    )
    parser.add_argument(
        "--skip-config-check",
        action="store_true",
        help="Skip configuration check before running (API mode only)"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    
    # Set debug flag for main() to pick up
    if args.debug or args.verbose:
        sys.argv.append("--debug")
    
    # Pass args to main for backup mode
    sys.exit(main(args=args))
