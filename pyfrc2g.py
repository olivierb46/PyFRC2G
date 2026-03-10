#!/usr/bin/env python3
"""
Compatibility launcher for PyFRC2G.
Run the installed package entry point when executed as script (e.g. python pyfrc2g.py).
"""

import sys

from pyfrc2g.main import main

if __name__ == "__main__":
    sys.exit(main())
