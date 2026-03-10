"""
Configuration checker for PyFRC2G.
Validates that pyfrc2g config is properly configured before running in API mode.
"""

import logging


# Placeholder values that indicate "not configured"
PFSENSE_PLACEHOLDERS = {
    "base_url": ["https://<pfs_address>", "https://<PFS_ADDRESS>"],
    "token": ["<your_pfsense_api_token>", "<YOUR_PFSENSE_API_TOKEN>", ""],
}
OPNSENSE_PLACEHOLDERS = {
    "base_url": ["https://<opns_address>", "https://<OPNS_ADDRESS>"],
    "key": ["<your_opnsense_api_key>", "<YOUR_OPNSENSE_API_KEY>", ""],
    "secret": ["<your_opnsense_api_secret>", "<YOUR_OPNSENSE_API_SECRET>", ""],
}


def _is_placeholder(value, placeholders_list):
    """Check if value is a placeholder or empty."""
    if value is None:
        return True
    v = (value or "").strip().lower()
    for p in placeholders_list:
        if (p or "").strip().lower() == v:
            return True
    return not v


def check_configuration():
    """
    Check that API configuration is valid for the selected gateway type.
    Only relevant when running in API mode (not backup).

    Returns:
        int: 0 = OK, 1 = warnings (optional issues), 2 = critical (must fix)
    """
    try:
        from pyfrc2g import config as config_module
    except ImportError:
        logging.error("Could not import pyfrc2g.config")
        return 2

    gateway_type = (getattr(config_module, "GATEWAY_TYPE", "") or "").strip().lower()
    if gateway_type not in ("pfsense", "opnsense"):
        logging.error("GATEWAY_TYPE must be 'pfsense' or 'opnsense' in pyfrc2g config")
        return 2

    errors = []
    warnings = []

    if gateway_type == "pfsense":
        base_url = getattr(config_module, "PFS_BASE_URL", "") or ""
        token = getattr(config_module, "PFS_TOKEN", "") or ""
        if _is_placeholder(base_url, PFSENSE_PLACEHOLDERS["base_url"]):
            errors.append("PFS_BASE_URL is not configured (edit pyfrc2g/config.py or set in your environment)")
        if _is_placeholder(token, PFSENSE_PLACEHOLDERS["token"]):
            errors.append("PFS_TOKEN is not configured (set your pfSense API key in pyfrc2g config)")
    else:
        base_url = getattr(config_module, "OPNS_BASE_URL", "") or ""
        key = getattr(config_module, "OPNS_KEY", "") or ""
        secret = getattr(config_module, "OPNS_SECRET", "") or ""
        if _is_placeholder(base_url, OPNSENSE_PLACEHOLDERS["base_url"]):
            errors.append("OPNS_BASE_URL is not configured (edit pyfrc2g/config.py or set in your environment)")
        if _is_placeholder(key, OPNSENSE_PLACEHOLDERS["key"]):
            errors.append("OPNS_KEY is not configured (set your OPNSense API key in pyfrc2g config)")
        if _is_placeholder(secret, OPNSENSE_PLACEHOLDERS["secret"]):
            errors.append("OPNS_SECRET is not configured (set your OPNSense API secret in pyfrc2g config)")

    if errors:
        for msg in errors:
            logging.error("  - %s", msg)
        return 2
    if warnings:
        for msg in warnings:
            logging.warning("  - %s", msg)
        return 1
    return 0


def run_configuration_check(skip_prompt=False):
    """
    Run configuration check and optionally prompt to continue on warnings.
    Call this before starting API mode.

    Args:
        skip_prompt: If True, do not ask to continue on warnings (just return True/False).

    Returns:
        bool: True if OK to proceed, False if should exit.
    """
    result = check_configuration()
    if result == 0:
        return True
    if result == 2:
        return False
    # result == 1: warnings
    if skip_prompt:
        return True
    try:
        response = input("Some configuration issues found. Continue anyway? (y/N): ").lower().strip()
        return response in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False
