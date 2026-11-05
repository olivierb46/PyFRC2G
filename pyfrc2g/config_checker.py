"""
Configuration checker for PyFRC2G.
Validates that firewall targets are properly configured before running in API mode.
"""

import logging

# Placeholder values that indicate "not configured" (compared case-insensitively).
_PLACEHOLDERS = {
    "https://<pfs_address>", "https://<opns_address>", "<your_pfsense_api_token>",
    "<your_opnsense_api_key>", "<your_opnsense_api_secret>", "",
}


def _is_placeholder(value):
    """Check if value is a placeholder or empty."""
    return (value or "").strip().lower() in _PLACEHOLDERS


def check_target(target):
    """
    Check one firewall target dict.

    Returns:
        list: Error messages (empty if the target is usable).
    """
    name = target.get("name") or target.get("url") or "firewall"
    gateway_type = (target.get("type") or "").strip().lower()
    if gateway_type not in ("pfsense", "opnsense"):
        return [f"[{name}] type must be 'pfsense' or 'opnsense' (got {gateway_type!r})"]

    errors = []
    if _is_placeholder(target.get("url")):
        errors.append(f"[{name}] URL is not configured (PFS_BASE_URL / OPNS_BASE_URL or 'url')")
    if gateway_type == "pfsense":
        if _is_placeholder(target.get("token")):
            errors.append(f"[{name}] pfSense API token is not configured (PFS_TOKEN or 'token')")
    else:
        if _is_placeholder(target.get("key")):
            errors.append(f"[{name}] OPNSense API key is not configured (OPNS_KEY or 'key')")
        if _is_placeholder(target.get("secret")):
            errors.append(f"[{name}] OPNSense API secret is not configured (OPNS_SECRET or 'secret')")
    return errors


def check_configuration(target=None):
    """
    Check that API configuration is valid.

    Args:
        target: Target dict to check; default: the single-firewall config variables.

    Returns:
        int: 0 = OK, 2 = critical (must fix).
    """
    from pyfrc2g.config import legacy_target

    errors = check_target(target or legacy_target())
    for msg in errors:
        logging.error("  - %s", msg)
    return 2 if errors else 0


def run_configuration_check(skip_prompt=False, target=None):
    """
    Run configuration check. Call this before starting API mode.

    Args:
        skip_prompt: Kept for backward compatibility (no interactive prompt anymore).
        target: Target dict to check.

    Returns:
        bool: True if OK to proceed, False if should exit.
    """
    return check_configuration(target) == 0
