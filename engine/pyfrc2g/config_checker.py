"""
Configuration checker for PyFRC2G.
Validates that firewall targets are properly configured before running in API mode.
"""

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
    import os

    from pyfrc2g.config import unresolved_env_refs

    name = target.get("name") or target.get("url") or "firewall"
    missing_env = sorted(set(unresolved_env_refs(target)))
    if missing_env:
        return [f"[{name}] environment variable(s) not set: {', '.join(missing_env)} "
                "(export them or add them to the .env file)"]
    ca_bundle = target.get("ca_bundle")
    if ca_bundle and not os.path.isfile(ca_bundle):
        return [f"[{name}] CA bundle not found: {ca_bundle}"]
    gateway_type = (target.get("type") or "").strip().lower()
    if gateway_type not in ("pfsense", "opnsense", "nfsensei"):
        return [f"[{name}] type must be 'pfsense', 'opnsense' or 'nfsensei' (got {gateway_type!r})"]

    errors = []
    if _is_placeholder(target.get("url")):
        errors.append(f"[{name}] URL is not configured (PFS_BASE_URL / OPNS_BASE_URL or 'url')")
    if gateway_type == "nfsensei":
        if _is_placeholder(target.get("token")):
            errors.append(f"[{name}] nfSensei API key is not configured ('token')")
    elif gateway_type == "pfsense":
        if _is_placeholder(target.get("token")):
            errors.append(f"[{name}] pfSense API token is not configured (PFS_TOKEN or 'token')")
    else:
        if _is_placeholder(target.get("key")):
            errors.append(f"[{name}] OPNSense API key is not configured (OPNS_KEY or 'key')")
        if _is_placeholder(target.get("secret")):
            errors.append(f"[{name}] OPNSense API secret is not configured (OPNS_SECRET or 'secret')")
    return errors
