"""
Accepted risks (exceptions file, YAML or JSON).

Example (exceptions.yml):

    exceptions:
      - check: WAN_ANY_ANY            # check name of the audit finding (or POLICY:<id>)
        rule: "12"                    # optional: RULE ID or rule summary; empty = every rule
        gateway: fw-paris             # optional: firewall name; empty = every firewall
        reason: Legacy VPN, replaced in Q3
        owner: network team           # optional
        expires: 2026-12-31           # optional (YYYY-MM-DD); after that the finding counts again

An accepted finding is left out of the audit findings, the severity counts and the risk score.
Reports list it apart, with its justification (Accepted risks).
"""

import json
import logging
from datetime import date

from pyfrc2g.analysis.audit import AUDIT_FIELDNAMES

ACCEPTED_FIELDNAMES = AUDIT_FIELDNAMES + ["REASON", "OWNER", "EXPIRES"]


class ExceptionsError(ValueError):
    pass


def rule_key(finding):
    """Identifier of the rule of a finding: its RULE ID, else its text."""
    return (finding.get("RULE ID") or "").strip() or (finding.get("RULE") or "").strip()


def is_active(exception, today=None):
    expires = exception.get("expires")
    return not expires or str(expires) >= (today or date.today().isoformat())


def matches(exception, finding, gateway):
    """True when the exception covers the finding (the expiry date is not looked at)."""
    if exception.get("gateway") not in (None, "", gateway):
        return False
    if exception.get("check") != finding.get("CHECK"):
        return False
    key = (exception.get("rule") or "").strip()
    return not key or key in ((finding.get("RULE ID") or "").strip(), (finding.get("RULE") or "").strip())


def split(findings, exceptions, gateway, today=None):
    """(active findings, accepted findings with REASON / OWNER / EXPIRES) for a firewall."""
    active, accepted = [], []
    for finding in findings:
        exception = next((e for e in exceptions if is_active(e, today) and matches(e, finding, gateway)), None)
        if exception is None:
            active.append(finding)
        else:
            accepted.append(dict(finding, REASON=exception.get("reason") or "", OWNER=exception.get("owner") or "",
                                 EXPIRES=str(exception.get("expires") or "")))
    return active, accepted


def parse_exceptions(text):
    """Parse and validate an exceptions file. Raises ExceptionsError."""
    try:
        import yaml

        data = yaml.safe_load(text) or {}
    except ImportError:
        data = json.loads(text or "{}")
    except Exception as e:
        raise ExceptionsError(f"invalid file: {e}") from e
    items = data.get("exceptions") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise ExceptionsError("expected a list under 'exceptions:'")
    result = []
    for number, item in enumerate(items, 1):
        if not isinstance(item, dict) or not str(item.get("check") or "").strip():
            raise ExceptionsError(f"exception {number}: 'check' is required")
        if not str(item.get("reason") or "").strip():
            raise ExceptionsError(f"exception {number}: 'reason' is required (justify the accepted risk)")
        expires = str(item.get("expires") or "").strip()
        try:
            if expires:
                date.fromisoformat(expires)
        except ValueError as e:
            raise ExceptionsError(f"exception {number}: 'expires' must be YYYY-MM-DD") from e
        result.append({"check": str(item["check"]).strip(), "rule": str(item.get("rule") or "").strip(),
                       "gateway": str(item.get("gateway") or "").strip(), "reason": str(item["reason"]).strip(),
                       "owner": str(item.get("owner") or "").strip(), "expires": expires})
    return result


def load_exceptions(path):
    with open(path, encoding="utf-8") as f:
        items = parse_exceptions(f.read())
    logging.info(f"✓ Loaded {len(items)} accepted risk(s) from {path}")
    return items
