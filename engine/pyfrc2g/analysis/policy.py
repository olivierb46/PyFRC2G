"""
Custom compliance policy (YAML or JSON file).

Example (policy.yml):

    policies:
      - id: no-rdp-from-wan
        description: RDP must never be reachable from the Internet
        severity: CRITICAL
        match: {interface: wan, action: pass, port: 3389}

      - id: pass-needs-description
        description: Every pass rule must be documented
        severity: LOW
        match: {action: pass}
        require: {comment: ".+"}

      - id: guest-isolated-from-lan
        description: The guest network must not reach the LAN
        severity: HIGH
        match: {interface: GUEST, action: pass, destination: "lan"}

A rule that satisfies every "match" condition is a violation, unless the policy has a
"require" block: then the violation is a matching rule that does NOT satisfy "require".

Conditions (a list means "any of"):
    interface    interface id or description (lan, opt1, GUEST)
    action       pass / block / reject
    protocol     tcp, udp, icmp... (a tcp/udp rule matches tcp and udp)
    port         port, range "8000-8080" or port alias: matches if the rule can reach it
    source       IP, network, alias or interface ("lan"): matches if the sets intersect
    destination  same as source
    comment      regular expression (case-insensitive) on the description
    disabled     true / false (default: disabled rules are ignored)
    floating     true / false
    automatic    true / false (default: automatic OPNsense rules are ignored)
    ip_version   4 or 6
    gateway      text contained in the GATEWAY column (several firewalls)
Prefix a value with "!" to negate it (e.g. action: "!block").
"""

import json
import logging
import re

from pyfrc2g.model import netmodel

_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_KNOWN_KEYS = {"interface", "action", "protocol", "port", "source", "destination", "comment",
               "disabled", "floating", "ip_version", "gateway", "automatic"}


class PolicyError(ValueError):
    pass


def load_policy(path):
    """Load and validate a policy file. Raises PolicyError on invalid content."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    policies = parse_policy(text, yaml_format=path.lower().endswith((".yml", ".yaml")))
    logging.info(f"✓ Loaded {len(policies)} compliance polic{'y' if len(policies) == 1 else 'ies'} from {path}")
    return policies


def parse_policy(text, yaml_format=True):
    """Parse and validate a policy given as YAML (or JSON) text. Raises PolicyError."""
    if yaml_format:
        try:
            import yaml
        except ImportError as e:
            raise PolicyError("PyYAML is required for YAML policies (pip install pyyaml), "
                              "or write the policy in JSON") from e
        try:
            data = yaml.safe_load(text) or {}
        except yaml.YAMLError as e:
            raise PolicyError(f"Invalid YAML policy: {e}") from e
    else:
        try:
            data = json.loads(text)
        except ValueError as e:
            raise PolicyError(f"Invalid JSON policy: {e}") from e
    policies = data.get("policies") if isinstance(data, dict) else data
    if not isinstance(policies, list):
        raise PolicyError("The policy file must contain a 'policies' list")
    checked = []
    for index, policy in enumerate(policies, start=1):
        if not isinstance(policy, dict):
            raise PolicyError(f"Policy #{index} is not a mapping")
        pid = str(policy.get("id") or f"policy-{index}")
        severity = str(policy.get("severity") or "MEDIUM").upper()
        if severity not in _SEVERITIES:
            raise PolicyError(f"Policy {pid}: severity must be one of {', '.join(_SEVERITIES)}")
        for block in ("match", "require"):
            conditions = policy.get(block) or {}
            if not isinstance(conditions, dict):
                raise PolicyError(f"Policy {pid}: '{block}' must be a mapping")
            unknown = set(conditions) - _KNOWN_KEYS
            if unknown:
                raise PolicyError(f"Policy {pid}: unknown condition(s) {', '.join(sorted(unknown))}")
            for key, value in conditions.items():
                if key == "comment":
                    for pattern in _values(value):
                        try:
                            re.compile(str(pattern).lstrip("!"))
                        except re.error as e:
                            raise PolicyError(f"Policy {pid}: invalid comment regex {pattern!r}: {e}") from e
        checked.append({"id": pid, "description": str(policy.get("description") or ""),
                        "severity": severity, "match": policy.get("match") or {},
                        "require": policy.get("require")})
    return checked


def _values(value):
    return value if isinstance(value, list) else [value]


def _bool(value):
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _interface_matches(rule, wanted):
    iface = netmodel.interface_id(wanted) or str(wanted).strip().lower()
    if iface in rule.ifaces:
        return True
    gateway = rule.group.split("/", 1)[-1].lower()
    return str(wanted).strip().lower() in {part.strip() for part in gateway.split(",")}


def _single(rule, key, value):
    """Evaluate one condition value (without negation)."""
    if key == "interface":
        return _interface_matches(rule, value)
    if key == "action":
        return rule.action == str(value).strip().lower()
    if key == "protocol":
        wanted = netmodel.resolve_protocol(value)
        return netmodel.protocol_intersects(rule.protos, wanted)
    if key == "port":
        return netmodel.ports_intersects(rule.ports, netmodel.resolve_ports(str(value))) is not False
    if key in ("source", "destination"):
        target = netmodel.resolve_address(str(value)).restrict(rule.ipver)
        field = rule.src if key == "source" else rule.dst
        return netmodel.addr_intersects(field, target) is not False
    if key == "comment":
        return re.search(str(value), rule.row.get("COMMENT") or "", re.IGNORECASE) is not None
    if key == "disabled":
        return (not rule.enabled) == _bool(value)
    if key == "floating":
        return rule.floating == _bool(value)
    if key == "automatic":
        return rule.automatic == _bool(value)
    if key == "ip_version":
        return int(str(value).strip()[-1]) in rule.ipver
    if key == "gateway":
        return str(value).lower() in rule.group.lower()
    return False


def _condition(rule, key, value):
    results = []
    for item in _values(value):
        text = str(item)
        negated = isinstance(item, str) and text.startswith("!")
        result = _single(rule, key, text[1:] if negated else item)
        results.append(not result if negated else result)
    return any(results)


def _matches(rule, conditions):
    conditions = dict(conditions)
    if "disabled" not in conditions and not rule.enabled:
        return False
    if rule.established_only:
        return False  # iptables/nft "established,related" rules never open a connection.
    if "automatic" not in conditions and rule.automatic:
        return False  # Firewall-generated rules are ignored unless the policy asks for them.
    return all(_condition(rule, key, value) for key, value in conditions.items())


def evaluate_policies(rows, policies):
    """Return audit findings (CHECK = POLICY:<id>) for every violation."""
    from pyfrc2g.analysis.audit import make_finding

    findings = []
    rules = netmodel.compile_rules(rows)
    for policy in policies:
        for rule in rules:
            if not _matches(rule, policy["match"]):
                continue
            require = policy.get("require")
            if require:
                required = dict(require)
                required.setdefault("disabled", not rule.enabled)
                required.setdefault("automatic", rule.automatic)
                if _matches(rule, required):
                    continue
            detail = policy["description"] or f"Violates policy {policy['id']}"
            findings.append(make_finding(policy["severity"], f"POLICY:{policy['id']}", rule.row, detail))
    return findings
