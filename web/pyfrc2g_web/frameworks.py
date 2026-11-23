"""
Indicative mapping of the audit checks to the controls of security frameworks, and compliance figures built on it.

A control is "met" for a firewall when none of its mapped checks has an active finding. The mapping is a guide
for audit preparation, not a certification: it only says what the rule base analysis can tell about a control.

Administrators can add their own frameworks (setting "custom_frameworks", edited on the Compliance page):

    [Internal baseline]
    NET-1 | No any-to-any rule | ANY_ANY
    NET-2 | Housekeeping | SHADOWED, REDUNDANT, UNUSED
    NET-3 | Company policy | POLICY:*

A check is an engine check name, or POLICY:<id> for a rule of the compliance policy; "*" matches any characters.
"""

import fnmatch
import re

KNOWN_CHECKS = ("ANY_ANY", "WAN_EXPOSED", "SHADOWED", "REDUNDANT", "PARTIAL_OVERLAP", "DISABLED", "NO_DESCRIPTION",
                "UNUSED", "NO_RECENT_TRAFFIC")
MAX_FRAMEWORKS, MAX_CONTROLS, MAX_CHECKS = 10, 60, 20
_CHECK = re.compile(r"^[A-Z][A-Z0-9_]*$|^POLICY:[\w.*-]{1,64}$")
_NAME = re.compile(r"^[\w][\w .:()/+-]{0,59}$", re.UNICODE)

HYGIENE = ("SHADOWED", "REDUNDANT", "PARTIAL_OVERLAP", "DISABLED", "UNUSED", "NO_RECENT_TRAFFIC")
EXPOSURE = ("ANY_ANY", "WAN_EXPOSED")

# framework -> [(control id, title, checks)]
FRAMEWORKS = {
    "ISO 27001:2022": [
        ("A.8.20", "Networks security", EXPOSURE),
        ("A.8.22", "Segregation of networks", EXPOSURE),
        ("A.8.9", "Configuration management", HYGIENE),
        ("A.5.37", "Documented operating procedures", ("NO_DESCRIPTION",)),
    ],
    "CIS Controls v8": [
        ("12.2", "Establish and maintain a secure network architecture", EXPOSURE),
        ("13.4", "Perform traffic filtering between network segments", EXPOSURE),
        ("4.1", "Establish and maintain a secure configuration process", HYGIENE + ("NO_DESCRIPTION",)),
    ],
    "NIS2 (art. 21(2))": [
        ("(a)", "Policies on risk analysis and information system security", EXPOSURE),
        ("(g)", "Basic cyber hygiene practices", HYGIENE + ("NO_DESCRIPTION",)),
    ],
    "PCI DSS v4.0 (req. 1)": [
        ("1.2.1", "Configuration standards for network security control rulesets are defined and maintained",
         ("NO_DESCRIPTION",)),
        ("1.2.5", "Allowed services, protocols and ports are identified, approved and justified", EXPOSURE),
        ("1.2.7", "Network security control configurations are reviewed regularly", HYGIENE),
        ("1.3.1", "Inbound traffic to the cardholder data environment is restricted", EXPOSURE),
        ("1.3.2", "Outbound traffic from the cardholder data environment is restricted", ("ANY_ANY",)),
    ],
    "NIST CSF 2.0": [
        ("PR.IR-01", "Networks and environments are protected from unauthorized logical access and usage", EXPOSURE),
        ("PR.PS-01", "Configuration management practices are established and applied", HYGIENE + ("NO_DESCRIPTION",)),
    ],
    "NIST SP 800-53 r5": [
        ("SC-7", "Boundary protection", EXPOSURE),
        ("AC-4", "Information flow enforcement", ("ANY_ANY",)),
        ("CM-6", "Configuration settings", HYGIENE + ("NO_DESCRIPTION",)),
    ],
    # ANSSI "Guide d'hygiene informatique" (France): the measures are named here, not numbered (the numbering
    # changed between editions).
    "ANSSI - IT hygiene guide": [
        ("Network partitioning", "Segment the network and set up partitioning", EXPOSURE),
        ("Exposed services", "Isolate the services visible from the Internet", ("WAN_EXPOSED",)),
        ("Internet gateway", "Set up a secure gateway to the Internet", ("ANY_ANY",)),
        ("Configuration upkeep", "Keep the configuration of the filtering equipment clean",
         HYGIENE + ("NO_DESCRIPTION",)),
    ],
}


class FrameworkError(ValueError):
    pass


def parse_custom(text):
    """Return [(framework name, [(control id, title, checks)])] from the editable text. Raises FrameworkError."""
    frameworks, current = [], None
    for number, raw in enumerate((text or "").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            name = line[1:].rstrip("]").strip() if line.endswith("]") else ""
            if not _NAME.match(name):
                raise FrameworkError(f"Line {number}: a framework is written [Name] (letters, digits, spaces).")
            if name in FRAMEWORKS or any(name == n for n, _ in frameworks):
                raise FrameworkError(f"Line {number}: the framework {name!r} already exists.")
            if len(frameworks) >= MAX_FRAMEWORKS:
                raise FrameworkError(f"At most {MAX_FRAMEWORKS} custom frameworks.")
            current = (name, [])
            frameworks.append(current)
            continue
        if current is None:
            raise FrameworkError(f"Line {number}: start with a framework name, e.g. [Internal baseline].")
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 3 or not parts[0] or not parts[1]:
            raise FrameworkError(f"Line {number}: expected 'ID | Title | CHECK, CHECK'.")
        checks = tuple(c.strip() for c in parts[2].split(",") if c.strip())
        bad = [c for c in checks if not _CHECK.match(c)]
        if not checks or bad or len(checks) > MAX_CHECKS:
            raise FrameworkError(f"Line {number}: checks are names such as ANY_ANY or POLICY:<id> "
                                 f"({', '.join(bad) or 'none given'}).")
        if len(parts[0]) > 20 or len(parts[1]) > 160 or len(current[1]) >= MAX_CONTROLS:
            raise FrameworkError(f"Line {number}: id 20 characters, title 160, {MAX_CONTROLS} controls at most.")
        current[1].append((parts[0], parts[1], checks))
    for name, controls in frameworks:
        if not controls:
            raise FrameworkError(f"The framework {name!r} has no control.")
    return frameworks


def _hit(check, patterns):
    return any(fnmatch.fnmatchcase(check, pattern) for pattern in patterns)


def evaluate(items, custom=()):
    """
    items: [{"name", "data"}] (data = analysis with the accepted risks applied, or None); custom: parse_custom().
    Return {framework: {"controls": [{id, title, checks, failing: [names], total}], "score": percent, "custom"}}.
    """
    analysed = [i for i in items if i.get("data")]
    result = {}
    catalogue = [(name, controls, False) for name, controls in FRAMEWORKS.items()]
    catalogue += [(name, controls, True) for name, controls in custom]
    for framework, controls, is_custom in catalogue:
        rows, met, total = [], 0, 0
        for control_id, title, checks in controls:
            failing = sorted(i["name"] for i in analysed
                             if any(_hit(f.get("CHECK") or "", checks) for f in i["data"].get("audit") or []))
            rows.append({"id": control_id, "title": title, "checks": checks, "failing": failing,
                         "total": len(analysed)})
            met += len(analysed) - len(failing)
            total += len(analysed)
        result[framework] = {"controls": rows, "score": round(100 * met / total) if total else None,
                             "custom": is_custom}
    return result


def to_csv(result):
    import csv
    import io

    from pyfrc2g_web import csvsafe

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["FRAMEWORK", "CONTROL", "TITLE", "CHECKS", "FIREWALLS ANALYSED", "FIREWALLS NOT MET",
                     "FIREWALLS"])
    for framework, info in result.items():
        for control in info["controls"]:
            writer.writerow([csvsafe.cell(x) for x in (
                framework, control["id"], control["title"], " ".join(control["checks"]), control["total"],
                len(control["failing"]), " ".join(control["failing"]))])
    return out.getvalue()
