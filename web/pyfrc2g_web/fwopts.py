"""
Options of an API firewall (stored encrypted in firewalls.config_enc).

One place for the defaults, the validation of the administration form and the translation
into an engine target (config.FIREWALLS entry) and command line arguments. An empty value
means "use the global setting" (Administration > Settings).
"""

import re

CHOICES = {
    "ip_version": ("", "4", "6"),
    "automatic_rules": ("default", "include", "exclude"),
    "policy_mode": ("global", "own", "none"),
    "schedule_mode": ("global", "custom", "manual"),
    "ciso_auto": ("default", "always", "never"),
    "view": ("all", "rules", "zones"),
}
DEFAULTS = {
    "timeout": None, "interfaces": [], "detected_interfaces": [], "interface_labels": {},
    "ip_version": "", "nat": True, "automatic_rules": "default", "hits": None,
    "wan_interfaces": [], "admin_ports": [], "sensitive_ports": [], "unused_days": None,
    "policy_mode": "global", "policy": "",
    "schedule_mode": "global", "schedule": "", "retention": None,
    "ciso_evidence_id": "", "ciso_auto": "default",
    "view": "all", "raster": False, "excel": True, "svg": True,
    "description": "", "site": "", "owner": "", "tags": [],
}
_ID = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
_IFACE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
_TAG = re.compile(r"^[\w .:-]{1,32}$", re.UNICODE)


def options(firewall):
    """Every option of a firewall record, defaults filled in."""
    conf = firewall.get("config") or {}
    values = {key: conf.get(key, value) for key, value in DEFAULTS.items()}
    if values["hits"] is None:  # Before this option: pfSense "hits_api", OPNsense always on.
        values["hits"] = bool(conf.get("hits_api")) if firewall.get("type") == "pfsense" else True
    for key, allowed in CHOICES.items():
        if values[key] not in allowed:
            values[key] = allowed[0]
    return values


def split_list(text):
    return [item.strip() for item in re.split(r"[,\n]+", text or "") if item.strip()]


def ports(text, label, errors):
    try:
        ports = sorted({int(p) for p in re.split(r"[,\s]+", text or "") if p})
    except ValueError:
        errors.append(f"{label}: numbers separated by commas.")
        return []
    if any(not 0 < p < 65536 for p in ports):
        errors.append(f"{label}: ports between 1 and 65535.")
    return ports


def _number(text, label, errors, low, high):
    text = (text or "").strip()
    if not text:
        return None
    try:
        value = int(text)
    except ValueError:
        errors.append(f"{label}: a number.")
        return None
    if not low <= value <= high:
        errors.append(f"{label}: between {low} and {high}.")
        return None
    return value


def _labels(text, errors):
    """'opt1=DMZ, opt2 = Guests' -> {'opt1': 'DMZ', 'opt2': 'Guests'}."""
    labels = {}
    for item in split_list(text):
        key, sep, value = item.partition("=")
        key, value = key.strip().lower(), value.strip()
        if not sep or not _IFACE.match(key) or not value or len(value) > 40:
            errors.append(f"Interface names: '{item}' is not 'interface=name'.")
            continue
        labels[key] = value
    return labels


def parse_form(form, old, errors):
    """Options from the firewall form (old: options of the stored firewall)."""
    from pyfrc2g.config import parse_duration

    values = {key: form.get(key, DEFAULTS[key]) for key in CHOICES}
    for key, allowed in CHOICES.items():
        if values[key] not in allowed:
            errors.append(f"Invalid value for {key}.")
            values[key] = allowed[0]

    chosen = [i.strip().lower() for i in form.getlist("interfaces_choice") if i.strip()]
    typed = [i.lower() for i in split_list(form.get("interfaces", ""))]
    interfaces = list(dict.fromkeys(chosen + typed))
    for name in interfaces:
        if not _IFACE.match(name):
            errors.append(f"Interfaces: invalid name '{name}'.")
    wan = [i.lower() for i in split_list(form.get("wan_interfaces", ""))]
    for name in wan:
        if not _IFACE.match(name):
            errors.append(f"Internet-facing interfaces: invalid name '{name}'.")

    schedule = form.get("schedule", "").strip()
    if values["schedule_mode"] == "custom":
        if not schedule:
            errors.append("Schedule: give an interval (30m, 6h, 1d) or choose another mode.")
        else:
            try:
                parse_duration(schedule)
            except ValueError as e:
                errors.append(f"Schedule: {e}")

    policy = form.get("policy", "")
    if values["policy_mode"] == "own":
        from pyfrc2g.analysis.policy import PolicyError, parse_policy

        if not policy.strip():
            errors.append("Compliance policy: paste a policy or choose another mode.")
        else:
            try:
                parse_policy(policy)
            except PolicyError as e:
                errors.append(f"Compliance policy: {e}")

    evidence = form.get("ciso_evidence_id", "").strip()
    if evidence and not _ID.match(evidence):
        errors.append("CISO Assistant evidence id: letters, digits, '-', '_', '.' or ':' only.")
    tags = list(dict.fromkeys(split_list(form.get("tags", ""))))
    if any(not _TAG.match(t) for t in tags):
        errors.append("Tags: letters, digits, spaces, '.', ':', '_' or '-' (32 characters max).")

    values.update(
        timeout=_number(form.get("timeout"), "API timeout", errors, 5, 600),
        interfaces=interfaces,
        detected_interfaces=old.get("detected_interfaces") or [],
        interface_labels=_labels(form.get("interface_labels", ""), errors),
        nat=form.get("nat") == "1",
        hits=form.get("hits") == "1",
        wan_interfaces=wan,
        admin_ports=ports(form.get("admin_ports"), "Administration ports", errors),
        sensitive_ports=ports(form.get("sensitive_ports"), "Sensitive ports", errors),
        unused_days=_number(form.get("unused_days"), "Unused rules", errors, 1, 3650),
        policy=policy if values["policy_mode"] == "own" else old.get("policy", ""),
        schedule=schedule if values["schedule_mode"] == "custom" else "",
        retention=_number(form.get("retention"), "Analyses kept", errors, 1, 500),
        ciso_evidence_id=evidence,
        raster=form.get("raster") == "1",
        excel=form.get("excel") == "1",
        svg=form.get("svg") == "1",
        description=form.get("description", "").strip()[:200],
        site=form.get("site", "").strip()[:64],
        owner=form.get("owner", "").strip()[:64],
        tags=tags,
    )
    return values


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

def target(firewall, opts):
    """Engine target dict (credentials, TLS and per-firewall overrides)."""
    conf = firewall["config"]
    result = {"name": firewall["name"], "type": firewall["type"], "url": conf.get("url"),
              "token": conf.get("token"), "key": conf.get("key"), "secret": conf.get("secret"),
              "interfaces": opts["interfaces"], "verify_ssl": conf.get("verify_ssl"),
              "timeout": opts["timeout"], "interface_labels": opts["interface_labels"],
              "wan_interfaces": opts["wan_interfaces"], "admin_ports": opts["admin_ports"],
              "sensitive_ports": opts["sensitive_ports"], "unused_days": opts["unused_days"],
              "meta": meta(opts)}
    if opts["hits"] and firewall["type"] == "pfsense":
        result["hits"] = "api"
    return result


def meta(opts):
    """Organisation fields shown in the reports."""
    return {"Description": opts["description"], "Site": opts["site"], "Owner": opts["owner"],
            "Tags": ", ".join(opts["tags"])}


def arguments(opts, firewall_type, settings):
    """Command line options of the engine for this firewall."""
    args = ["--view", opts["view"]]
    if opts["ip_version"]:
        args += ["--ip-version", opts["ip_version"]]
    if not opts["nat"]:
        args.append("--no-nat")
    if not opts["hits"]:
        args.append("--no-hits")
    automatic = opts["automatic_rules"]
    if automatic == "exclude" or (automatic == "default" and not settings.get("automatic_rules", True)):
        args.append("--no-automatic-rules")
    if opts["raster"]:
        args.append("--raster")
    if not opts["excel"]:
        args.append("--no-excel")
    return args


def policy_text(opts, settings):
    """Compliance policy (YAML) applied to this firewall ('' = none)."""
    if opts["policy_mode"] == "none":
        return ""
    if opts["policy_mode"] == "own":
        return opts["policy"]
    return settings.get("policy") or ""


def schedule_interval(opts, settings):
    """Seconds between two scheduled analyses, None when not scheduled."""
    from pyfrc2g.config import parse_duration

    if opts["schedule_mode"] == "manual":
        return None
    text = opts["schedule"] if opts["schedule_mode"] == "custom" else settings.get("schedule")
    try:
        return parse_duration(text) if (text or "").strip() else None
    except ValueError:
        return None


def ciso_auto(opts, settings):
    if opts["ciso_auto"] == "default":
        return bool(settings.get("ciso_auto"))
    return opts["ciso_auto"] == "always"
