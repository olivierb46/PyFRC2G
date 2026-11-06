"""
Rule hit counters: find rules that carry no traffic.

Sources:
    - "pfctl -vvsr" output (pfSense and OPNsense): rules are matched by "ridentifier"
      (pfSense tracker) or by label (OPNsense rule uuid);
    - OPNsense API /api/firewall/filter_util/rule_stats (fetched by APIClient);
    - counters embedded in iptables-save -c / nft -j outputs (set by the adapters).

pf counters are reset when the ruleset is reloaded or the firewall reboots, so a history is
kept in <output>/hits_history.json: a rule is reported only when its packet counter has not
moved for UNUSED_DAYS days of observation.
"""

import json
import logging
import os
import re
from datetime import datetime, timedelta

from pyfrc2g.model.rules import rule_summary

HITS_FIELDNAMES = ["GATEWAY", "RULE ORDER", "RULE ID", "RULE", "PACKETS", "BYTES", "STATES",
                   "EVALUATIONS", "LAST TRAFFIC SEEN", "OBSERVED SINCE", "STATUS"]

_RULE_LINE = re.compile(r"^@(\d+)(?:\((\d+)\))?\s+(.*)$")
_COUNTERS = re.compile(r"(Evaluations|Packets|Bytes|States):\s*(\d+)")
_LABEL = re.compile(r'label\s+"([^"]*)"')
_RIDENTIFIER = re.compile(r"ridentifier\s+(\d+)")
_DATE_FMT = "%Y-%m-%d %H:%M:%S"


def parse_pfctl(text):
    """
    Parse "pfctl -vvsr" output.

    Returns:
        dict: {key: {"packets", "bytes", "states", "evaluations"}} where key is the
              ridentifier (pfSense tracker) and/or the label (OPNsense uuid).
    """
    counters = {}
    keys = []
    for line in (text or "").splitlines():
        stripped = line.strip()
        match = _RULE_LINE.match(stripped)
        if match:
            body = match.group(3)
            keys = []
            ident = _RIDENTIFIER.search(body) or (match.group(2) and re.match(r"(\d+)", match.group(2)))
            if ident:
                keys.append(ident.group(1))
            label = _LABEL.search(body)
            if label and label.group(1):
                keys.append(label.group(1).strip())
            continue
        if keys and stripped.startswith("[") and ("Packets" in stripped or "Evaluations" in stripped):
            values = {name.lower(): int(value) for name, value in _COUNTERS.findall(stripped)}
            if not values:
                continue
            for key in keys:
                total = counters.setdefault(key, {"packets": 0, "bytes": 0, "states": 0, "evaluations": 0})
                # One GUI rule can produce several pf rules (IPv4 + IPv6, several ports): sum them.
                for name, value in values.items():
                    total[name] = total.get(name, 0) + value
    return counters


def load_counters_file(path):
    """Read a pfctl -vvsr output file. Returns {} on error."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            counters = parse_pfctl(f.read())
    except OSError as e:
        logging.error(f"Cannot read hit counters file {path}: {e}")
        return {}
    logging.info(f"✓ Hit counters loaded from {path} ({len(counters)} pf rule(s))")
    return counters


def normalize_opnsense_stats(data):
    """{"stats": {label: {...}}} from rule_stats -> {key: counters}."""
    stats = data.get("stats", data) if isinstance(data, dict) else {}
    out = {}
    for key, value in (stats or {}).items():
        if isinstance(value, dict):
            out[str(key)] = {name: _to_int(value.get(name)) for name in
                             ("packets", "bytes", "states", "evaluations")}
    return out


def missing_counters_note(gateway_type, from_api, source=None, counters=None):
    """
    Why a run has no hit counters, and how to get them (shown in the reports and logs).

    pfSense has no counters in its configuration backup nor in the REST API rule endpoints:
    they come from "pfctl -vvsr", read through the API command prompt (opt-in) or from a file.
    """
    if counters:
        return ("Hit counters were read but no rule matched them: the counters are keyed by the "
                "rule tracker (pfSense) / uuid (OPNsense) of the current ruleset.")
    if gateway_type == "pfsense":
        if from_api and source == "api":
            return ("pfSense did not return the counters: the API key needs the privilege of the "
                    "POST /api/v2/diagnostics/command_prompt endpoint (runs 'pfctl -vvsr').")
        if from_api:
            return ("pfSense counters are not part of the REST API rules: add --hits api (or "
                    "\"hits\": \"api\" for the firewall; the key needs the command prompt privilege), "
                    "or --hits <file> with the output of 'pfctl -vvsr' run on the firewall.")
        return ("A configuration backup holds no counters: add --hits <file> with the output of "
                "'pfctl -vvsr' run on the firewall (Diagnostics > Command Prompt).")
    if gateway_type == "opnsense":
        if from_api:
            return "OPNsense did not return rule statistics (/api/firewall/filter_util/rule_stats)."
        return ("A configuration backup holds no counters: add --hits <file> with the output of "
                "'pfctl -vvsr' run on the firewall.")
    if gateway_type in ("iptables", "nftables"):
        return "No counters in the file: export it with 'iptables-save -c' or 'nft -j list ruleset'."
    return "This firewall type provides no hit counters."


def _to_int(value):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def attach_counters(rows, counters):
    """Set row["_HITS"] from counters (keyed by RULE ID). Returns the number of rules matched."""
    matched = 0
    for row in rows:
        key = (row.get("RULE ID") or "").strip()
        if key and key in counters:
            row["_HITS"] = counters[key]
            matched += 1
    return matched


def _parse_date(text):
    try:
        return datetime.strptime(text, _DATE_FMT)
    except (TypeError, ValueError):
        return None


def update_history(path, rows, now=None, unused_days=30):
    """
    Update hits_history.json with the counters attached to rows and classify each rule.

    Returns:
        tuple: (hits_rows for the HITS report, audit findings).
    """
    from pyfrc2g.analysis.audit import make_finding

    now = now or datetime.now()
    history = {}
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as f:
                history = json.load(f)
        except (OSError, ValueError) as e:
            logging.warning(f"Ignoring unreadable hit history {path}: {e}")

    report, findings = [], []
    threshold = timedelta(days=unused_days)
    for row in rows:
        counters = row.get("_HITS")
        rule_id = (row.get("RULE ID") or "").strip()
        if not counters or not rule_id:
            continue
        key = f"{row.get('GATEWAY', '')}|{rule_id}"
        packets = _to_int(counters.get("packets"))
        entry = history.get(key) or {"first_seen": now.strftime(_DATE_FMT), "last_traffic": None,
                                     "packets": 0}
        # Counter moved (or was reset and already counts packets again): traffic seen.
        if packets and packets != entry.get("packets"):
            entry["last_traffic"] = now.strftime(_DATE_FMT)
        entry["packets"] = packets
        history[key] = entry

        first_seen = _parse_date(entry["first_seen"]) or now
        last_traffic = _parse_date(entry.get("last_traffic"))
        disabled = (row.get("DISABLED") or "").strip() in ("True", "1")
        status = "ACTIVE"
        if disabled:
            status = "DISABLED"
        elif last_traffic is None:
            if now - first_seen >= threshold:
                status = "UNUSED"
                findings.append(make_finding(
                    "MEDIUM", "UNUSED", row,
                    f"No packet matched since {entry['first_seen']} (observed for "
                    f"{(now - first_seen).days} days): candidate for removal."))
            else:
                status = "NO HIT YET"
        elif now - last_traffic >= threshold:
            status = "STALE"
            findings.append(make_finding(
                "LOW", "NO_RECENT_TRAFFIC", row,
                f"No new packet since {entry['last_traffic']} ({(now - last_traffic).days} days)."))

        report.append({
            "GATEWAY": row.get("GATEWAY", ""), "RULE ORDER": row.get("RULE ORDER", ""),
            "RULE ID": rule_id,
            "RULE": rule_summary(row),
            "PACKETS": packets, "BYTES": _to_int(counters.get("bytes")),
            "STATES": _to_int(counters.get("states")),
            "EVALUATIONS": _to_int(counters.get("evaluations")),
            "LAST TRAFFIC SEEN": entry.get("last_traffic") or "",
            "OBSERVED SINCE": entry["first_seen"], "STATUS": status,
        })

    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=1, sort_keys=True)
    return report, findings
