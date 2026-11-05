"""
Main entry point for PyFRC2G CLI.
"""

import argparse
import csv
import hashlib
import io
import logging
import os
import shutil
import sys
import tempfile
import traceback
from datetime import datetime
from pathlib import Path

from pyfrc2g.utils import (
    get_dest_val,
    get_port_val,
    get_source_val,
    map_value,
    normalize_interface,
    safe_filename,
    update_api_maps,
)

# Heavy imports (requests, graphviz, reportlab, pypdf, openpyxl) are done lazily in _run().
REQUIRED_PACKAGES = ("requests", "graphviz", "reportlab", "pypdf", "openpyxl")


def check_dependencies():
    """
    Verify that required dependencies are installed.

    Returns:
        tuple: (ok, error_message). ok is True if all deps are installed, else False and error_message
               contains an "Install with: ..." line.
    """
    import importlib

    missing = []
    for package in REQUIRED_PACKAGES:
        try:
            importlib.import_module(package)
        except ImportError:
            missing.append(package)
    if missing:
        return False, (
            f"Missing required package(s): {', '.join(missing)}.\n"
            f"Install with: pip install -r requirements.txt   or   pip install {' '.join(missing)}"
        )
    return True, None


# ---------------------------------------------------------------------------
# Rule entries -> CSV rows
# ---------------------------------------------------------------------------

def _gateway_from_entry(entry, config):
    """Build GATEWAY cell: gateway_name/interfaces. Floating with multiple interfaces (e.g. lan,wan) shows interfaces; else Floating-rules."""
    entry_interface = normalize_interface(entry.get("interface"))
    if entry.get("floating"):
        if entry_interface and "," in entry_interface:
            return f"{config.gateway_name}/{map_value(entry_interface, 'interface', config.any_value)}"
        return f"{config.gateway_name}/Floating-rules"
    if entry_interface:
        return f"{config.gateway_name}/{map_value(entry_interface, 'interface', config.any_value)}"
    return f"{config.gateway_name}/Floating-rules"


def _protocol_from_entry(entry):
    """Build PROTOCOL cell from ipprotocol + protocol (e.g. 'IPv4 tcp', 'IPv6 Any'). Empty protocol → 'Any'."""
    ipp = (entry.get("ipprotocol") or "").strip()
    prot = (entry.get("protocol") or "").strip()
    prot_display = prot or "Any"
    if ipp:
        return f"{ipp} {prot_display}"
    return prot or "Any"


def _is_floating_entry(entry):
    """True if rule is floating (no interface or explicitly tagged). Same logic for API and backup."""
    return bool(entry.get("floating") or not entry.get("interface"))


def _rule_id(entry):
    """Stable rule identifier: pfSense tracker or OPNsense uuid (pfSense API 'id' is positional)."""
    return str(entry.get("tracker") or entry.get("uuid") or "")


def _entry_to_csv_row(entry, config, gateway_type, gateway, rule_order):
    """Convert one rule entry to a CSV row dict (pfSense and OPNsense share the same columns)."""
    floating = _is_floating_entry(entry)
    if gateway_type == "pfsense":
        source = entry.get("source")
        action = entry.get("type")
        port = entry.get("destination_port")
        dest = entry.get("destination")
        comment = entry.get("descr")
        disabled = "True" if entry.get("disabled") else "False"
    else:
        source = get_source_val(entry)
        action = entry.get("action") or entry.get("type")
        port = get_port_val(entry)
        dest = get_dest_val(entry)
        comment = entry.get("description")
        disabled = "True" if not entry.get("enabled", True) else "False"
    protocol = _protocol_from_entry(entry)
    return {
        "SOURCE": map_value(source, "source", config.any_value),
        "GATEWAY": gateway,
        "ACTION": map_value(action, None, config.any_value),
        "PROTOCOL": map_value(protocol, None, config.any_value),
        "PORT": map_value(port, "destination_port", config.any_value),
        "DESTINATION": map_value(dest, "destination", config.any_value),
        "COMMENT": str(comment or ""),
        "DISABLED": disabled,
        "FLOATING": "True" if floating else "False",
        "RULE ORDER": str(rule_order),
        "RULE ID": _rule_id(entry),
    }


def build_rule_rows(entries, config):
    """Convert rule entries to CSV rows, numbering rules per gateway/interface."""
    rows = []
    counters = {}
    for entry in entries:
        gateway = _gateway_from_entry(entry, config)
        counters[gateway] = counters.get(gateway, 0) + 1
        rows.append(_entry_to_csv_row(entry, config, config.gateway_type, gateway, counters[gateway]))
    return rows


def _interface_set(value):
    """'lan,opt1' / ['lan', 'opt1'] -> {'lan', 'opt1'}."""
    return {part.strip().lower() for part in normalize_interface(value).split(",") if part.strip()}


def filter_by_interfaces(entries, interfaces, keep_floating=True):
    """Keep entries on one of the given interfaces (and floating rules if keep_floating)."""
    if not interfaces:
        return entries
    wanted = {i.lower() for i in interfaces}
    kept = []
    for entry in entries:
        if keep_floating and _is_floating_entry(entry):
            kept.append(entry)
        elif _interface_set(entry.get("interface")) & wanted:
            kept.append(entry)
    return kept


def _csv_bytes(fieldnames, rows):
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue().encode("utf-8")


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Output generation
# ---------------------------------------------------------------------------

def _archive_previous(global_csv, history_dir, host_name):
    """Copy the previous global CSV to history/ (timestamped with its modification time)."""
    if not os.path.isfile(global_csv):
        return
    os.makedirs(history_dir, exist_ok=True)
    stamp = datetime.fromtimestamp(os.path.getmtime(global_csv)).strftime("%Y%m%d-%H%M%S")
    shutil.copy2(global_csv, os.path.join(history_dir, f"{host_name}_ALL_flows_{stamp}.csv"))


def generate_outputs(config, rows, nat_rows, report_info, args, ciso_client=None):
    """
    Produce every output for one firewall: CSVs, change report, audit, PDFs (global and
    per interface), HTML report, Excel workbook; upload the global PDF to CISO Assistant.
    """
    from pyfrc2g.audit import AUDIT_FIELDNAMES, audit_rules
    from pyfrc2g.diff import CHANGES_FIELDNAMES, count_changes, diff_rules, read_rows
    from pyfrc2g.exports import write_csv, write_html_report, write_xlsx_report
    from pyfrc2g.graph_generator import GraphGenerator
    from pyfrc2g.nat import NAT_FIELDNAMES
    from pyfrc2g.reports import (
        RunReport,
        assemble_pdf,
        interface_of,
        write_audit_pdf,
        write_changes_pdf,
        write_nat_pdf,
        write_summary_pdf,
    )

    out = config.graph_output_dir
    os.makedirs(out, exist_ok=True)
    host = os.path.basename(os.path.normpath(out)) or "gateway"
    view = getattr(args, "view", "all")
    fields = config.csv_fieldnames

    # Change report against the previous snapshot.
    global_csv = os.path.join(out, f"{host}_ALL_flows.csv")
    previous_rows, previous_fields = read_rows(global_csv)
    changes = None
    if previous_rows is not None:
        changes = diff_rules(previous_rows, previous_fields, rows)
        counts = count_changes(changes)
        logging.info(f"Changes since previous run: {counts['ADDED']} added, "
                     f"{counts['MODIFIED']} modified, {counts['REMOVED']} removed")
        _archive_previous(global_csv, os.path.join(out, "history"), host)
    else:
        logging.info("No previous snapshot: change report starts with this run")

    findings = audit_rules(rows, config)
    logging.info(f"Audit: {len(findings)} finding(s)")

    write_csv(global_csv, fields, rows)
    logging.info(f"✓ Global CSV created: {global_csv}")
    write_csv(os.path.join(out, f"{host}_AUDIT.csv"), AUDIT_FIELDNAMES, findings)
    if changes is not None:
        write_csv(os.path.join(out, f"{host}_CHANGES.csv"), CHANGES_FIELDNAMES, changes)
    if nat_rows:
        write_csv(os.path.join(out, f"{host}_NAT.csv"), NAT_FIELDNAMES, nat_rows)

    report = RunReport(
        gateway_name=config.gateway_name, gateway_type=config.gateway_type,
        source=report_info["source"], generated_at=report_info["generated_at"], rules=rows,
        fingerprint=report_info["fingerprint"], source_fingerprint=report_info.get("source_fingerprint"),
        audit=findings, changes=changes, nat=nat_rows,
        interfaces_filter=report_info.get("interfaces_filter"),
    )

    groups = {}
    for row in rows:
        groups.setdefault(interface_of(row), []).append(row)

    generator = GraphGenerator(config, raster=getattr(args, "raster", False))
    with tempfile.TemporaryDirectory(prefix="pyfrc2g-") as work:
        rule_pages = {}
        if view in ("all", "rules"):
            for iface, group in groups.items():
                rule_pages[iface] = generator.render_rule_graphs(group, os.path.join(work, "rules"))

        zone_page = None
        if view in ("all", "zones") and rows:
            zone_page = generator.render_zone_graph(rows, os.path.join(work, "zones"),
                                                    f"ZONES : {config.gateway_name}")

        # Global PDF.
        parts = [
            ("Summary", write_summary_pdf(report, os.path.join(work, "summary.pdf"))),
            ("Changes", write_changes_pdf(report, os.path.join(work, "changes.pdf"))),
            ("Audit", write_audit_pdf(report, os.path.join(work, "audit.pdf"))),
            ("NAT port forwards", write_nat_pdf(report, os.path.join(work, "nat.pdf"))),
        ]
        if zone_page:
            parts.append(("Zones view", zone_page[1]))
        for pages in rule_pages.values():
            parts.extend(pages)
        global_pdf = os.path.join(out, f"{host}_FLOW_MATRIX.pdf")
        assemble_pdf(global_pdf, parts, f"Flow matrix for gateway {host}")
        logging.info(f"✓ Global PDF generated: {global_pdf}")

        # Per-interface CSV + PDF.
        for iface, group in groups.items():
            iface_safe = safe_filename(iface)
            if len(iface_safe) > 80:
                iface_safe = f"{iface_safe[:60]}_{hashlib.md5(iface_safe.encode()).hexdigest()[:8]}"
            write_csv(os.path.join(out, f"{host}_{iface_safe}_flows.csv"), fields, group)
            iface_parts = [("Summary", write_summary_pdf(
                report, os.path.join(work, f"summary_{iface_safe}.pdf"), rows=group, interface=iface))]
            if view in ("all", "zones"):
                page = generator.render_zone_graph(group, os.path.join(work, f"zones_{iface_safe}"),
                                                   f"ZONES : {config.gateway_name} / {iface}")
                if page:
                    iface_parts.append(("Zones view", page[1]))
            iface_parts.extend(rule_pages.get(iface, []))
            assemble_pdf(os.path.join(out, f"{host}_{iface_safe}_FLOW_MATRIX.pdf"), iface_parts,
                         f"Flow matrix for gateway {host} - {iface}")
            logging.info(f"✓ Interface {iface}: {len(group)} rule(s)")

    write_html_report(report, os.path.join(out, f"{host}_REPORT.html"), fields)
    xlsx = write_xlsx_report(report, os.path.join(out, f"{host}_FLOW_MATRIX.xlsx"), fields)
    logging.info(f"✓ HTML report: {os.path.join(out, f'{host}_REPORT.html')}")
    if xlsx:
        logging.info(f"✓ Excel workbook: {xlsx}")

    if ciso_client is not None and ciso_client.enabled:
        logging.info("Uploading PDF to CISO Assistant...")
        stats = ciso_client.upload_global_pdf(global_pdf)
        if stats["failed"]:
            logging.warning(f"⚠ Failed to upload {stats['failed']} PDF(s) to CISO Assistant")
    return report


# ---------------------------------------------------------------------------
# Per-firewall processing
# ---------------------------------------------------------------------------

def _load_backup(path, args, gateway_name_override):
    """Read rules from an XML backup. Returns (config, entries, nat_entries, info) or None."""
    from pyfrc2g.config import Config
    from pyfrc2g.xml_parser import parse_xml_backup

    logging.info(f"Mode: XML backup (no API calls). File: {path}")
    aliases, entries, gateway_type, name_from_xml, nat_entries = parse_xml_backup(path)
    if aliases is None:
        return None
    if not entries:
        logging.warning("No rules found in backup file - output may be empty")
    config = Config(gateway_name_override=gateway_name_override or name_from_xml or Path(path).stem,
                    gateway_type_override=gateway_type, output_base=args.output_dir)
    update_api_maps(aliases.get("interface_map", {}), aliases.get("net_map", {}),
                    aliases.get("address_map", {}), aliases.get("port_map", {}),
                    aliases.get("alias_details"))
    info = {"source": f"XML backup {os.path.basename(path)}", "source_fingerprint": _sha256_file(path)}
    return config, entries, nat_entries, info


def _load_api(target, args, gateway_name_override):
    """Fetch rules from a firewall API. Returns (config, entries, nat_entries, info) or None."""
    from pyfrc2g.api_client import APIClient
    from pyfrc2g.config import Config

    config = Config(gateway_name_override=gateway_name_override, target=target,
                    output_base=args.output_dir, interfaces_override=_parse_interfaces(args))
    if config.gateway_type not in ("pfsense", "opnsense"):
        logging.error(f"Unknown gateway type: {config.gateway_type}. Use 'pfsense' or 'opnsense'.")
        return None
    client = APIClient(config)
    client.fetch_aliases()
    entries = client.fetch_rules()
    if not entries:
        # Do not overwrite the fingerprint / publish empty graphs when the API call failed.
        logging.error("Aborting: no rules retrieved from the API, previous results kept.")
        return None
    nat_entries = [] if args.no_nat else client.fetch_nat_rules()
    return config, entries, nat_entries, {"source": f"{config.gateway_type} API {config.base_url}"}


def _parse_interfaces(args):
    value = getattr(args, "interfaces", None)
    return [i.strip() for i in value.split(",") if i.strip()] if value else None


def process_firewall(loaded, args, from_backup):
    """Normalize rules, detect changes and generate outputs. Returns an exit code."""
    from pyfrc2g.ciso_client import CISOCClient
    from pyfrc2g.nat import NAT_FIELDNAMES, nat_entry_to_row

    config, entries, nat_entries, info = loaded
    interfaces = _parse_interfaces(args)
    if interfaces:
        entries = filter_by_interfaces(entries, interfaces)
        nat_entries = filter_by_interfaces(nat_entries or [], interfaces, keep_floating=False)
        logging.info(f"Interfaces filter {interfaces}: {len(entries)} rule(s) kept")
    nat_entries = [] if args.no_nat else (nat_entries or [])

    logging.info(f"Retrieved {len(entries)} rules from {config.gateway_type} ({config.gateway_name})")
    rows = build_rule_rows(entries, config)
    nat_rows = [nat_entry_to_row(e, config.any_value) for e in nat_entries]

    fingerprint = hashlib.sha256(
        _csv_bytes(config.csv_fieldnames, rows) + _csv_bytes(NAT_FIELDNAMES, nat_rows)
    ).hexdigest()
    os.makedirs(config.graph_output_dir, exist_ok=True)
    fingerprint_file = os.path.join(config.graph_output_dir, "fingerprint.txt")
    previous = ""
    if os.path.isfile(fingerprint_file):
        with open(fingerprint_file, encoding="utf-8") as f:
            previous = f.readline().strip()

    if not (from_backup or args.force or previous != fingerprint):
        logging.info("No rules created or modified (use --force to regenerate)")
        return 0

    logging.info("Generating reports and graphs...")
    info.update(fingerprint=fingerprint, generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                interfaces_filter=interfaces)
    generate_outputs(config, rows, nat_rows, info, args, CISOCClient(config))
    with open(fingerprint_file, "w", encoding="utf-8") as f:
        f.write(f"{fingerprint}\n")
    return 0


def _run(args):
    """Core execution logic: one or several firewalls (API) or backup files."""
    ok, err = check_dependencies()
    if not ok:
        print(err, file=sys.stderr)
        return 1

    from graphviz import ExecutableNotFound

    from pyfrc2g.config import api_targets
    from pyfrc2g.config_checker import check_target

    backups = list(getattr(args, "backup", None) or [])
    jobs = backups if backups else api_targets()
    gateway_name = getattr(args, "gateway_name", None)
    if gateway_name and len(jobs) > 1:
        logging.warning("--gateway-name ignored: several firewalls/backups are processed")
        gateway_name = None

    exit_code = 0
    for job in jobs:
        label = job if backups else (job.get("name") or job.get("url") or "firewall")
        if len(jobs) > 1:
            logging.info(f"===== {label} =====")
        try:
            if backups:
                loaded = _load_backup(job, args, gateway_name)
            else:
                if not getattr(args, "skip_config_check", False):
                    errors = check_target(job)
                    if errors:
                        for msg in errors:
                            logging.error(f"  - {msg}")
                        logging.error("Configuration is missing or invalid: edit pyfrc2g/config.py "
                                      "(or use --backup FILE).")
                        exit_code = max(exit_code, 2)
                        continue
                loaded = _load_api(job, args, gateway_name)
            if loaded is None:
                exit_code = max(exit_code, 1)
                continue
            exit_code = max(exit_code, process_firewall(loaded, args, from_backup=bool(backups)))
        except ExecutableNotFound:
            logging.error("Graphviz 'dot' executable not found: install Graphviz "
                          "(apt install graphviz / dnf install graphviz / brew install graphviz)")
            return 1
        except Exception as e:
            logging.error(f"[{label}] failed: {e}")
            logging.debug(traceback.format_exc())
            exit_code = max(exit_code, 1)
    return exit_code


def parse_args(argv=None):
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="PyFRC2G - Convert pfSense/OPNSense firewall rules to flow diagrams",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fetch rules from API (configure pyfrc2g/config.py first; FIREWALLS for several)
  pyfrc2g
  pyfrc2g --api --force

  # Read rules from one or several XML backup files
  pyfrc2g --backup config-backup.xml
  pyfrc2g --backup fw1.xml fw2.xml --output-dir /srv/audit

  # Only some interfaces, zones view only, raster PDF
  pyfrc2g --backup config.xml --interfaces lan,opt1 --view zones --raster

  # Enable debug logging
  pyfrc2g --api --debug
        """
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--api", "-a", action="store_true",
                      help="Fetch rules from firewall API (default if no mode; configure pyfrc2g/config.py)")
    mode.add_argument("--backup", "-b", metavar="FILE", nargs="+",
                      help="Read rules from one or several XML backup files (pfSense or OPNSense config.xml)")
    parser.add_argument("--gateway-name", "-g", metavar="NAME",
                        help="Gateway display name (single firewall/backup only)")
    parser.add_argument("--output-dir", "-o", metavar="DIR", default="results",
                        help="Base output directory (default: results); files go to DIR/<gateway>/")
    parser.add_argument("--force", "-f", action="store_true",
                        help="Regenerate outputs even if no rule changed since the previous run")
    parser.add_argument("--interfaces", "-i", metavar="LIST",
                        help="Comma-separated interfaces to process (e.g. lan,opt1); floating rules are kept")
    parser.add_argument("--view", choices=("all", "rules", "zones"), default="all",
                        help="Graphs to include: rules (per-rule flows), zones (network view) or all")
    parser.add_argument("--raster", action="store_true",
                        help="Render graphs as PNG on A4 pages instead of vector PDF")
    parser.add_argument("--no-nat", action="store_true", help="Do not include NAT port forwards")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug logging")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output (same as --debug)")
    parser.add_argument("--skip-config-check", action="store_true",
                        help="Skip configuration check before running (API mode only)")
    parser.add_argument("--check-deps", action="store_true",
                        help="Check that required packages are installed, then exit (0=OK, 1=missing deps)")
    return parser.parse_args(argv)


def main(argv=None):
    """
    Entry point for the pyfrc2g console script.

    Args:
        argv: Optional list of arguments (default: sys.argv[1:]).

    Returns:
        int: Exit code (0 on success).
    """
    args = parse_args(argv)
    if args.check_deps:
        ok, err = check_dependencies()
        if ok:
            print(f"All required packages are installed ({', '.join(REQUIRED_PACKAGES)}).")
            return 0
        print(err, file=sys.stderr)
        return 1
    logging.basicConfig(
        level=logging.DEBUG if (args.debug or args.verbose) else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    return _run(args) or 0


if __name__ == "__main__":
    sys.exit(main())
