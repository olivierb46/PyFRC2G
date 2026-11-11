"""
Processing pipeline for one firewall:

    load (API or configuration file) -> rows -> hit counters -> change detection
    -> analysis (changes, audit, policy, risk, matrix) -> outputs (CSV, PDF, HTML, Excel, CISO)

Also the comparison of two configuration files (--compare).
"""

import csv
import hashlib
import io
import logging
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path

from pyfrc2g.model.rules import (
    build_rule_rows,
    filter_by_interfaces,
    filter_by_ip_version,
    interface_of,
    is_automatic_entry,
)
from pyfrc2g.utils import safe_filename, update_api_maps

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def parse_interfaces(args):
    """--interfaces 'lan,opt1' -> ['lan', 'opt1'] (None when not given)."""
    value = getattr(args, "interfaces", None)
    return [i.strip() for i in value.split(",") if i.strip()] if value else None


def _csv_bytes(fieldnames, rows):
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, lineterminator="\n", extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue().encode("utf-8")


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _apply_maps(maps):
    update_api_maps(maps.get("interface_map", {}), maps.get("net_map", {}),
                    maps.get("address_map", {}), maps.get("port_map", {}),
                    maps.get("alias_details"), maps.get("interface_nets"))


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def read_backup(path, args):
    """Parse a configuration file in any supported format: (maps, entries, type, name, nat) or None."""
    from pyfrc2g.inputs import load_backup

    parsed = load_backup(path, getattr(args, "format", "auto"))
    return None if parsed[0] is None else parsed


def load_backup_file(path, args, gateway_name_override=None, default_name=None, target=None):
    """
    Read rules from a configuration file. Returns (config, entries, nat_entries, info) or None.
    Gateway name: override, else hostname found in the file, else default_name / file name.
    target: optional per-firewall settings (audit ports, WAN interfaces, meta, CISO ids...).
    """
    from pyfrc2g.config import Config

    logging.info(f"Mode: backup file (no API calls). File: {path}")
    parsed = read_backup(path, args)
    if parsed is None:
        return None
    maps, entries, gateway_type, name_from_file, nat_entries = parsed
    if not entries:
        logging.warning("No rules found in backup file - output may be empty")
    name = gateway_name_override or name_from_file or default_name or Path(path).stem
    config = Config(gateway_name_override=name,
                    gateway_type_override=gateway_type, output_base=args.output_dir, target=target)
    _apply_maps(maps)
    mode = maps.get("nat_outbound_mode")
    info = {"source": f"{gateway_type} backup {os.path.basename(os.path.normpath(path))}",
            "source_fingerprint": _sha256_file(path) if os.path.isfile(path) else "",
            "extra_meta": list(config.extra_meta) + ([("Outbound NAT mode", mode)] if mode else [])}
    hits_source = getattr(args, "hits", None)
    if hits_source == "api":
        logging.warning("--hits api needs API mode: give the output of 'pfctl -vvsr' as a file instead")
    elif hits_source:
        from pyfrc2g.analysis.hits import load_counters_file

        info["counters"] = load_counters_file(hits_source)
    return config, entries, nat_entries, info


def load_api(target, args, gateway_name_override=None):
    """Fetch rules from a firewall API. Returns (config, entries, nat_entries, info) or None."""
    from pyfrc2g.analysis.hits import load_counters_file
    from pyfrc2g.config import Config
    from pyfrc2g.inputs.api_client import new_client

    config = Config(gateway_name_override=gateway_name_override, target=target,
                    output_base=args.output_dir, interfaces_override=parse_interfaces(args))
    if config.gateway_type not in ("pfsense", "opnsense", "nfsensei"):
        logging.error(f"Unknown gateway type: {config.gateway_type}. Use 'pfsense', 'opnsense' or 'nfsensei'.")
        return None
    client = new_client(config)
    client.fetch_aliases()
    entries = client.fetch_rules()
    if not entries:
        # Do not overwrite the fingerprint / publish empty graphs when the API call failed.
        logging.error("Aborting: no rules retrieved from the API, previous results kept.")
        return None
    nat_entries = [] if args.no_nat else client.fetch_nat_rules()
    if config.interfaces and not parse_interfaces(args):
        # Selected interfaces of the target: the global rule list holds every interface.
        names = client.firewall_interface_names
        wanted = [*config.interfaces, *(names.get(str(i).lower(), "") for i in config.interfaces)]
        wanted = [w for w in wanted if w]
        entries = filter_by_interfaces(entries, wanted)
        nat_entries = filter_by_interfaces(nat_entries or [], wanted, keep_floating=False)
        logging.info(f"Interfaces {config.interfaces}: {len(entries)} rule(s) kept (floating rules included)")
    info = {"source": f"{config.gateway_type} API {config.base_url}", "extra_meta": list(config.extra_meta),
            # Aliases and interfaces of this firewall: installed again before the analysis, because the
            # lookup maps are process-wide and other firewalls may be loaded in parallel meanwhile.
            "maps": {"interface_map": client.interface_map, "net_map": client.net_map,
                     "address_map": client.address_map, "port_map": client.port_map,
                     "alias_details": client.alias_details, "interface_nets": client.interface_nets}}
    if not getattr(args, "no_hits", False):
        hits_source = getattr(args, "hits", None) or config.hits_source
        info["hits_source"] = hits_source
        if hits_source and hits_source != "api":
            info["counters"] = load_counters_file(hits_source)
        else:
            info["counters"] = client.fetch_rule_counters(hits_source)
    return config, entries, nat_entries, info


# ---------------------------------------------------------------------------
# One firewall
# ---------------------------------------------------------------------------

def _fingerprint(config, rows, nat_rows, hits):
    """SHA-256 of rules + NAT + rule usage statuses (packet counts alone do not trigger a run)."""
    from pyfrc2g.model.nat import NAT_FIELDNAMES

    statuses = "".join(f"{h['RULE ID']}={h['STATUS']};" for h in (hits[0] if hits else []))
    return hashlib.sha256(_csv_bytes(config.csv_fieldnames, rows) + _csv_bytes(NAT_FIELDNAMES, nat_rows)
                          + statuses.encode("utf-8")).hexdigest()


def process_firewall(loaded, args, from_backup):
    """Normalize rules, detect changes and generate outputs. Returns an exit code."""
    from pyfrc2g.analysis.hits import attach_counters, missing_counters_note, update_history
    from pyfrc2g.model.nat import nat_entry_to_row
    from pyfrc2g.outputs.ciso import CISOCClient

    config, entries, nat_entries, info = loaded
    if info.get("maps"):
        _apply_maps(info["maps"])
    interfaces = parse_interfaces(args)
    if interfaces:
        entries = filter_by_interfaces(entries, interfaces)
        nat_entries = filter_by_interfaces(nat_entries or [], interfaces, keep_floating=False)
        logging.info(f"Interfaces filter {interfaces}: {len(entries)} rule(s) kept")
    nat_entries = [] if args.no_nat else (nat_entries or [])
    automatic = [e for e in entries if is_automatic_entry(e, config.gateway_type)]
    if automatic and getattr(args, "no_automatic_rules", False):
        entries = [e for e in entries if not is_automatic_entry(e, config.gateway_type)]
        logging.info(f"{len(automatic)} automatic rule(s) generated by the firewall left out (--no-automatic-rules)")
    elif automatic:
        logging.info(f"{len(automatic)} automatic rule(s) generated by the firewall (column AUTOMATIC; "
                     "--no-automatic-rules to leave them out)")

    logging.info(f"Retrieved {len(entries)} rules from {config.gateway_type} ({config.gateway_name})")
    rows = build_rule_rows(entries, config)
    if getattr(args, "ip_version", None):
        rows = filter_by_ip_version(rows, args.ip_version)
        logging.info(f"IPv{args.ip_version} filter: {len(rows)} rule(s) kept")
    nat_rows = [nat_entry_to_row(e, config.any_value) for e in nat_entries]

    if info.get("counters"):
        matched = attach_counters(rows, info["counters"])
        logging.info(f"Hit counters matched for {matched}/{len(rows)} rule(s)")
    hits = None
    if any(row.get("_HITS") for row in rows):
        # Updated on every run, even without rule change: the history must keep growing.
        hits = update_history(os.path.join(config.graph_output_dir, "hits_history.json"), rows,
                              unused_days=config.unused_days)
    elif not getattr(args, "no_hits", False):
        info["hits_note"] = missing_counters_note(config.gateway_type, not from_backup,
                                                  info.get("hits_source"), info.get("counters"))
        logging.info(f"No rule hit counters: {info['hits_note']}")

    fingerprint = _fingerprint(config, rows, nat_rows, hits)
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
    generate_outputs(config, rows, nat_rows, info, args, CISOCClient(config), hits=hits)
    with open(fingerprint_file, "w", encoding="utf-8") as f:
        f.write(f"{fingerprint}\n")
    return 0


# ---------------------------------------------------------------------------
# Analysis and outputs
# ---------------------------------------------------------------------------

def _archive_previous(global_csv, history_dir, host_name):
    """Copy the previous global CSV to history/ (timestamped with its modification time)."""
    os.makedirs(history_dir, exist_ok=True)
    stamp = datetime.fromtimestamp(os.path.getmtime(global_csv)).strftime("%Y%m%d-%H%M%S")
    shutil.copy2(global_csv, os.path.join(history_dir, f"{host_name}_ALL_flows_{stamp}.csv"))


def analyse(config, rows, nat_rows, info, args, hits=None, global_csv=None):
    """
    Change report (against global_csv), audit + hit counters + compliance policy, risk score
    and zone matrix. Returns a RunReport.
    """
    from pyfrc2g.analysis.audit import audit_rules, sort_findings
    from pyfrc2g.analysis.changes import count_changes, diff_rules, read_rows
    from pyfrc2g.analysis.matrix import build_matrix
    from pyfrc2g.analysis.policy import evaluate_policies
    from pyfrc2g.analysis.risk import compute as compute_risk
    from pyfrc2g.analysis.risk import describe as describe_risk
    from pyfrc2g.outputs.pdf import RunReport

    hits_rows, hits_findings = hits or ([], [])
    previous_rows, previous_fields = read_rows(global_csv)
    changes = None
    if previous_rows is not None:
        changes = diff_rules(previous_rows, previous_fields, rows)
        counts = count_changes(changes)
        logging.info(f"Changes since previous run: {counts['ADDED']} added, "
                     f"{counts['MODIFIED']} modified, {counts['REMOVED']} removed")
    else:
        logging.info("No previous snapshot: change report starts with this run")

    findings = audit_rules(rows, config) + list(hits_findings)
    policies = getattr(args, "policies", None)
    if policies:
        violations = evaluate_policies(rows, policies)
        logging.info(f"Compliance policy: {len(violations)} violation(s)")
        findings += violations
    findings = sort_findings(findings)
    accepted = []
    exceptions = getattr(args, "exceptions", None)
    if exceptions:
        from pyfrc2g.analysis.exceptions import split

        findings, accepted = split(findings, exceptions, config.gateway_name)
        logging.info(f"Accepted risks: {len(accepted)} finding(s) left out of the audit")
    logging.info(f"Audit: {len(findings)} finding(s)")
    risk = compute_risk(findings, config.risk_weights,
                        os.path.join(config.graph_output_dir, "risk_history.json"), info["generated_at"])
    logging.info(f"Risk score: {describe_risk(risk)}")

    return RunReport(
        gateway_name=config.gateway_name, gateway_type=config.gateway_type, source=info["source"],
        generated_at=info["generated_at"], rules=rows, fingerprint=info["fingerprint"],
        source_fingerprint=info.get("source_fingerprint"), audit=findings, changes=changes,
        nat=nat_rows, interfaces_filter=info.get("interfaces_filter"), risk=risk,
        matrix=build_matrix(rows, config.gateway_type), hits=hits_rows,
        extra_meta=info.get("extra_meta"), hits_note=info.get("hits_note"), accepted=accepted,
    )


def write_csv_files(report, out, host, rule_fields):
    """Global CSV (next change report snapshot), audit, changes, NAT, rule usage and matrix CSVs."""
    from pyfrc2g.analysis.audit import AUDIT_FIELDNAMES
    from pyfrc2g.analysis.changes import CHANGES_FIELDNAMES
    from pyfrc2g.analysis.exceptions import ACCEPTED_FIELDNAMES
    from pyfrc2g.analysis.hits import HITS_FIELDNAMES
    from pyfrc2g.analysis.matrix import MATRIX_FIELDNAMES
    from pyfrc2g.model.nat import NAT_FIELDNAMES
    from pyfrc2g.outputs.csv_files import write_csv

    global_csv = write_csv(os.path.join(out, f"{host}_ALL_flows.csv"), rule_fields, report.rules)
    logging.info(f"✓ Global CSV created: {global_csv}")
    write_csv(os.path.join(out, f"{host}_AUDIT.csv"), AUDIT_FIELDNAMES, report.audit)
    optional = [("CHANGES", CHANGES_FIELDNAMES, report.changes), ("ACCEPTED", ACCEPTED_FIELDNAMES, report.accepted),
                ("NAT", NAT_FIELDNAMES, report.nat),
                ("HITS", HITS_FIELDNAMES, report.hits),
                ("MATRIX", MATRIX_FIELDNAMES, report.matrix["rows"] if report.matrix else None)]
    for suffix, fieldnames, rows in optional:
        if rows is not None and (rows or suffix == "CHANGES"):
            write_csv(os.path.join(out, f"{host}_{suffix}.csv"), fieldnames, rows)


def _short_name(name):
    name = safe_filename(name)
    return f"{name[:60]}_{hashlib.md5(name.encode(), usedforsecurity=False).hexdigest()[:8]}" if len(name) > 80 else name


def _zone_part(generator, rows, work_dir, title):
    """("Zones view", pdf) bookmark entry; assemble_pdf skips a None path."""
    page = generator.render_zone_graph(rows, work_dir, title)
    return "Zones view", page[1] if page else None


def write_pdf_files(report, config, args, out, host, rule_fields):
    """Global PDF and per-interface CSV + PDF (graphs rendered once, shared by both)."""
    from pyfrc2g.outputs.csv_files import write_csv
    from pyfrc2g.outputs.graphs import GraphGenerator
    from pyfrc2g.outputs.pdf import (
        assemble_pdf,
        write_accepted_pdf,
        write_audit_pdf,
        write_changes_pdf,
        write_hits_pdf,
        write_matrix_pdf,
        write_nat_pdf,
        write_summary_pdf,
    )

    view = getattr(args, "view", "all")
    groups = {}
    for row in report.rules:
        groups.setdefault(interface_of(row), []).append(row)

    generator = GraphGenerator(config, raster=getattr(args, "raster", False))
    with tempfile.TemporaryDirectory(prefix="pyfrc2g-") as work:
        rule_pages = {}
        if view in ("all", "rules"):
            for iface, group in groups.items():
                rule_pages[iface] = generator.render_rule_graphs(group, os.path.join(work, "rules"))

        parts = [
            ("Summary", write_summary_pdf(report, os.path.join(work, "summary.pdf"))),
            ("Changes", write_changes_pdf(report, os.path.join(work, "changes.pdf"))),
            ("Audit", write_audit_pdf(report, os.path.join(work, "audit.pdf"))),
            ("Accepted risks", write_accepted_pdf(report, os.path.join(work, "accepted.pdf"))),
            ("Zone matrix", write_matrix_pdf(report, os.path.join(work, "matrix.pdf"))),
            ("Rule usage", write_hits_pdf(report, os.path.join(work, "hits.pdf"))),
            ("NAT", write_nat_pdf(report, os.path.join(work, "nat.pdf"))),
        ]
        if view in ("all", "zones"):
            parts.append(_zone_part(generator, report.rules, os.path.join(work, "zones"),
                                    f"ZONES : {config.gateway_name}"))
        for pages in rule_pages.values():
            parts.extend(pages)
        global_pdf = os.path.join(out, f"{host}_FLOW_MATRIX.pdf")
        assemble_pdf(global_pdf, parts, f"Flow matrix for gateway {host}")
        logging.info(f"✓ Global PDF generated: {global_pdf}")

        for iface, group in groups.items():
            name = _short_name(iface)
            write_csv(os.path.join(out, f"{host}_{name}_flows.csv"), rule_fields, group)
            iface_parts = [("Summary", write_summary_pdf(
                report, os.path.join(work, f"summary_{name}.pdf"), rows=group, interface=iface))]
            if view in ("all", "zones"):
                iface_parts.append(_zone_part(generator, group, os.path.join(work, f"zones_{name}"),
                                              f"ZONES : {config.gateway_name} / {iface}"))
            iface_parts.extend(rule_pages.get(iface, []))
            assemble_pdf(os.path.join(out, f"{host}_{name}_FLOW_MATRIX.pdf"), iface_parts,
                         f"Flow matrix for gateway {host} - {iface}")
            logging.info(f"✓ Interface {iface}: {len(group)} rule(s)")
    return global_pdf


def generate_outputs(config, rows, nat_rows, report_info, args, ciso_client=None, hits=None):
    """
    Produce every output for one firewall and upload the global PDF to CISO Assistant.

    hits: (hits_rows, hits_findings) from hits.update_history, or None.
    """
    from pyfrc2g.outputs.excel import write_xlsx_report
    from pyfrc2g.outputs.html_report import write_html_report

    out = config.graph_output_dir
    os.makedirs(out, exist_ok=True)
    host = os.path.basename(os.path.normpath(out)) or "gateway"
    fields = config.csv_fieldnames
    global_csv = os.path.join(out, f"{host}_ALL_flows.csv")

    report = analyse(config, rows, nat_rows, report_info, args, hits, global_csv)
    if report.changes is not None:
        _archive_previous(global_csv, os.path.join(out, "history"), host)
    write_csv_files(report, out, host, fields)
    global_pdf = write_pdf_files(report, config, args, out, host, fields)

    html = write_html_report(report, os.path.join(out, f"{host}_REPORT.html"), fields)
    logging.info(f"✓ HTML report: {html}")
    if not getattr(args, "no_excel", False):
        xlsx = write_xlsx_report(report, os.path.join(out, f"{host}_FLOW_MATRIX.xlsx"), fields)
        if xlsx:
            logging.info(f"✓ Excel workbook: {xlsx}")

    if ciso_client is not None and ciso_client.enabled:
        logging.info("Uploading PDF to CISO Assistant...")
        stats = ciso_client.upload_global_pdf(global_pdf)
        if stats["failed"]:
            logging.warning(f"⚠ Failed to upload {stats['failed']} PDF(s) to CISO Assistant")
    return report


# ---------------------------------------------------------------------------
# Comparison of two firewalls
# ---------------------------------------------------------------------------

def run_compare(args):
    """--compare A B: write CSV / HTML / PDF difference reports. Returns an exit code."""
    from pyfrc2g.analysis.compare import (
        compare_aliases,
        compare_nat,
        compare_rules,
        write_comparison,
    )
    from pyfrc2g.config import Config
    from pyfrc2g.model.nat import nat_entry_to_row

    sides = []
    for path in args.compare:
        parsed = read_backup(path, args)
        if parsed is None:
            return 1
        maps, entries, gateway_type, name, nat_entries = parsed
        config = Config(gateway_name_override=name or Path(path).stem,
                        gateway_type_override=gateway_type, output_base=args.output_dir)
        _apply_maps(maps)  # Rows of each side are built with its own aliases.
        rows = build_rule_rows(filter_by_interfaces(entries, parse_interfaces(args)), config)
        rows = filter_by_ip_version(rows, getattr(args, "ip_version", None))
        nat_rows = [] if args.no_nat else [nat_entry_to_row(e, config.any_value) for e in nat_entries]
        sides.append({"path": path, "name": config.gateway_name, "type": gateway_type, "rows": rows,
                      "aliases": maps.get("alias_details", {}), "nat": nat_rows})
    a, b = sides
    name_a, name_b = safe_filename(a["name"]), safe_filename(b["name"])
    if name_a == name_b:
        name_a, name_b = safe_filename(Path(a["path"]).stem), safe_filename(Path(b["path"]).stem)
    differences = (compare_rules(a["rows"], b["rows"]) + compare_aliases(a["aliases"], b["aliases"])
                   + compare_nat(a["nat"], b["nat"]))
    meta = [("A", f"{a['name']} ({a['type']}, {os.path.basename(a['path'])}, {len(a['rows'])} rules)"),
            ("B", f"{b['name']} ({b['type']}, {os.path.basename(b['path'])}, {len(b['rows'])} rules)"),
            ("Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            ("Differences", str(len(differences)))]
    write_comparison(args.output_dir, name_a, name_b, differences, meta)
    logging.info(f"{len(differences)} difference(s) between {a['name']} and {b['name']}")
    return 0
