"""
Analyses of the web application.

Each analysis runs the regular pipeline (pipeline.process_firewall) in a private temporary
directory: the state of the previous run (rules snapshot, risk and hit counter history,
fingerprint) is decrypted from the database into it, the reports are generated, then
everything is read back, encrypted into the database, and the directory is deleted. Nothing
readable stays on disk.

One analysis at a time (the alias maps of the analysis modules are process-wide).
"""

import csv
import json
import logging
import mimetypes
import os
import queue
import re
import shutil
import tarfile
import tempfile
import threading
import time
import traceback
import zipfile

from pyfrc2g_web.db import now

RUN_LOCK = threading.RLock()
ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz")
MAX_ARCHIVE_SIZE = 200 * 1024 * 1024
AUDIT_FIELDS = ("SEVERITY", "CHECK", "GATEWAY", "RULE ORDER", "RULE ID", "RULE", "DETAIL")
STATE_FILES = ("risk_history.json", "hits_history.json", "fingerprint.txt")
INTERNAL_FILES = set(STATE_FILES)


class JobError(Exception):
    pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def safe_name(filename):
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", os.path.basename(filename or "upload")).strip("._")
    return name[:100] or "upload"


def base_name(filename):
    """'fw-lyon.conf' -> 'fw-lyon' (default gateway name of an uploaded file)."""
    name = safe_name(filename)
    for suffix in (*ARCHIVE_SUFFIXES, ".xml", ".conf", ".txt", ".json", ".cfg"):
        if name.lower().endswith(suffix) and len(name) > len(suffix):
            return name[: -len(suffix)]
    return name


def _extract(archive, target):
    """Extract a zip / tar archive without leaving target (no absolute paths, '..', links)."""
    root = os.path.realpath(target)
    total = 0

    def check(name, size):
        nonlocal total
        if not os.path.realpath(os.path.join(root, name)).startswith(root + os.sep):
            raise JobError(f"unsafe path in archive: {name}")
        total += size
        if total > MAX_ARCHIVE_SIZE:
            raise JobError("archive too large once extracted")

    if archive.lower().endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                check(info.filename, info.file_size)
            zf.extractall(root)
    else:
        with tarfile.open(archive) as tf:
            members = [m for m in tf.getmembers() if m.isfile() or m.isdir()]
            for member in members:
                check(member.name, member.size)
            extra = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
            tf.extractall(root, members=members, **extra)


NFSENSEI_CONFIG_NAMES = ("running.yaml", "config.yaml.lkg")


def slim_upload(filename, content):
    """
    A full nfSensei backup archive (the whole /etc/nfsensei folder, hundreds of MB, with API key
    hashes and certificates) is reduced to its running.yaml before being stored. Anything else is
    returned unchanged. Returns (filename, content).
    """
    import io

    lowered = (filename or "").lower()
    if not lowered.endswith(ARCHIVE_SUFFIXES):
        return filename, content
    wanted = None
    try:
        if lowered.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                names = [i.filename for i in zf.infolist() if not i.is_dir() and i.filename.count("/") <= 1]
                for config_name in NFSENSEI_CONFIG_NAMES:
                    wanted = next((n for n in names if os.path.basename(n) == config_name), None)
                    if wanted:
                        return f"{base_name(filename)}-{config_name}", zf.read(wanted)
        else:
            with tarfile.open(fileobj=io.BytesIO(content)) as tf:
                members = [m for m in tf.getmembers() if m.isfile() and m.name.lstrip("./").count("/") <= 1]
                for config_name in NFSENSEI_CONFIG_NAMES:
                    member = next((m for m in members if os.path.basename(m.name) == config_name), None)
                    if member is not None and member.size < 5 * 1024 * 1024:
                        return f"{base_name(filename)}-{config_name}", tf.extractfile(member).read()
    except (OSError, tarfile.TarError, zipfile.BadZipFile, KeyError):
        pass
    return filename, content


def _input_path(work, filename, content):
    """Write an uploaded file into work/input and return the file or directory to parse."""
    folder = os.path.join(work, "input")
    os.makedirs(folder, exist_ok=True)
    saved = os.path.join(folder, safe_name(filename))
    with open(saved, "wb") as f:
        f.write(content)
    if not saved.lower().endswith(ARCHIVE_SUFFIXES):
        return saved
    target = os.path.join(folder, "extracted")
    os.makedirs(target)
    _extract(saved, target)
    entries = [os.path.join(target, e) for e in os.listdir(target)]
    return entries[0] if len(entries) == 1 and os.path.isfile(entries[0]) else target


def _read_csv(path):
    if not os.path.isfile(path):
        return None
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _read_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Settings applied to the analysis modules
# ---------------------------------------------------------------------------

def apply_settings(settings):
    """Install the audit / TLS settings of the database into the configuration module."""
    from pyfrc2g import config as cfg

    cfg.WAN_INTERFACES = list(settings["wan_interfaces"])
    cfg.ADMIN_PORTS = list(settings["admin_ports"])
    cfg.SENSITIVE_PORTS = list(settings["sensitive_ports"])
    cfg.UNUSED_DAYS = int(settings["unused_days"])
    cfg.VERIFY_SSL = bool(settings["verify_ssl"])
    cfg.CA_BUNDLE = None
    cfg.POLICY_FILE = None
    # CISO Assistant uploads are done by the web application (ciso.py), never by the engine.
    cfg.CISO_URL = "https://<CISO_ASSISTANT_ADDRESS>"
    cfg.CISO_TOKEN = "<CISO_ASSISTANT_TOKEN>"


def _args(work, extra=(), policy=""):
    """Engine arguments; policy: a YAML text or a list of YAML texts (their policies are added up)."""
    from pyfrc2g.analysis.policy import PolicyError, parse_policy
    from pyfrc2g.cli import parse_args

    args = parse_args(["--output-dir", work, *extra])
    args.policies = None
    texts = [policy] if isinstance(policy, str) else list(policy)
    policies = []
    for text in texts:
        if (text or "").strip():
            try:
                policies.extend(parse_policy(text))
            except PolicyError as e:
                raise JobError(f"invalid compliance policy: {e}") from e
    args.policies = policies or None
    return args


def firewall_target(firewall, work, opts=None):
    """Engine target dict (see config.FIREWALLS) from a firewall record; CA written to work/."""
    from pyfrc2g_web import fwopts

    conf = firewall["config"]
    target = fwopts.target(firewall, opts or fwopts.options(firewall))
    if (conf.get("ca_pem") or "").strip():
        path = os.path.join(work, f"ca-{firewall['id']}.pem")
        with open(path, "w", encoding="utf-8") as f:
            f.write(conf["ca_pem"])
        target["ca_bundle"] = path
    return target


def test_firewall(firewall, settings, tmp_dir):
    """
    Check the connection to a firewall (URL, credentials, TLS, interfaces, rules, counters).

    Returns (ok, lines, detected interfaces). Runs in the request: waits 5 s at most for a
    running analysis (the alias maps of the engine are shared).
    """
    from pyfrc2g.config import Config
    from pyfrc2g.inputs.api_client import new_client

    from pyfrc2g_web import fwopts

    if not RUN_LOCK.acquire(timeout=5):
        return False, ["An analysis is running: try again in a moment."], []
    capture = _Capture(logging.WARNING)
    root = logging.getLogger()
    root.addHandler(capture)
    os.makedirs(tmp_dir, mode=0o700, exist_ok=True)
    work = tempfile.mkdtemp(prefix="test-", dir=tmp_dir)
    lines, detected, ok = [], [], False
    try:
        apply_settings(settings)
        opts = fwopts.options(firewall)
        target = firewall_target(firewall, work, opts)
        target["interfaces"] = []  # Detect every interface, whatever is selected.
        client = new_client(Config(target=target, output_base=work))
        interfaces, nets, _, ports = client.fetch_aliases()
        if not interfaces and not nets and not ports:
            lines.append("✗ No interface nor alias returned: check the URL, the credentials and TLS.")
        else:
            lines.append(f"✓ Connected: {len(interfaces)} interface(s), {len(nets) + len(ports)} alias(es).")
            names = client.firewall_interface_names or interfaces  # Names before the labels.
            detected = [{"id": k, "name": v} for k, v in sorted(names.items())]
            entries = client.fetch_rules()
            ok = bool(entries)
            lines.append(f"✓ {len(entries)} rule(s) readable." if entries else "✗ No rule returned.")
            if opts["hits"]:
                counters = client.fetch_rule_counters("api" if firewall["type"] == "pfsense" else None)
                lines.append(f"✓ Hit counters for {len(counters)} rule(s)." if counters else
                             "⚠ Hit counters unavailable (see the privileges of the API key).")
    except Exception as e:  # Never break the page for a test.
        lines.append(f"✗ {e}")
    finally:
        root.removeHandler(capture)
        RUN_LOCK.release()
        shutil.rmtree(work, ignore_errors=True)
    seen = set()
    for line in capture.lines:  # Engine warnings / errors explain the failures.
        message = line.split(" ", 2)[-1]
        if message not in seen and "certificate verification disabled" not in message:
            seen.add(message)
            lines.append(f"• {message}")
    return ok, lines[:15], detected


# ---------------------------------------------------------------------------
# One analysis
# ---------------------------------------------------------------------------

def _restore_state(gateway_dir, host, state):
    os.makedirs(gateway_dir, exist_ok=True)
    files = dict(state or {})
    for name, text in files.items():
        if name in STATE_FILES or name == "snapshot.csv":
            target = os.path.join(gateway_dir, f"{host}_ALL_flows.csv" if name == "snapshot.csv" else name)
            with open(target, "w", encoding="utf-8") as f:
                f.write(text)


def _collect_state(gateway_dir, host):
    state = {}
    for name in STATE_FILES:
        path = os.path.join(gateway_dir, name)
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                state[name] = f.read()
    snapshot = os.path.join(gateway_dir, f"{host}_ALL_flows.csv")
    if os.path.isfile(snapshot):
        with open(snapshot, encoding="utf-8") as f:
            state["snapshot.csv"] = f.read()
    return state


def _matrix_from_rows(rows):
    if not rows:
        return None
    sources, destinations, cells = [], [], {}
    for row in rows:
        src, dst = row["SOURCE ZONE"], row["DESTINATION ZONE"]
        if src not in sources:
            sources.append(src)
        if dst not in destinations:
            destinations.append(dst)
        cells[f"{src}|{dst}"] = [row["STATUS"], row["DETAIL"]]
    return {"sources": sources, "destinations": destinations, "cells": cells}


def _render_svgs(config, rows, work):
    """Zones view and one rules graph per interface, as SVG (for the browser)."""
    from pyfrc2g.model.rules import interface_of
    from pyfrc2g.outputs.graphs import GraphGenerator

    generator = GraphGenerator(config, svg=True)
    out = os.path.join(work, "svg")
    graphs = []
    try:
        zone = generator.render_zone_graph(rows, out, f"ZONES : {config.gateway_name}")
        if zone:
            graphs.append(("graphs/zones.svg", zone[1]))
        groups = {}
        for row in rows:
            groups.setdefault(interface_of(row), []).append(row)
        for index, group in enumerate(groups.values()):
            for title, path in generator.render_rule_graphs(group, os.path.join(out, f"rules{index}")):
                graphs.append((f"graphs/{safe_name(title)}.svg", path))
    except Exception as e:  # Graphs are a bonus: never fail the analysis for them.
        logging.warning(f"SVG graphs not generated: {e}")
    result = []
    for name, path in graphs:
        with open(path, "rb") as f:
            result.append((name, "image/svg+xml", f.read()))
    return result


def _build_analysis(config, gateway_dir, host, source_label, run_id):
    """Data shown by the application + artifacts (reports, CSV, SVG graphs)."""
    from pyfrc2g.analysis.risk import level
    from pyfrc2g.model.rules import interface_stats

    rows = _read_csv(os.path.join(gateway_dir, f"{host}_ALL_flows.csv")) or []
    audit = _read_csv(os.path.join(gateway_dir, f"{host}_AUDIT.csv")) or []
    # Accepted risks are not in the audit CSV: keep them (without their justification, re-read from the
    # database) so that a later change of the exceptions can re-evaluate the analysis.
    accepted = _read_csv(os.path.join(gateway_dir, f"{host}_ACCEPTED.csv")) or []
    everything = audit + [{k: v for k, v in row.items() if k in AUDIT_FIELDS} for row in accepted]
    history = _read_json(os.path.join(gateway_dir, "risk_history.json"), [])
    last = history[-1] if history else {}
    score = last.get("score")
    previous = history[-2]["score"] if len(history) > 1 else None
    fingerprint = ""
    if os.path.isfile(os.path.join(gateway_dir, "fingerprint.txt")):
        with open(os.path.join(gateway_dir, "fingerprint.txt"), encoding="utf-8") as f:
            fingerprint = f.readline().strip()
    severities = {}
    for finding in audit:
        severities[finding["SEVERITY"]] = severities.get(finding["SEVERITY"], 0) + 1
    data = {
        "gateway": host, "gateway_type": config.gateway_type, "source": source_label,
        "generated": now(), "run_id": run_id, "fingerprint": fingerprint,
        "rules": rows, "audit": audit, "audit_all": everything, "severities": severities,
        "changes": _read_csv(os.path.join(gateway_dir, f"{host}_CHANGES.csv")),
        "nat": _read_csv(os.path.join(gateway_dir, f"{host}_NAT.csv")) or [],
        "hits": _read_csv(os.path.join(gateway_dir, f"{host}_HITS.csv")) or [],
        "matrix": _matrix_from_rows(_read_csv(os.path.join(gateway_dir, f"{host}_MATRIX.csv"))),
        "interfaces": [dict(name=k, **v) for k, v in interface_stats(rows).items()],
        "risk": {"score": score, "level": level(score) if score is not None else "",
                 "delta": None if score is None or previous is None else score - previous,
                 "by_interface": last.get("by_interface") or {}, "history": history[-60:]},
    }
    artifacts = []
    for directory, _, names in os.walk(gateway_dir):
        if os.path.basename(directory) == "history":
            continue
        for name in names:
            if name in INTERNAL_FILES:
                continue
            path = os.path.join(directory, name)
            with open(path, "rb") as f:
                artifacts.append((os.path.relpath(path, gateway_dir).replace(os.sep, "/"),
                                  mimetypes.guess_type(name)[0] or "application/octet-stream", f.read()))
    return data, artifacts


def _analyse_one(state, run_id, work, loaded, kind, source_label, firewall_id=None, upload_id=None, opts=None):
    """Run the pipeline on one loaded configuration and store the result (opts: firewall options)."""
    from pyfrc2g.pipeline import process_firewall

    from pyfrc2g_web import fwopts

    db, settings, args = state["db"], state["settings"], state["args"]
    config = loaded[0]
    host = os.path.basename(os.path.normpath(config.graph_output_dir))
    gateway_dir = config.graph_output_dir
    previous = db.gateway(host)
    _restore_state(gateway_dir, host, previous["state"] if previous else {})

    from pyfrc2g_web import exceptions as accepted

    args.exceptions = accepted.engine_list(db.exceptions())  # Accepted risks: left out of every report.
    process_firewall(loaded, args, from_backup=(kind == "upload"))

    report = os.path.join(gateway_dir, f"{host}_REPORT.html")
    summary = None
    data = artifacts = None
    if os.path.isfile(report):
        data, artifacts = _build_analysis(config, gateway_dir, host, source_label, run_id)
        from pyfrc2g_web import exceptions

        exceptions.apply(data, db.exceptions(), host)  # Accepted risks leave the findings and the score.
        if opts is None or opts["svg"]:
            artifacts += _render_svgs(config, data["rules"], work)
        summary = exceptions.summary(data)
    gateway_id = db.save_gateway(host, kind, config.gateway_type, _collect_state(gateway_dir, host),
                                 firewall_id=firewall_id, upload_id=upload_id, summary=summary)
    if opts is not None and kind == "upload":  # Settings given with the file: kept for the next analyses.
        db.set_gateway_options(gateway_id, opts)
    elif opts is not None:  # The firewall settings hold its CISO Assistant evidence and folder.
        db.set_gateway_evidence(gateway_id, opts["ciso_evidence_id"], opts["ciso_folder_id"])
    if data is not None:
        analysis_id = db.add_analysis(gateway_id, run_id, data, artifacts)
        db.prune_analyses(gateway_id, (opts or {}).get("retention") or settings.get("retention", 30))
        logging.info(f"✓ Analysis of {host} stored ({len(artifacts)} files, encrypted)")
        if fwopts.ciso_auto(opts, settings) if opts else settings.get("ciso_auto"):
            from pyfrc2g_web import ciso

            if ciso.configured(settings):
                ciso.send_analysis(db, settings, analysis_id, state["tmp_dir"], "automatic")
            else:
                logging.warning("Automatic CISO Assistant upload enabled but CISO Assistant is not configured")
    else:
        logging.info(f"{host}: no change since the previous analysis")
    return host


def _load_api_source(db, settings, source, work):
    """
    Read one API firewall (network bound). Returns (firewall, opts, args, loaded). Thread safe: it
    does not touch the process-wide state of the analysis (the alias maps come with `loaded`).
    """
    from pyfrc2g.cli import load_job

    from pyfrc2g_web import fwopts

    firewall = db.firewall(source["firewall_id"])
    if firewall is None:
        raise JobError("firewall not found")
    opts = fwopts.options(firewall)
    target = firewall_target(firewall, work, opts)
    extra = fwopts.arguments(opts, firewall["type"], settings)
    if source.get("force"):
        extra.append("--force")
    args = _args(work, extra, fwopts.policy_texts(opts, settings))
    loaded, _ = load_job(target, args, from_backup=False)
    if loaded is None:
        raise JobError(f"{firewall['name']}: rules could not be retrieved (see the log)")
    return firewall, opts, args, loaded


def _prefetch(state, settings, sources):
    """
    Reads the API firewalls of a run in parallel (settings: parallel_fetch). Returns
    {source index: (work dir, (firewall, opts, args, loaded) | JobError)}; the analyses and the
    reports stay sequential, as the analysis modules share process-wide state.
    """
    from pyfrc2g.utils import load_in_parallel

    db = state["db"]
    indexes = [i for i, s in enumerate(sources) if s["kind"] == "api"]
    workers = min(max(1, int(settings.get("parallel_fetch") or 1)), len(indexes))
    if workers < 2:
        return {}
    logging.info(f"Reading {len(indexes)} API firewall(s) with {workers} parallel worker(s)")
    works = {i: tempfile.mkdtemp(prefix="run-", dir=state["tmp_dir"]) for i in indexes}

    def load(index):
        try:
            return _load_api_source(db, settings, sources[index], works[index])
        except JobError as e:
            return e

    names = []
    for i in indexes:
        firewall = db.firewall(sources[i]["firewall_id"])
        names.append((firewall["name"] if firewall else f"firewall {sources[i]['firewall_id']}", i))
    results = load_in_parallel(names, load, workers)
    prefetched = {}
    for (_, index), result in zip(names, results):
        prefetched[index] = (works[index], JobError(str(result)) if isinstance(result, Exception)
                             and not isinstance(result, JobError) else result)
    return prefetched


def run_analysis(state, run_id, sources):
    """
    sources: [{"kind": "api", "firewall_id": id}] / [{"kind": "upload", "upload_id": id}].
    Returns an exit code (0 = every source analysed).
    """
    db = state["db"]
    settings = db.settings()
    apply_settings(settings)
    exit_code, gateways = 0, []
    os.makedirs(state["tmp_dir"], mode=0o700, exist_ok=True)
    from pyfrc2g.utils import install_thread_prefix

    install_thread_prefix()
    prefetched = _prefetch(state, settings, sources)
    try:
        return _run_sources(state, run_id, sources, settings, prefetched, exit_code, gateways)
    finally:
        for work, _ in prefetched.values():
            shutil.rmtree(work, ignore_errors=True)


def _run_sources(state, run_id, sources, settings, prefetched, exit_code, gateways):
    from pyfrc2g.pipeline import load_backup_file

    db = state["db"]
    for index, source in enumerate(sources):
        if source["kind"] == "ciso":
            from pyfrc2g_web import ciso

            ok, _ = ciso.send_analysis(db, settings, source["analysis_id"], state["tmp_dir"],
                                       source.get("username", "-"))
            gateways.extend(g for g in [source.get("gateway")] if g)
            db.update_run(run_id, gateways=gateways)
            exit_code = max(exit_code, 0 if ok else 1)
            continue
        work = prefetched[index][0] if index in prefetched else tempfile.mkdtemp(prefix="run-", dir=state["tmp_dir"])
        try:
            if source["kind"] == "upload":
                upload = db.upload(source["upload_id"])
                if upload is None:
                    raise JobError("upload not found")
                path = _input_path(work, upload["filename"], upload["content"])
                extra = ["--format", upload["format"]]
                if not settings.get("automatic_rules", True):
                    extra.append("--no-automatic-rules")
                args = _args(work, extra, settings.get("policy"))
                name = source.get("name") or None
                loaded = load_backup_file(path, args, gateway_name_override=name,
                                          default_name=base_name(upload["filename"]))
                if loaded is None:
                    raise JobError(f"{upload['filename']}: format not recognised or file unreadable")
                # The gateway name is known once the file is read: apply its own settings (and the
                # ones given with the upload), then read the file again with them.
                known = db.gateway(loaded[0].gateway_name)
                known = known if known and known["kind"] == "upload" else None
                hints = {key: source[key] for key in ("site", "ciso_folder_id", "ciso_evidence_id")
                         if source.get(key)}
                opts = None
                if hints or (known and known.get("options") is not None):
                    from pyfrc2g_web import fwopts

                    opts = fwopts.options({"config": {**((known or {}).get("options") or {}), **hints}})
                    extra = ["--format", upload["format"],
                             *fwopts.arguments(opts, loaded[0].gateway_type, settings)]
                    args = _args(work, extra, fwopts.policy_texts(opts, settings))
                    loaded = load_backup_file(path, args, gateway_name_override=name,
                                              default_name=base_name(upload["filename"]),
                                              target=fwopts.backup_target(opts))
                    if loaded is None:
                        raise JobError(f"{upload['filename']}: format not recognised or file unreadable")
                label = f"File {upload['filename']}"
                ids = {"upload_id": upload["id"]}
            else:
                if index in prefetched:
                    result = prefetched[index][1]
                    if isinstance(result, Exception):
                        raise result
                    firewall, opts, args, loaded = result
                else:
                    firewall, opts, args, loaded = _load_api_source(db, settings, source, work)
                label = f"API {firewall['config'].get('url')}"
                ids = {"firewall_id": firewall["id"]}
            state["args"], state["settings"] = args, settings
            gateways.append(_analyse_one(state, run_id, work, loaded, source["kind"], label, opts=opts, **ids))
            db.update_run(run_id, gateways=gateways)
        except JobError as e:
            logging.error(str(e))
            exit_code = 1
        finally:
            shutil.rmtree(work, ignore_errors=True)
    return exit_code


# ---------------------------------------------------------------------------
# Runner and scheduler
# ---------------------------------------------------------------------------

class _Capture(logging.Handler):
    def __init__(self, level=logging.INFO):
        super().__init__(level)
        self.lines = []
        self.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S"))

    def emit(self, record):
        self.lines.append(self.format(record))


class Runner:
    """Executes queued analyses one by one in a background thread."""

    def __init__(self, db, tmp_dir):
        self.db = db
        self.tmp_dir = tmp_dir
        self.queue = queue.Queue()
        db.fail_unfinished_runs()
        shutil.rmtree(tmp_dir, ignore_errors=True)  # Leftovers of a killed process.
        threading.Thread(target=self._work, name="pyfrc2g-runner", daemon=True).start()

    def submit(self, kind, label, sources, user_id=None):
        run_id = self.db.new_run(kind, label, user_id)
        self.queue.put((run_id, sources))
        return run_id

    def _work(self):
        while True:
            run_id, sources = self.queue.get()
            capture = _Capture()
            root = logging.getLogger()
            root.addHandler(capture)
            level = root.level
            root.setLevel(min(level, logging.INFO))  # The run log always has the INFO lines.
            self.db.update_run(run_id, status="running", started=now())
            status, code = "failed", 1
            try:
                with RUN_LOCK:
                    code = run_analysis({"db": self.db, "tmp_dir": self.tmp_dir}, run_id, sources)
                status = "ok" if code == 0 else "warning"
            except Exception as e:  # Keep the runner alive whatever happens.
                logging.error(f"Analysis failed: {e}")
                logging.debug(traceback.format_exc())
            finally:
                root.removeHandler(capture)
                root.setLevel(level)
                self.db.update_run(run_id, status=status, exit_code=code, finished=now(), log=capture.lines)


class Scheduler:
    """
    Every minute: queue an analysis of the enabled API firewalls that are due. Each firewall
    follows its own interval (firewall settings) or the global schedule, or is analysed manually
    only; the last scheduled analysis of each firewall is kept in the meta table.
    """

    def __init__(self, db, runner):
        self.db = db
        self.runner = runner
        threading.Thread(target=self._loop, name="pyfrc2g-scheduler", daemon=True).start()

    def _last(self, firewall_id):
        # Firewalls scheduled before the per-firewall schedule share the global timestamp.
        own = self.db.get_meta(f"last_schedule:{firewall_id}")
        return float(own if own is not None else self.db.get_meta("last_schedule", "0") or 0)

    def due_times(self):
        """{firewall id: next scheduled analysis (epoch)} of the enabled scheduled firewalls."""
        from pyfrc2g_web import fwopts

        settings = self.db.settings()
        due = {}
        for firewall in self.db.firewalls():
            if not firewall["enabled"]:
                continue
            interval = fwopts.schedule_interval(fwopts.options(firewall), settings)
            if interval:
                due[firewall["id"]] = max(self._last(firewall["id"]) + interval, time.time())
        return due

    def next_run(self):
        times = self.due_times()
        return min(times.values()) if times else None

    def _loop(self):
        while True:
            try:
                current = time.time()
                due = [fid for fid, when in self.due_times().items() if when <= current + 1]
                if due:
                    for firewall_id in due:
                        self.db.set_meta(f"last_schedule:{firewall_id}", str(current))
                    self.runner.submit("schedule", f"Scheduled analysis ({len(due)} firewall(s))",
                                       [{"kind": "api", "firewall_id": fid} for fid in due])
            except Exception as e:
                logging.error(f"Scheduler error: {e}")
            time.sleep(60)
