"""
Graph generation module for PyFRC2G.

Graphs are rendered by Graphviz directly to PDF (vector, searchable text). The raster
mode (PNG placed on an A4 page) is kept as an option and as a fallback when the local
Graphviz build has no PDF output.
"""

import csv
import html
import logging
import os
import subprocess
import textwrap
from collections import OrderedDict

from graphviz import Digraph

from pyfrc2g.config import ANY_VALUE, DISABLED_LABEL, FLOATING_RULES_LABELS, UNKNOWN_LABEL
from pyfrc2g.utils import format_alias_label, normalize_ports, safe_filename

LABEL_WRAP_WIDTH = 40
ZONE_EDGE_MAX_LINES = 6
_RECORD_SPECIAL_CHARS = '\\{}|<>"'

ACTION_COLORS = {"PASS": "#a3f7a3", "BLOCK": "#f7a3a3", "REJECT": "#f7a3a3"}
EDGE_COLORS = {"PASS": "#2e7d32", "BLOCK": "#c62828", "REJECT": "#c62828"}
DISABLED_COLOR = "#ffcc00"
FONT = "Helvetica,Arial,sans-serif"


def _clean_label(s, default=UNKNOWN_LABEL):
    """Return label with angle brackets removed, or default if empty."""
    if not s:
        return default
    return str(s).replace("<", "").replace(">", "").strip() or default


def _escape_record_text(text):
    """Escape characters that have a special meaning in Graphviz record labels."""
    for ch in _RECORD_SPECIAL_CHARS:
        text = text.replace(ch, "\\" + ch)
    return text


def record_label(fields, width=LABEL_WRAP_WIDTH):
    """
    Build a Graphviz record label from a list of fields.
    Each field is wrapped independently and escaped, so user data (comments, aliases)
    containing '|', '{', '<'... cannot break the record layout.
    """
    rendered = []
    for field in fields:
        lines = textwrap.wrap(str(field), width=width) or [""]
        rendered.append(r"\n".join(_escape_record_text(line) for line in lines))
    return " | ".join(rendered)


def _plain_label(lines, width=LABEL_WRAP_WIDTH):
    """Multi-line label for non-record shapes (backslashes escaped, lines joined with \\n)."""
    out = []
    for line in lines:
        out.extend(textwrap.wrap(str(line).replace("\\", "\\\\"), width=width) or [""])
    return r"\n".join(out)


def _interface_from_gateway(gateway):
    """Return interface part of a 'gateway/interface' value."""
    return gateway.split("/", 1)[1] if "/" in gateway else gateway


def _is_true(value):
    return (value or "").strip() in ("True", "1")


def load_rows(csv_path):
    """Read a rules CSV into a list of dicts."""
    with open(csv_path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


class GraphGenerator:
    """Graph generator for firewall rules."""

    def __init__(self, config, raster=False):
        self.config = config
        self.raster = raster

    # ------------------------------------------------------------------ rendering

    def _render(self, graph, work_dir):
        """Render a graph to a single-page PDF in work_dir and return its path."""
        from pyfrc2g.reports import png_to_pdf

        if not self.raster:
            graph.format = "pdf"
            try:
                return graph.render(directory=work_dir, cleanup=True)
            except subprocess.CalledProcessError as e:
                logging.warning(f"Graphviz cannot produce PDF ({e}); falling back to PNG rendering")
                self.raster = True
        graph.format = "png"
        png_path = graph.render(directory=work_dir, cleanup=True)
        return png_to_pdf(png_path, os.path.splitext(png_path)[0] + ".pdf")

    @staticmethod
    def _new_graph(name, title):
        g = Digraph("g", filename=f"{safe_filename(name)}.gv")
        g.attr(fontname=FONT, rankdir="LR")
        g.attr("node", fontname=FONT, fontsize="11")
        g.attr("edge", fontname=FONT, fontsize="9")
        g.attr(label=f"<<b>{html.escape(title)}</b>>", labelloc="t", fontsize="14")
        return g

    # ------------------------------------------------------------------ rules view

    def _build_flows(self, rows, interface_filter=None):
        """Return {gateway: {source: {"nodes": ..., "edges": ...}}} from rule rows."""
        flows_by_gateway = OrderedDict()
        next_id = 0

        def get_node(nodes, key, label, color=None, force_unique=False):
            """Create or retrieve a node (by cluster/source unless force_unique)."""
            nonlocal next_id
            actual_key = f"{key}__{next_id}" if force_unique else key
            if actual_key not in nodes:
                nodes[actual_key] = (f"node{next_id}", color, label)
                next_id += 1
            return nodes[actual_key][0]

        for row in rows:
            floating = _is_true(row.get("FLOATING"))
            gateway = "Floating-rules" if floating else (row.get("GATEWAY") or "").strip()

            if interface_filter and _interface_from_gateway(gateway) != interface_filter:
                continue

            source = (row.get("SOURCE") or "").strip()
            action = (row.get("ACTION") or "").strip().upper()
            protocol = (row.get("PROTOCOL") or "").strip() or ANY_VALUE
            ports = normalize_ports(row.get("PORT"), ANY_VALUE)
            destination = (row.get("DESTINATION") or "").strip()
            comment = _clean_label(row.get("COMMENT"), default="")
            disabled = _is_true(row.get("DISABLED"))
            rule_number = (row.get("RULE ORDER") or "").strip()

            source_fmt = format_alias_label(source, _clean_label(source))
            destination_fmt = format_alias_label(destination, _clean_label(destination))
            port_fmt = format_alias_label(ports, ports)

            if comment:
                destination_fields = [f"Rule #{rule_number}", destination_fmt, comment]
            else:
                destination_fields = [f"Rule #{rule_number}", "VLAN", destination_fmt]
            if disabled:
                destination_fields.append(DISABLED_LABEL)

            sources = flows_by_gateway.setdefault(gateway, OrderedDict())
            cluster = sources.setdefault(source, {"nodes": OrderedDict(), "edges": set()})
            nodes = cluster["nodes"]

            n_source = get_node(nodes, f"SOURCE|{source_fmt}", ["SOURCE", source_fmt])
            n_gateway = get_node(nodes, f"GATEWAY|{gateway}", ["GATEWAY", _clean_label(gateway)])
            n_action = get_node(nodes, f"ACTION|{action}", ["ACTION", _clean_label(action)],
                                color=ACTION_COLORS.get(action))
            proto_key = f"{protocol}|{action}"
            n_proto = get_node(nodes, proto_key, ["PROTOCOL", protocol])
            port_key = f"{ports}|{proto_key}"
            n_port = get_node(nodes, port_key, ["PORT", port_fmt])

            is_floating = any(label in gateway for label in FLOATING_RULES_LABELS)
            n_destination = get_node(
                nodes, "|".join(destination_fields), destination_fields,
                force_unique=not is_floating,
                color=DISABLED_COLOR if disabled else None,
            )

            cluster["edges"].update([
                (n_source, n_gateway), (n_gateway, n_action), (n_action, n_proto),
                (n_proto, n_port), (n_port, n_destination),
            ])
        return flows_by_gateway

    def render_rule_graphs(self, rows, work_dir, interface_filter=None):
        """
        Render one rules graph per gateway/interface.

        Returns:
            list: (bookmark title, pdf path) for each graph.
        """
        os.makedirs(work_dir, exist_ok=True)
        pages = []
        for gateway, sources in self._build_flows(rows, interface_filter).items():
            title = _clean_label(gateway, default="Gateway")
            g = self._new_graph(f"rules_{gateway}", f"GATEWAY : {title}")
            g.attr("node", shape="record")
            g.attr(color="#8888ff")
            for index, (source, cluster) in enumerate(sources.items()):
                with g.subgraph(name=f"cluster_{index}") as sg:
                    sg.attr(label=f"SOURCE : {source}", style="dashed", color="#aaaaaa")
                    for nid, color, fields in cluster["nodes"].values():
                        style = {"style": "filled", "fillcolor": color} if color else {}
                        sg.node(nid, label=record_label(fields), **style)
                    for src, dst in sorted(cluster["edges"]):
                        sg.edge(src, dst)
            path = self._render(g, work_dir)
            pages.append((title, path))
            logging.info(f"✓ Graph generated: {title}")
        return pages

    # ------------------------------------------------------------------ zones view

    def render_zone_graph(self, rows, work_dir, title):
        """
        Network-centric view: one node per source/destination, one edge per
        (source, destination, action) aggregating protocols/ports and interfaces.

        Returns:
            tuple: (bookmark title, pdf path), or None if there is no rule.
        """
        if not rows:
            return None
        os.makedirs(work_dir, exist_ok=True)
        nodes = OrderedDict()
        edges = OrderedDict()
        for row in rows:
            src = (row.get("SOURCE") or ANY_VALUE).strip()
            dst = (row.get("DESTINATION") or ANY_VALUE).strip()
            action = (row.get("ACTION") or "").strip().upper()
            disabled = _is_true(row.get("DISABLED"))
            for endpoint in (src, dst):
                nodes.setdefault(endpoint, f"z{len(nodes)}")
            iface = "Floating" if _is_true(row.get("FLOATING")) else \
                _interface_from_gateway((row.get("GATEWAY") or "").strip())
            service = f"{(row.get('PROTOCOL') or ANY_VALUE).strip()} " \
                      f"{normalize_ports(row.get('PORT'), ANY_VALUE)}"
            edges.setdefault((src, dst, action, disabled), OrderedDict())[f"{iface}: {service}"] = None

        g = self._new_graph("zones", title)
        g.attr(nodesep="0.3", ranksep="1.2")
        g.attr("node", shape="box", style="rounded,filled", fillcolor="#eef2f7", color="#7a8899")
        for name, nid in nodes.items():
            g.node(nid, label=_plain_label([format_alias_label(name, name)]))
        for (src, dst, action, disabled), services in edges.items():
            lines = list(services)
            if len(lines) > ZONE_EDGE_MAX_LINES:
                lines = lines[:ZONE_EDGE_MAX_LINES] + [f"+{len(services) - ZONE_EDGE_MAX_LINES} more"]
            if disabled:
                lines.append("(disabled)")
            attrs = {"color": EDGE_COLORS.get(action, "#607d8b"), "fontcolor": "#37474f"}
            if disabled:
                attrs.update(style="dashed", color="#9e9e9e")
            g.edge(nodes[src], nodes[dst], label=_plain_label([f"{action}"] + lines, width=60),
                   **attrs)
        path = self._render(g, work_dir)
        logging.info(f"✓ Zone graph generated ({len(nodes)} zones, {len(edges)} flows)")
        return title, path
