"""
nfSensei (nftables based firewall): REST API client and configuration file parser.

API (read only, header "X-API-Key"; every answer is {"success": true, "data": ...}):
    GET /api/v1/config/running       the applied configuration (rules, NAT, tables = aliases, host name);
                                     /config/candidate = pending changes, not yet committed
    GET /api/v1/interfaces           interfaces: name, alias, role (wan / lan...), live addresses
    GET /api/v1/firewall/stats       per-rule hit counters (only rules with counters enabled)
    GET /api/v1/firewall/rules, /nat/rules, /nat/port-forwards   fallback when the configuration
                                     cannot be read (these list the CANDIDATE configuration)

Aliases are the "tables" of the configuration: name, alias_type (network / host / port...), entries
(addresses, networks, ports or other tables).

Configuration file: the running configuration (GET /api/v1/config/running, answer or its
"config" part, JSON or YAML such as candidate.yaml).

Rule fields: name, enabled, action (pass / block), interface (eth1, "any"), protocol (any, tcp,
udp, icmp, icmpv6), source / destination (CIDR, address, "any", "self" = the firewall),
destination_port ("80,443", "1000-2000"), address_family (inet / inet6, absent = both), state
("established,related"), direction (in), stack, icmpv6_types.
"""

import ipaddress
import json
import logging
import os
import re

from pyfrc2g.inputs import register_alias
from pyfrc2g.inputs.api_client import APIClient
from pyfrc2g.utils import add_interface_address, empty_maps, update_api_maps

_ACTIONS = {"drop": "block", "deny": "block", "accept": "pass", "allow": "pass"}


def _text(value):
    return str(value).strip() if value is not None else ""


def register_interfaces(maps, interfaces):
    """Fill the interface maps from interface dicts (API list or configuration)."""
    count = 0
    for item in interfaces or []:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        iface = _text(item["name"]).lower()
        label = _text(item.get("alias") or item.get("description")) or iface.upper()
        maps["interface_map"][iface] = label
        wan = _text(item.get("role")).lower() == "wan"
        addresses = item.get("addresses") or item.get("static_addresses") or []
        add_interface_address(maps["interface_nets"], iface, "dhcp", wan=wan)  # Registers the interface.
        for address in addresses if isinstance(addresses, list) else [addresses]:
            add_interface_address(maps["interface_nets"], iface, address, wan=wan)
        count += 1
    return count


def register_tables(maps, tables):
    """Aliases of nfSensei ("tables": name, alias_type, entries) in the lookup maps. Returns their number."""
    count = 0
    for table in tables or []:
        if not isinstance(table, dict) or not table.get("name"):
            continue
        entries = table.get("entries") or []
        content = " ".join(str(e) for e in entries) if isinstance(entries, list) else str(entries)
        alias_type = _text(table.get("alias_type")).lower() or "network"
        register_alias(maps, table["name"], alias_type, content, _text(table.get("description")))
        count += 1
    return count


def interface_variables(interfaces):
    """
    Built-in variables of the configuration ($LAN_SUBNET, $WAN_IP...) from the interfaces: for each
    interface, its role, alias and name give <NAME>_SUBNET (networks) and <NAME>_IP / <NAME>_ADDRESS.
    Interfaces without a static address (DHCP in a backup) define nothing.
    """
    variables = {}
    for item in interfaces or []:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        networks, addresses = [], []
        for text in item.get("addresses") or item.get("static_addresses") or []:
            try:
                iface = ipaddress.ip_interface(str(text))
            except ValueError:
                continue
            networks.append(str(iface.network))
            addresses.append(str(iface.ip))
        if not networks:
            continue
        for label in (item.get("role"), item.get("alias"), item.get("description"), item["name"]):
            key = re.sub(r"[^A-Za-z0-9]+", "_", _text(label)).strip("_").upper()
            if key:
                variables.setdefault(f"{key}_SUBNET", ",".join(networks))
                variables.setdefault(f"{key}_NETWORK", ",".join(networks))
                variables.setdefault(f"{key}_IP", ",".join(addresses))
                variables.setdefault(f"{key}_ADDRESS", ",".join(addresses))
    return variables


def _expand(value, variables):
    """'$LAN_SUBNET' / '!$LAN_SUBNET' -> its value; anything else (or unknown variable) unchanged."""
    if not isinstance(value, str) or "$" not in value:
        return value
    negate = value.startswith("!")
    name = (value[1:] if negate else value).strip()
    if name.startswith("${") and name.endswith("}"):
        name = "$" + name[2:-1]
    if name.startswith("$") and name[1:].upper() in variables:
        return ("!" if negate else "") + variables[name[1:].upper()]
    return value


def rule_entries(rules, counters=None, variables=None):
    """Rule entries (model of the pfSense parser) from nfSensei rule dicts, in the given order."""
    variables = variables or {}
    entries = []
    for rule in rules or []:
        if not isinstance(rule, dict) or not rule.get("name"):
            continue
        name = _text(rule["name"])
        action = _text(rule.get("action")).lower()
        action = _ACTIONS.get(action, action) or "block"
        interface = _text(rule.get("interface")).lower()
        floating = interface in ("", "any", "*")
        protocol = _text(rule.get("protocol")).lower()
        family = _text(rule.get("address_family")).lower()
        states = {s.strip().lower() for s in _text(rule.get("state")).split(",") if s.strip()}
        notes = [name]
        if rule.get("description"):
            notes.append(_text(rule["description"]))
        if rule.get("icmpv6_types"):
            notes.append("icmpv6 types " + ",".join(str(t) for t in rule["icmpv6_types"]))
        if rule.get("icmp_types"):
            notes.append("icmp types " + ",".join(str(t) for t in rule["icmp_types"]))
        if states:
            notes.append("state " + ",".join(sorted(states)))
        if rule.get("stack") and rule["stack"] != "production":
            notes.append(f"stack {rule['stack']}")
        entry = {
            "action": action, "type": action, "interface": "" if floating else interface,
            "source": _expand(rule.get("source") or "any", variables),
            "destination": _expand(rule.get("destination") or "any", variables),
            "protocol": None if protocol in ("", "any") else protocol,
            "destination_port": rule.get("destination_port") or None,
            "description": " - ".join(notes), "enabled": rule.get("enabled", True) is not False,
            "uuid": name, "floating": floating, "direction": _text(rule.get("direction")) or "in",
            "established_only": bool(states) and not states & {"new", "invalid"},
            "ipprotocol": {"inet": "inet", "inet6": "inet6"}.get(family, "inet46"),
        }
        if counters and name in counters:
            entry["_hits"] = counters[name]
        entries.append(entry)
    return entries


def nat_entries(outbound, port_forwards):
    """NAT entries from nfSensei NAT dicts (outbound: documented; port forwards: best effort)."""
    entries = []
    for item in outbound or []:
        if not isinstance(item, dict):
            continue
        target = item.get("translated_address") or item.get("translation")
        entries.append({"_nat_type": "OUTBOUND", "interface": item.get("interface"),
                        "protocol": item.get("protocol"), "source": item.get("source") or "any",
                        "destination": item.get("destination") or "any",
                        "target": None if target in (None, "", "interface") else target,
                        "disabled": item.get("enabled") is False,
                        "descr": item.get("description") or item.get("name") or "",
                        "uuid": item.get("name") or ""})
    for item in port_forwards or []:
        if not isinstance(item, dict):
            continue
        entries.append({"_nat_type": "PORT FORWARD", "interface": item.get("interface"),
                        "protocol": item.get("protocol"), "source": item.get("source") or "any",
                        "destination": item.get("destination") or item.get("external_address") or "any",
                        "destination_port": (item.get("destination_port") or item.get("external_port")
                                             or item.get("port")),
                        "target": (item.get("translated_address") or item.get("internal_address")
                                   or item.get("target") or item.get("to_address")),
                        "local_port": (item.get("translated_port") or item.get("internal_port")
                                       or item.get("target_port") or item.get("to_port")),
                        "disabled": item.get("enabled") is False,
                        "descr": item.get("description") or item.get("name") or "",
                        "uuid": item.get("name") or ""})
    return entries


def counters_from_stats(data):
    """{rule name: counters} from GET /firewall/stats. Only rules with counters enabled are kept."""
    counters = {}
    for item in (data or {}).get("rules") or []:
        if not isinstance(item, dict) or not item.get("counted"):
            continue
        total = counters.setdefault(str(item.get("rule_name")), {"packets": 0, "bytes": 0, "states": 0,
                                                                  "evaluations": 0})
        total["packets"] += int(item.get("hit_count") or 0)  # One rule can exist in several chains (v4 + v6).
        total["bytes"] += int(item.get("byte_count") or 0)
    return counters


# ---------------------------------------------------------------------------
# Configuration file
# ---------------------------------------------------------------------------

def unwrap_config(document):
    """The configuration dict of an API answer ({"data": {"config": ...}}), a {"config": ...} or the config."""
    for _ in range(3):
        if not isinstance(document, dict):
            break
        if "firewall" in document and "schema_version" in document:
            return document
        document = document.get("data") if "data" in document else document.get("config", document.get("data"))
    return None


def load_document(path):
    """JSON or YAML file -> object."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    try:
        return json.loads(text)
    except ValueError:
        pass
    try:
        import yaml

        return yaml.safe_load(text)
    except ImportError as e:
        raise ValueError("PyYAML is required for a YAML configuration (pip install pyyaml)") from e
    except Exception as e:
        raise ValueError(f"neither JSON nor YAML: {e}") from e


CONFIG_NAMES = ("running.yaml", "config.yaml.lkg", "candidate.yaml")


def find_config_file(directory):
    """running.yaml of an extracted nfSensei backup (the folder itself or one level down), else None."""
    for name in CONFIG_NAMES:
        for base in [directory] + sorted(os.path.join(directory, d) for d in os.listdir(directory)
                                         if os.path.isdir(os.path.join(directory, d))):
            candidate = os.path.join(base, name)
            if os.path.isfile(candidate):
                return candidate
    return None


def parse(path):
    """Configuration file (or extracted backup folder) -> (maps, entries, host name, nat entries)."""
    if os.path.isdir(path):
        found = find_config_file(path)
        if found is None:
            raise ValueError("no running.yaml in the nfSensei backup")
        path = found
    config = unwrap_config(load_document(path))
    if config is None:
        raise ValueError("not an nfSensei configuration (expected the running configuration)")
    maps = empty_maps()
    register_interfaces(maps, config.get("interfaces"))
    register_tables(maps, config.get("tables"))
    firewall = config.get("firewall") or {}
    nat = config.get("nat") or {}
    entries = rule_entries(firewall.get("rules"), variables=interface_variables(config.get("interfaces")))
    nats = nat_entries(nat.get("outbound"), nat.get("port_forward") or nat.get("inbound"))
    name = (config.get("system") or {}).get("hostname")
    return maps, entries, name, nats


# ---------------------------------------------------------------------------
# API client
# ---------------------------------------------------------------------------

class NfSenseiClient(APIClient):
    """Read-only client of the nfSensei REST API (same interface as the pfSense / OPNsense client)."""

    _config_cache = None
    _variables = None

    def _data(self, path, operation, timeout=30, log_level=logging.ERROR):
        """The "data" of an API answer, None on any failure (logged)."""
        headers = {"accept": "application/json", "X-API-Key": self.config.api_key}
        response = self._make_api_request(f"{self.config.base_url}{path}", headers=headers, timeout=timeout,
                                          operation=operation, log_level=log_level)
        if response is None:
            return None
        try:
            body = response.json()
        except ValueError:
            logging.log(log_level, f"{path}: the answer is not JSON (is the URL the one of the API, "
                                   "not of the web interface?)")
            return None
        if isinstance(body, dict) and body.get("success") is False:
            logging.log(log_level, f"{path}: {body.get('error') or 'request refused'}")
            return None
        return body.get("data") if isinstance(body, dict) and "data" in body else body

    def _config(self):
        """The configuration analysed (running = applied, candidate = pending), None if unreadable."""
        if self._config_cache is None:
            which = getattr(self.config, "nfsensei_config", "running")
            data = self._data(f"/api/v1/config/{which}", f"fetching the nfSensei {which} configuration",
                              log_level=logging.WARNING)
            self._config_cache = unwrap_config(data) or {}
            if self._config_cache:
                logging.info(f"✓ nfSensei {which} configuration read"
                             + (" (changes not yet committed)" if which == "candidate" else ""))
                self.config.extra_meta.append(("Configuration analysed",
                                               "candidate (not committed)" if which == "candidate" else "running"))
        return self._config_cache

    def _fetch_nfsensei_aliases(self):
        """Interfaces (names, roles, live networks) and aliases (the tables of the configuration)."""
        maps = empty_maps()
        data = self._data("/api/v1/interfaces", "fetching nfSensei interfaces", timeout=15)
        interfaces = (data or {}).get("interfaces") if isinstance(data, dict) else data
        count = register_interfaces(maps, interfaces)
        config = self._config()
        if not count:
            interfaces = config.get("interfaces")
            count = register_interfaces(maps, interfaces)
        self._variables = interface_variables(interfaces)
        tables = register_tables(maps, config.get("tables"))
        if count:
            logging.info(f"✓ Retrieved {count} interfaces and {tables} alias(es) from nfSensei API")
        self.interface_map, self.net_map = maps["interface_map"], maps["net_map"]
        self.address_map, self.port_map = maps["address_map"], maps["port_map"]
        self.alias_details, self.interface_nets = maps["alias_details"], maps["interface_nets"]
        update_api_maps(self.interface_map, self.net_map, self.address_map, self.port_map, self.alias_details,
                        self.interface_nets)
        return self.interface_map, self.net_map, self.address_map, self.port_map

    def fetch_rules(self):
        rules = (self._config().get("firewall") or {}).get("rules")
        if not isinstance(rules, list):  # Configuration unreadable: the rules endpoint (candidate).
            logging.warning("nfSensei configuration unavailable: reading /api/v1/firewall/rules "
                            "(it lists the candidate configuration, possibly not committed)")
            data = self._data("/api/v1/firewall/rules", "fetching nfSensei rules")
            rules = data.get("rules") if isinstance(data, dict) else data
        if not isinstance(rules, list):
            self._log_no_rules_error()
            return []
        entries = rule_entries(rules, variables=self._variables)
        logging.info(f"✓ Retrieved {len(entries)} rules from nfSensei API")
        return entries

    def fetch_nat_rules(self):
        nat = self._config().get("nat")
        if isinstance(nat, dict):
            entries = nat_entries(nat.get("outbound"), nat.get("port_forward") or nat.get("inbound"))
        else:
            outbound = self._data("/api/v1/nat/rules", "fetching nfSensei NAT", log_level=logging.WARNING)
            forwards = self._data("/api/v1/nat/port-forwards", "fetching nfSensei port forwards",
                                  log_level=logging.WARNING)
            entries = nat_entries((outbound or {}).get("rules") if isinstance(outbound, dict) else outbound,
                                  (forwards or {}).get("port_forwards") if isinstance(forwards, dict) else forwards)
        logging.info(f"✓ Retrieved {len(entries)} NAT rule(s)")
        return entries

    def fetch_rule_counters(self, source=None):
        data = self._data("/api/v1/firewall/stats", "fetching nfSensei rule statistics",
                          log_level=logging.WARNING)
        counters = counters_from_stats(data)
        if data is not None:
            logging.info(f"✓ nfSensei counters: {len(counters)} counted rule(s) "
                         f"({(data or {}).get('uncounted_count', 0)} rule(s) without counters)")
        return counters

    def fetch_host_name(self):
        """Host name of the firewall, None if unavailable."""
        name = ((self._config().get("system") or {}).get("hostname"))
        if name:
            return name
        data = self._data("/api/v1/system/info", "fetching nfSensei system information",
                          timeout=10, log_level=logging.DEBUG)
        return (data or {}).get("hostname") if isinstance(data, dict) else None
