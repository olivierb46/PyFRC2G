"""
Firewall scope of the users: which firewalls (gateways) a non-administrator may see.

A scope is None (every firewall) or {"sites": [...], "tags": [...], "firewalls": [...]}: a firewall
is visible when its name, its site or one of its tags is listed. Administrators are never
restricted. The scope of an SSO user comes from the group mapping (setting "group_scopes", edited in
Administration > Users) and is recomputed at each sign-in; the scope of a local user is set by hand.

When a group mapping exists, an SSO user matching none of its groups sees no firewall (deny by default).
"""

import json
import re

from flask import abort, current_app, g

from pyfrc2g_web import fwopts

KEYS = ("sites", "tags", "firewalls")
_ALIASES = {"site": "sites", "sites": "sites", "tag": "tags", "tags": "tags",
            "fw": "firewalls", "firewall": "firewalls", "firewalls": "firewalls"}
_ITEM = re.compile(r"^[\w .:/-]{1,64}$", re.UNICODE)


class ScopeError(ValueError):
    pass


def parse_scope(value):
    """Normalise a stored scope (JSON text, dict or None) to a dict, or None for no restriction."""
    if not value:
        return None
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {key: [] for key in KEYS}  # Corrupted: fail closed.
    if not isinstance(value, dict):
        return {key: [] for key in KEYS}
    return {key: sorted({str(x) for x in value.get(key) or []}) for key in KEYS}


def describe(scope):
    if scope is None:
        return "all firewalls"
    parts = [f"{key[:-1] if key != 'firewalls' else 'firewall'} {', '.join(scope[key])}"
             for key in KEYS if scope.get(key)]
    return "; ".join(parts) or "no firewall"


def _items(text):
    names = [item.strip() for item in re.split(r"[,\n]", text) if item.strip()]
    for name in names:
        if not _ITEM.match(name):
            raise ScopeError(f"Invalid name {name!r}: letters, digits, spaces, '.', ':', '/', '_' or '-'.")
    return names


def parse_scope_text(text):
    """Parse 'site: Paris, Lyon; tag: prod; fw: fw1' into a scope (empty text means None). Raise ScopeError."""
    text = (text or "").strip()
    if not text:
        return None
    scope = {key: set() for key in KEYS}
    for part in re.split(r"[;\n]", text):
        if not part.strip():
            continue
        label, sep, rest = part.partition(":")
        key = _ALIASES.get(label.strip().lower())
        if not sep or key is None:
            raise ScopeError(f"Unknown scope {part.strip()!r}: use site:, tag: or fw: followed by names.")
        scope[key].update(_items(rest))
    return {key: sorted(values) for key, values in scope.items()}


def scope_text(scope):
    if scope is None:
        return ""
    return "; ".join(f"{key[:-1] if key != 'firewalls' else 'fw'}: {', '.join(scope[key])}"
                     for key in KEYS if scope.get(key))


def parse_group_scopes(text):
    """Parse one rule per line, 'idp-group = site:Paris, tag:prod, fw:fw1', into a list of rule dicts.

    Blank lines and lines starting with '#' are ignored. Raise ScopeError on a malformed line.
    """
    rules = []
    for number, line in enumerate((text or "").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        group, sep, rest = line.partition("=")
        group = group.strip().lstrip("/")
        if not sep or not _ITEM.match(group):
            raise ScopeError(f"Line {number}: expected 'group = site:NAME, tag:NAME, fw:NAME'.")
        scope = {key: set() for key in KEYS}
        for item in _items(rest):
            label, colon, name = item.partition(":")
            key = _ALIASES.get(label.strip().lower())
            if not colon or key is None or not name.strip():
                raise ScopeError(f"Line {number}: {item!r} must look like site:NAME, tag:NAME or fw:NAME.")
            scope[key].add(name.strip())
        rules.append(dict(group=group, **{key: sorted(values) for key, values in scope.items()}))
    return rules


def group_scopes_text(rules):
    lines = []
    for rule in rules or []:
        items = [f"{label}:{name}" for key, label in (("sites", "site"), ("tags", "tag"), ("firewalls", "fw"))
                 for name in rule.get(key) or []]
        lines.append(f"{rule['group']} = {', '.join(items)}")
    return "\n".join(lines)


def scope_for_groups(rules, groups):
    """Return the scope of an SSO user from the group mapping and the token groups (None when there is no mapping)."""
    if not rules:
        return None
    wanted = {str(x).lstrip("/") for x in groups}
    scope = {key: set() for key in KEYS}
    for rule in rules:
        if rule["group"] in wanted:
            for key in KEYS:
                scope[key].update(rule.get(key) or [])
    return {key: sorted(values) for key, values in scope.items()}


# ---------------------------------------------------------------------------
# Enforcement
# ---------------------------------------------------------------------------

def user_scope(user=None):
    """Return the scope of `user` (default: current user); None for administrators."""
    user = user or g.user
    if user is None or user["role"] == "admin":
        return None
    return parse_scope(user.get("scope"))


def is_restricted(user=None):
    return user_scope(user) is not None


def labelled_gateways(db):
    """Every gateway with its site, tags, description and owner (from its firewall or file settings)."""
    labels = {f["id"]: fwopts.options(f) for f in db.firewalls()}
    gateways = db.gateways()
    for gw in gateways:
        opts = labels.get(gw["firewall_id"]) or (
            fwopts.options({"config": gw["options"]}) if gw.get("options") is not None else {})
        gw.update(site=opts.get("site", ""), tags=opts.get("tags", []), description=opts.get("description", ""),
                  owner=opts.get("owner", ""))
    return gateways


def allows(scope, gateway):
    if scope is None:
        return True
    return (gateway["name"] in scope["firewalls"] or bool(gateway.get("site")) and gateway["site"] in scope["sites"]
            or bool(set(gateway.get("tags") or []) & set(scope["tags"])))


def visible_gateways(db, user=None):
    scope = user_scope(user)
    return [gw for gw in labelled_gateways(db) if allows(scope, gw)]


def require_gateway(name):
    """Return the gateway `name` if the current user may see it, else abort with 404 (hides its existence)."""
    gateway = next((gw for gw in visible_gateways(current_app.db) if gw["name"] == name), None)
    if gateway is None:
        abort(404)
    return gateway


def run_visible(db, run, names=None, user=None):
    """True if the user may see an analysis run: their own, or one whose firewalls are all in their scope.

    A run that also covers firewalls outside the scope is hidden: its log names them (addresses, errors).
    """
    user = user or g.user
    if not is_restricted(user):
        return True
    if run.get("user_id") == user["id"]:
        return True
    names = visible_names(db, user) if names is None else names
    return bool(run["gateways"]) and set(run["gateways"]) <= names


def visible_names(db, user=None):
    return {gw["name"] for gw in visible_gateways(db, user)}
