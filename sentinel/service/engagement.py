"""Engagement / scope gate for authorized testing.

An engagement records who authorized the work and what is in scope (app
packages and network hosts/CIDRs). Active modules call `require_scope` before
touching a target; when an engagement is active it refuses out-of-scope targets
and the `observe` mode. When no engagement is active, `require_scope` is a
no-op, so own-device use is unchanged. Everything is local; the point is an
auditable boundary, not a lock.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import time
import uuid
from typing import Any

_ENGAGEMENTS = "engagements"      # hub.store snapshot: {id: {...}}
_ACTIVE = "active_engagement"     # hub.store snapshot: {"id": <id>}

_MODES = ("observe", "active")


class ScopeError(Exception):
    """Raised when an active engagement forbids the requested target."""


def _store(hub):
    return hub.store


def _all(hub) -> dict[str, dict]:
    return _store(hub).get_snapshot(_ENGAGEMENTS) or {}


def _active_id(hub) -> str | None:
    return (_store(hub).get_snapshot(_ACTIVE) or {}).get("id")


def _public(e: dict) -> dict:
    """The engagement as the API exposes it (every field is already safe)."""
    return {
        "id": e["id"], "name": e.get("name", ""), "client": e.get("client", ""),
        "authorization_ref": e.get("authorization_ref", ""),
        "created": e.get("created"), "mode": e.get("mode", "active"),
        "scope_packages": e.get("scope_packages", []),
        "scope_hosts": e.get("scope_hosts", []), "deny": e.get("deny", []),
    }


def _as_list(v) -> list[str]:
    if isinstance(v, str):
        parts = v.replace(",", "\n").split("\n")
    elif isinstance(v, (list, tuple)):
        parts = v
    else:
        parts = []
    return [str(p).strip() for p in parts if str(p).strip()]


def list_engagements(hub) -> list[dict]:
    aid = _active_id(hub)
    return [{"id": e["id"], "name": e.get("name", ""), "active": e["id"] == aid}
            for e in _all(hub).values()]


def current(hub) -> dict | None:
    aid = _active_id(hub)
    e = _all(hub).get(aid) if aid else None
    return _public(e) if e else None


def create(hub, data: dict) -> dict:
    name = str((data or {}).get("name", "")).strip()
    if not name:
        raise ValueError("an engagement needs a name")
    mode = (data or {}).get("mode", "active")
    if mode not in _MODES:
        mode = "active"
    e = {
        "id": uuid.uuid4().hex[:12],
        "name": name,
        "client": str((data or {}).get("client", "")).strip(),
        "authorization_ref": str((data or {}).get("authorization_ref", "")).strip(),
        # time.time() is fine here (host clock); not used for crypto/ordering
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": mode,
        "scope_packages": _as_list((data or {}).get("scope_packages")),
        "scope_hosts": _as_list((data or {}).get("scope_hosts")),
        "deny": _as_list((data or {}).get("deny")),
    }
    alle = _all(hub)
    alle[e["id"]] = e
    _store(hub).put_snapshot(_ENGAGEMENTS, alle)
    _store(hub).put_snapshot(_ACTIVE, {"id": e["id"]})
    return _public(e)


def set_active(hub, eid: str) -> dict | None:
    if eid not in _all(hub):
        raise ValueError("no such engagement")
    _store(hub).put_snapshot(_ACTIVE, {"id": eid})
    return current(hub)


def set_mode(hub, mode: str) -> str:
    if mode not in _MODES:
        raise ValueError("mode must be observe or active")
    aid = _active_id(hub)
    alle = _all(hub)
    if not aid or aid not in alle:
        raise ValueError("no active engagement")
    alle[aid]["mode"] = mode
    _store(hub).put_snapshot(_ENGAGEMENTS, alle)
    return mode


def close(hub, eid: str) -> None:
    alle = _all(hub)
    alle.pop(eid, None)
    _store(hub).put_snapshot(_ENGAGEMENTS, alle)
    if _active_id(hub) == eid:
        _store(hub).put_snapshot(_ACTIVE, {})


# ---------------- scope matching ----------------

def _host_in(host: str, patterns: list[str]) -> bool:
    host = (host or "").strip().lower()
    if not host:
        return False
    for raw in patterns:
        pat = raw.strip().lower()
        if not pat:
            continue
        if "/" in pat:  # CIDR
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(pat, strict=False):
                    return True
            except ValueError:
                pass
            continue
        if pat.startswith("*."):
            if host == pat[2:] or host.endswith(pat[1:]):  # *.x matches x and sub.x
                return True
        elif fnmatch.fnmatch(host, pat) or host == pat:
            return True
    return False


def _pkg_in(pkg: str, patterns: list[str]) -> bool:
    pkg = (pkg or "").strip()
    return any(pkg == p.strip() or fnmatch.fnmatch(pkg, p.strip())
               for p in patterns if p.strip())


def require_scope(hub, pkg: str | None = None, host: str | None = None) -> None:
    """Raise ScopeError when an active engagement forbids this target. No-op
    when no engagement is active (own-device default)."""
    e_pub = current(hub)
    if not e_pub:
        return  # no engagement -> own-device use, unrestricted
    if e_pub["mode"] == "observe":
        raise ScopeError("the active engagement is in observe mode; switch to "
                         "active mode to run device-changing actions")
    if pkg is not None:
        if _pkg_in(pkg, e_pub["deny"]):
            raise ScopeError(f"{pkg} is on the engagement's deny list")
        if e_pub["scope_packages"] and not _pkg_in(pkg, e_pub["scope_packages"]):
            raise ScopeError(f"{pkg} is not in the engagement's package scope")
    if host is not None:
        if _host_in(host, e_pub["deny"]):
            raise ScopeError(f"{host} is on the engagement's deny list")
        if e_pub["scope_hosts"] and not _host_in(host, e_pub["scope_hosts"]):
            raise ScopeError(f"{host} is not in the engagement's host scope")
