"""App Manager: enumerate every app and run the standard owner actions.

Inspection (list / detail) is read-only. The actions (enable, disable,
force-stop, clear cache, clear data, uninstall, grant/revoke a permission,
set an app op) are the same operations a device owner runs from Settings or
`pm`/`am`/`appops`; they target only the device connected over the owner's
own adb. Every package/permission/op/component argument is validated against
a strict allowlist pattern and shell-quoted, so nothing shell-like reaches
the device. Destructive actions require an explicit confirm from the caller.
"""
from __future__ import annotations

import shlex

from ..adb.client import AdbError
from ..parsers.appops import parse_appops
from ..parsers.packagedump import parse_packages_dump, parse_pm_list

import re

_PKG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.]{1,254}$")
_PERM = re.compile(r"^[A-Za-z0-9_.]{1,128}$")
_OP = re.compile(r"^[A-Za-z0-9_:]{1,64}$")
_COMPONENT = re.compile(r"^[A-Za-z0-9_.]{1,254}/[A-Za-z0-9_.$]{1,254}$")
_MODES = {"allow", "deny", "ignore", "default", "foreground"}

DESTRUCTIVE = {"disable", "clear-data", "uninstall"}


def _vpkg(pkg: str) -> str:
    if not _PKG.match(pkg or ""):
        raise AdbError("invalid package name")
    return pkg


_USER_LINE = re.compile(r"UserInfo\{(\d+):([^:}]*):")


def list_users(adb) -> list[dict]:
    """Android users / profiles on the device: [{id, name, running}]."""
    try:
        out = adb.shell_sync("pm list users", timeout=15)
    except AdbError:
        return [{"id": 0, "name": "Owner", "running": True}]
    users = []
    for line in out.splitlines():
        m = _USER_LINE.search(line)
        if m:
            users.append({"id": int(m.group(1)), "name": m.group(2).strip() or f"user {m.group(1)}",
                          "running": "running" in line})
    return users or [{"id": 0, "name": "Owner", "running": True}]


def _pm_list(adb, flag: str, user: int | None = None, uninstalled: bool = False) -> tuple[dict, str]:
    """`pm list packages` with graceful fallbacks: some builds reject -i or -U.
    Returns (parsed, flags_used). `uninstalled` adds -u (packages removed for
    this user with `pm uninstall --user` but still on the device)."""
    scope = (f"--user {int(user)} " if user is not None else "") + ("-u " if uninstalled else "")
    attempts = [f"-f -i -U {flag}", f"-f -U {flag}", f"-f {flag}", flag, ""]
    for fl in attempts:
        cmd = ("pm list packages " + scope + fl).strip()
        try:
            out = adb.shell_sync(cmd, timeout=60)
        except AdbError:
            continue
        parsed = parse_pm_list(out)
        if parsed:
            return parsed, (scope + fl).strip()
    return {}, ""


def list_apps(dctx, which: str = "all", user: int | None = None,
              include_uninstalled: bool = True) -> dict:
    """Every package on the device for one user, incl. ones uninstalled for
    that user (debloated) when include_uninstalled.
    which: all|user|system|disabled|enabled|uninstalled."""
    from ..enrich.labels import BUILTIN_LABELS, label_for
    adb = dctx.adb
    flag = {"all": "", "user": "-3", "system": "-s", "disabled": "-d",
            "enabled": "-e", "uninstalled": ""}.get(which, "")
    want_uninst = include_uninstalled or which == "uninstalled"
    base, used = _pm_list(adb, flag, user, uninstalled=want_uninst)
    if not base:
        return {"apps": [], "count": 0, "flags": used, "users": list_users(adb),
                "error": "pm list packages returned nothing - is the device authorized?"}
    installed: set[str] | None = None
    if want_uninst:
        inst, _ = _pm_list(adb, flag, user, uninstalled=False)
        installed = set(inst)
    uflag = f"--user {int(user)} " if user is not None else ""
    try:
        disabled = set(parse_pm_list(adb.shell_sync(f"pm list packages {uflag}-d", timeout=20)))
    except AdbError:
        disabled = set()
    try:
        system = set(parse_pm_list(adb.shell_sync(f"pm list packages {uflag}-s -u", timeout=20)))
    except AdbError:
        system = set()
    sizes = (dctx.state.get("storage") or {}).get("apps") or {}
    god = dctx.state.get("godmode") or {}
    god_pkgs = {p for pkgs in god.values() for p in pkgs}
    labels: dict[str, str] = dctx.store.get_snapshot("labels") or {}
    out = []
    for pkg, b in base.items():
        is_installed = True if installed is None else (pkg in installed)
        if which == "uninstalled" and is_installed:
            continue
        szd = sizes.get(pkg, {})
        out.append({
            "package": pkg,
            "label": label_for(pkg, labels),
            "label_source": "apk" if pkg in labels else ("known" if pkg in BUILTIN_LABELS else "guess"),
            "system": pkg in system,
            "enabled": pkg not in disabled,
            "installed": is_installed,
            "installer": b.get("installer"),
            "uid": b.get("uid"),
            "data_size": szd.get("data", 0),
            "apk_size": szd.get("app", 0),
            "godmode": pkg in god_pkgs,
        })
    out.sort(key=lambda a: (a["label"].lower(), a["package"]))
    return {"apps": out, "count": len(out), "flags": used, "user": user,
            "users": list_users(adb),
            "uninstalled": sum(1 for a in out if not a["installed"]),
            "labels_resolved": sum(1 for a in out if a["label_source"] == "apk")}


def app_detail(dctx, pkg: str) -> dict:
    _vpkg(pkg)
    adb = dctx.adb
    dump = parse_packages_dump(adb.shell_sync(f"dumpsys package {shlex.quote(pkg)}", timeout=40))
    d = dump.get(pkg, {})
    # app-ops state for this package
    ops = []
    try:
        for a in parse_appops(adb.shell_sync(f"dumpsys appops {shlex.quote(pkg)}", timeout=20)):
            if a.package == pkg:
                ops.append({"op": a.op, "background": a.background,
                            "rejected": a.rejected, "ago": round(a.ago)})
    except AdbError:
        ops = []
    sizes = (dctx.state.get("storage") or {}).get("apps") or {}
    god = dctx.state.get("godmode") or {}
    return {
        "package": pkg,
        "detail": d,
        "appops": ops,
        "godmode": sorted(a for a, pkgs in god.items() if pkg in pkgs),
        "sizes": sizes.get(pkg, {}),
        "apk_paths": _safe(lambda: adb.apk_paths(pkg), []),
    }


def _safe(fn, default):
    try:
        return fn()
    except Exception:
        return default


def run_action(dctx, action: str, params: dict) -> dict:
    """Validate and run one owner action. Returns {ok, output, action}."""
    try:
        return _run_action(dctx, action, params)
    except AdbError as e:
        return {"ok": False, "output": str(e), "action": action}


def _run_action(dctx, action: str, params: dict) -> dict:
    adb = dctx.adb
    p = params or {}
    pkg = p.get("package", "")

    if action in DESTRUCTIVE and not p.get("confirm"):
        return {"ok": False, "output": "destructive action requires confirm=true",
                "action": action}
    try:
        user = int(p.get("user", 0) or 0)
    except (TypeError, ValueError):
        user = 0
    if not 0 <= user <= 999:
        return {"ok": False, "output": "invalid user id", "action": action}

    if action == "enable":
        cmd = f"pm enable --user {user} {shlex.quote(_vpkg(pkg))}"
    elif action == "disable":
        cmd = f"pm disable-user --user {user} {shlex.quote(_vpkg(pkg))}"
    elif action == "force-stop":
        cmd = f"am force-stop {shlex.quote(_vpkg(pkg))}"
    elif action == "clear-data":
        cmd = f"pm clear --user {user} {shlex.quote(_vpkg(pkg))}"
    elif action == "clear-cache":
        _vpkg(pkg)
        cmd = (f"rm -rf /data/data/{pkg}/cache/* /data/data/{pkg}/code_cache/* "
               f"2>/dev/null; echo cleared")
    elif action == "uninstall":
        cmd = f"pm uninstall --user {user} {shlex.quote(_vpkg(pkg))}"
    elif action == "reinstall":
        # bring back an app that was removed for this user (the usual debloat),
        # using the copy still on the device - no download needed
        cmd = f"pm install-existing --user {user} {shlex.quote(_vpkg(pkg))}"
    elif action in ("grant", "revoke"):
        perm = p.get("permission", "")
        if not _PERM.match(perm):
            return {"ok": False, "output": "invalid permission", "action": action}
        cmd = f"pm {action} {shlex.quote(_vpkg(pkg))} {shlex.quote(perm)}"
    elif action == "appop":
        op = p.get("op", "")
        mode = p.get("mode", "")
        if not _OP.match(op) or mode not in _MODES:
            return {"ok": False, "output": "invalid op or mode", "action": action}
        cmd = f"appops set {shlex.quote(_vpkg(pkg))} {shlex.quote(op)} {shlex.quote(mode)}"
    elif action in ("enable-component", "disable-component"):
        comp = p.get("component", "")
        if not _COMPONENT.match(comp):
            return {"ok": False, "output": "invalid component", "action": action}
        verb = "enable" if action == "enable-component" else "disable"
        cmd = f"pm {verb} {shlex.quote(comp)}"
    else:
        return {"ok": False, "output": f"unknown action: {action}", "action": action}

    needs_root = action in ("clear-cache",)
    try:
        out = adb.shell_sync(cmd, su=needs_root, timeout=60).strip()
    except AdbError as e:
        return {"ok": False, "output": str(e), "action": action, "package": pkg}
    # pm/am print "Success" / "Failure [..]"; treat an explicit Failure as not-ok
    ok = "Failure" not in out and "Error" not in out and "Exception" not in out
    return {"ok": ok, "output": out or "(done)", "action": action, "package": pkg}
