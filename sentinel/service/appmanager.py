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

import posixpath
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
# find-package query: never reaches a shell, but keep it boring anyway
QUERY_RE = re.compile(r"^[A-Za-z0-9_. -]{1,64}$")
# one "pkg/Component" result line of `pm query-activities --brief`
_COMP_LINE = re.compile(r"^\s*([A-Za-z0-9_.]+)/([A-Za-z0-9_.$]+)\s*$")

DESTRUCTIVE = {"disable", "clear-data", "uninstall"}

# Fixed intent table for handlers(); constants only, never built from input.
_INTENTS: dict[str, str] = {
    "browser": "-a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d https://example.com",
    "launcher": "-a android.intent.action.MAIN -c android.intent.category.HOME",
    "sms": "-a android.intent.action.SENDTO -d sms:5551234",
    "dialer": "-a android.intent.action.DIAL -d tel:5551234",
    "camera": "-a android.media.action.IMAGE_CAPTURE",
}
_ROLES: dict[str, str] = {
    "browser": "android.app.role.BROWSER", "home": "android.app.role.HOME",
    "sms": "android.app.role.SMS", "dialer": "android.app.role.DIALER",
    "assistant": "android.app.role.ASSISTANT",
}
# where preinstalled APKs live (one folder per app); readable without root
_APK_DIRS = ("/system/app", "/system/priv-app", "/product/app", "/product/priv-app",
             "/system_ext/app", "/system_ext/priv-app", "/vendor/app", "/apex")


def _vpkg(pkg: str) -> str:
    if not _PKG.match(pkg or ""):
        raise AdbError("invalid package name")
    return pkg


def _vuser(user) -> int:
    try:
        u = int(user)
    except (TypeError, ValueError):
        raise AdbError("invalid user id") from None
    if not 0 <= u <= 999:
        raise AdbError("invalid user id")
    return u


def _snapshot(dctx, name: str) -> dict:
    """A store snapshot as a dict, or {} when there is no store / nothing saved."""
    store = getattr(dctx, "store", None)
    try:
        snap = store.get_snapshot(name) if store is not None else None
    except Exception:  # noqa: BLE001 - a broken store must not break listings
        snap = None
    return snap if isinstance(snap, dict) else {}


def _has_root(dctx) -> bool:
    # device_info() stores the su probe on dctx.device; fakes may only have state
    dev = getattr(dctx, "device", None)
    if not isinstance(dev, dict):
        dev = (getattr(dctx, "state", None) or {}).get("device") or {}
    return bool(dev.get("root"))


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


def _pm_set(adb, args: str) -> set[str]:
    """Package names from one `pm list packages <args>`; empty on failure."""
    try:
        return set(parse_pm_list(adb.shell_sync(f"pm list packages {args}".strip(), timeout=20)))
    except AdbError:
        return set()


def list_apps(dctx, which: str = "all", user: int | str | None = None,
              include_uninstalled: bool = True) -> dict:
    """Every package on the device for one user (None = owner, as pm does),
    or for user="all" the union over every user/profile. Includes packages
    uninstalled for the user(s) (debloated / hidden) when include_uninstalled.
    which: all|user|system|disabled|enabled|uninstalled."""
    from ..enrich.labels import BUILTIN_LABELS, label_for
    adb = dctx.adb
    flag = {"all": "", "user": "-3", "system": "-s", "disabled": "-d",
            "enabled": "-e", "uninstalled": ""}.get(which, "")
    want_uninst = include_uninstalled or which == "uninstalled"
    users = list_users(adb)
    every = user == "all"
    user_ids: list[int | None] = [u["id"] for u in users] if every else [user]
    base: dict[str, dict] = {}
    used = ""
    where: dict[str, set[int]] = {}        # pkg -> user ids it is installed for
    disabled_by: dict[int, set[str]] = {}  # -d is per user
    for uid in user_ids:
        b, fl = _pm_list(adb, flag, uid, uninstalled=want_uninst)
        used = used or fl
        for pkg, row in b.items():
            base.setdefault(pkg, row)
        inst = set(_pm_list(adb, flag, uid, uninstalled=False)[0]) if want_uninst else set(b)
        real_uid = 0 if uid is None else int(uid)
        for pkg in inst:
            where.setdefault(pkg, set()).add(real_uid)
        disabled_by[real_uid] = _pm_set(adb, f"--user {real_uid} -d" if uid is not None else "-d")
    if not base:
        return {"apps": [], "count": 0, "flags": used, "users": users,
                "user": "all" if every else (0 if user is None else user),
                "uninstalled": 0, "labels_resolved": 0,
                "error": "pm list packages returned nothing - is the device authorized?"}
    # the system flag is a property of the package, not of a user: one listing
    # (owner scope) is enough, -u so debloated system apps keep their flag
    system = _pm_set(adb, ("" if user is None or every else f"--user {int(user)} ") + "-s -u")
    sizes = (dctx.state.get("storage") or {}).get("apps") or {}
    god = dctx.state.get("godmode") or {}
    god_pkgs = {p for pkgs in god.values() for p in pkgs}
    labels: dict[str, str] = _snapshot(dctx, "labels")
    meta: dict[str, dict] = _snapshot(dctx, "apk_meta")
    out = []
    for pkg, b in base.items():
        users_installed = sorted(where.get(pkg, ()))
        is_installed = bool(users_installed)
        if which == "uninstalled" and is_installed:
            continue
        # an app counts as enabled when at least one user that has it can run
        # it; a package nobody has installed is reported enabled (as before)
        enabled = (not users_installed or
                   any(pkg not in disabled_by.get(u, ()) for u in users_installed))
        szd = sizes.get(pkg, {})
        row = {
            "package": pkg,
            "label": label_for(pkg, labels),
            "label_source": "apk" if pkg in labels else ("known" if pkg in BUILTIN_LABELS else "guess"),
            "system": pkg in system,
            "enabled": enabled,
            "installed": is_installed,
            "users_installed": users_installed,
            "installer": b.get("installer"),
            "uid": b.get("uid"),
            "data_size": szd.get("data", 0),
            "apk_size": szd.get("app", 0),
            "godmode": pkg in god_pkgs,
        }
        if isinstance(meta.get(pkg), dict) and meta[pkg]:
            row["meta"] = meta[pkg]
        out.append(row)
    out.sort(key=lambda a: (a["label"].lower(), a["package"]))
    return {"apps": out, "count": len(out), "flags": used,
            "user": "all" if every else (0 if user is None else user),
            "users": users,
            "uninstalled": sum(1 for a in out if not a["installed"]),
            "labels_resolved": sum(1 for a in out if a["label_source"] == "apk")}


def _ls_paths(out: str) -> list[str]:
    """Full paths from `ls -1 d1 d2 ...` output: a "d1:" header line, then one
    entry per line, blank line between directories."""
    paths: list[str] = []
    cur: str | None = None
    for line in out.splitlines():
        line = line.rstrip()
        if not line:
            continue
        if line.startswith("/") and line.endswith(":"):
            cur = line[:-1]
            continue
        if cur:
            paths.append(cur + "/" + line.strip())
    return paths


def _parse_components(out: str, labels: dict[str, str]) -> list[dict]:
    """`pm query-activities --brief` -> [{package,label,component}], one per package."""
    from ..enrich.labels import label_for
    seen: dict[str, dict] = {}
    for line in out.splitlines():
        m = _COMP_LINE.match(line)
        if not m or m.group(1) in seen or not _PKG.match(m.group(1)):
            continue
        pkg = m.group(1)
        seen[pkg] = {"package": pkg, "label": label_for(pkg, labels),
                     "component": f"{pkg}/{m.group(2)}"}
    return list(seen.values())


def handlers(dctx, user: int = 0) -> dict:
    """Who fills the browser/home/sms/dialer/assistant roles for a user, and
    every activity that answers the browser/launcher/sms/dialer/camera intents."""
    empty = {"roles": {k: [] for k in _ROLES}, "handlers": {k: [] for k in _INTENTS},
             "default_browser": None}
    try:
        user = _vuser(user)
    except AdbError as e:
        return {"user": user, **empty, "error": str(e)}
    adb = dctx.adb
    labels: dict[str, str] = _snapshot(dctx, "labels")
    roles: dict[str, list[str]] = {}
    for key, role in _ROLES.items():
        try:
            out = adb.shell_sync(f"cmd role get-role-holders --user {user} {role}", timeout=15)
        except AdbError:
            out = ""
        # holders come ';'-joined on one line; anything else (errors, usage
        # text) fails the package shape and is dropped
        roles[key] = [t for t in re.split(r"[;\s]+", out.strip())
                      if t and "." in t and _PKG.match(t)]
    found: dict[str, list[dict]] = {}
    for key, intent in _INTENTS.items():
        try:
            out = adb.shell_sync(f"pm query-activities --brief --user {user} {intent}", timeout=20)
        except AdbError:
            out = ""
        found[key] = _parse_components(out, labels)
    default = roles["browser"][0] if roles["browser"] else None
    if default is None:
        try:
            out = adb.shell_sync(f"pm resolve-activity --brief --user {user} "
                                 "-a android.intent.action.VIEW -d https://example.com", timeout=15)
        except AdbError:
            out = ""
        lines = [m.group(1) for m in map(_COMP_LINE.match, out.splitlines()) if m]
        # "android/...ResolverActivity" means no default is set, not a browser
        if lines and lines[-1] != "android":
            default = lines[-1]
    return {"user": user, "roles": roles, "handlers": found, "default_browser": default}


def find_package(dctx, query: str) -> dict:
    """Is a package anywhere on the device? Checks every user/profile (incl.
    uninstalled-for-user and hidden apps via -u), the preinstalled-APK folders
    on disk and, with root, /data/app; plus which browsers are registered."""
    from ..enrich.labels import label_for
    q = (query or "").strip()
    if not QUERY_RE.match(query or "") or not q:
        return {"query": (query or "")[:64], "users": [], "scanned": 0, "matches": [],
                "apk_dirs": [], "browsers": [], "error": "invalid query"}
    adb = dctx.adb
    ql = q.lower()
    labels: dict[str, str] = _snapshot(dctx, "labels")
    users = list_users(adb)
    seen: dict[str, dict[int, bool]] = {}  # pkg -> {user id: installed for that user}
    for u in users:
        uid = u["id"]
        full = set(_pm_list(adb, "", uid, uninstalled=True)[0])
        inst = set(_pm_list(adb, "", uid, uninstalled=False)[0])
        for pkg in full | inst:
            seen.setdefault(pkg, {})[uid] = pkg in inst
    system = _pm_set(adb, "-s -u")
    matches = []
    for pkg in sorted(seen):
        label = label_for(pkg, labels)
        if ql in pkg.lower() or ql in label.lower():
            matches.append({"package": pkg, "label": label, "system": pkg in system,
                            "users": [{"id": u["id"], "installed": seen[pkg].get(u["id"], False)}
                                      for u in users]})
    apk_dirs: list[str] = []
    try:
        out = adb.shell_sync("ls -1 " + " ".join(_APK_DIRS) + " 2>/dev/null", timeout=30)
        apk_dirs += [p for p in _ls_paths(out) if ql in posixpath.basename(p).lower()]
    except AdbError:
        pass
    if _has_root(dctx):
        # /data/app/~~<hash>/<pkg>-<hash>/ is only listable as root
        try:
            out = adb.shell_sync("ls -d /data/app/*/*/ 2>/dev/null", su=True, timeout=30)
            for line in out.splitlines():
                p = line.strip().rstrip("/")
                if p.startswith("/data/app/") and ql in posixpath.basename(p).lower():
                    apk_dirs.append(p)
        except AdbError:
            pass
    h = handlers(dctx, 0)
    browsers = [{**b, "default": b["package"] == h.get("default_browser")}
                for b in h["handlers"]["browser"]]
    return {"query": q, "users": users, "scanned": len(seen), "matches": matches,
            "apk_dirs": apk_dirs, "browsers": browsers}


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
    # one plain (no -u) listing per user: present there == installed for them
    users_installed = [u["id"] for u in list_users(adb)
                       if pkg in _pm_set(adb, f"--user {u['id']}")]
    res = {
        "package": pkg,
        "detail": d,
        "appops": ops,
        "godmode": sorted(a for a, pkgs in god.items() if pkg in pkgs),
        "sizes": sizes.get(pkg, {}),
        "apk_paths": _safe(lambda: adb.apk_paths(pkg), []),
        "users_installed": users_installed,
    }
    meta = _snapshot(dctx, "apk_meta").get(pkg)
    if isinstance(meta, dict) and meta:
        res["meta"] = meta
    return res


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
