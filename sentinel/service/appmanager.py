"""App Manager: enumerate every app and run the standard owner actions.

Inspection (list / detail / controls) is read-only. The actions (enable,
disable, freeze, force-stop, clear cache/data, uninstall, permissions and app
ops, background/battery/network policy, intent-firewall rules, Magisk denylist,
compile, APK export, process kill, one preference key) are the same operations
a device owner runs from Settings or `pm`/`am`/`appops`/`cmd` on their own
rooted phone; they target only the device connected over the owner's own adb.
Every package/permission/op/component/file argument is validated against a
strict allowlist pattern and shell-quoted, so nothing shell-like reaches the
device. Destructive actions require an explicit confirm from the caller, and
every action that reaches the device is logged as an app.action event.
"""
from __future__ import annotations

import posixpath
import shlex

from ..adb.client import AdbError
from ..core.events import Event, SEV_NOTICE, SEV_WARN
from ..parsers.appops import parse_appops
from ..parsers.packagedump import parse_packages_dump, parse_pm_list

import re

_PKG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.]{1,254}$")
PKG_RE = _PKG
_PERM = re.compile(r"^[A-Za-z0-9_.]{1,128}$")
_OP = re.compile(r"^[A-Za-z0-9_:]{1,64}$")
_COMPONENT = re.compile(r"^[A-Za-z0-9_.]{1,254}/[A-Za-z0-9_.$]{1,254}$")
_MODES = {"allow", "deny", "ignore", "default", "foreground"}
# find-package query: never reaches a shell, but keep it boring anyway
QUERY_RE = re.compile(r"^[A-Za-z0-9_. -]{1,64}$")
# one "pkg/Component" result line of `pm query-activities --brief`
_COMP_LINE = re.compile(r"^\s*([A-Za-z0-9_.]+)/([A-Za-z0-9_.$]+)\s*$")

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


class _Refused(AdbError):
    """Input refused before anything reached the device (no event is logged)."""


def _vpkg(pkg: str) -> str:
    if not isinstance(pkg, str) or not _PKG.match(pkg or ""):
        raise _Refused("invalid package name")
    return pkg


def _vuser(user) -> int:
    try:
        u = int(user)
    except (TypeError, ValueError):
        raise _Refused("invalid user id") from None
    if not 0 <= u <= 999:
        raise _Refused("invalid user id")
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
    # the fallbacks only drop -i/-U (which some builds reject); the type filter
    # itself is never dropped, otherwise an empty "-d" result would turn into
    # the full package list
    attempts = [f"-f -i -U {flag}", f"-f -U {flag}", f"-f {flag}", flag]
    for fl in attempts:
        cmd = ("pm list packages " + scope + fl).strip()
        try:
            out = adb.shell_sync(cmd, timeout=60)
        except AdbError:
            continue
        parsed = parse_pm_list(out)
        if parsed:
            return parsed, (scope + fl).strip()
        if flag and not _looks_like_error(out):
            return {}, (scope + fl).strip()   # a filtered list can legitimately be empty
    return {}, ""


def _looks_like_error(out: str) -> bool:
    low = out.lower()
    return any(w in low for w in ("error", "exception", "unknown option", "usage:", "bad "))


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
        res = {"apps": [], "count": 0, "flags": used, "users": users,
               "user": "all" if every else (0 if user is None else user),
               "uninstalled": 0, "labels_resolved": 0}
        # a type filter (disabled/user/...) can be legitimately empty; only an
        # unfiltered listing that yields nothing means pm is not answering
        if not flag or not used:
            res["error"] = "pm list packages returned nothing - is the device authorized?"
        return res
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
    h = handlers_cached(dctx, 0)
    browsers = [{**b, "default": b["package"] == h.get("default_browser")}
                for b in h["handlers"]["browser"]]
    return {"query": q, "users": users, "scanned": len(seen), "matches": matches,
            "apk_dirs": apk_dirs, "browsers": browsers}


_CACHE_TTL = 60.0


def _cached(dctx, key: str, ttl: float, compute):
    """Small per-device memo in dctx.state: role/handler and per-user listings
    cost 5-10 adb round trips each and change rarely."""
    import time
    slot = dctx.state.setdefault("_memo", {})
    hit = slot.get(key)
    now = time.time()
    if hit and now - hit[0] < ttl:
        return hit[1]
    val = compute()
    slot[key] = (now, val)
    return val


def handlers_cached(dctx, user: int = 0) -> dict:
    return _cached(dctx, f"handlers:{user}", _CACHE_TTL, lambda: handlers(dctx, user))


def installed_users_cached(dctx, pkg: str) -> list[int]:
    """User ids a package is installed for, from one plain listing per user
    (memoised 30 s: the detail pane asks on every click)."""
    adb = dctx.adb
    per_user = _cached(dctx, "installed_by_user", 30.0, lambda: {
        u["id"]: _pm_set(adb, f"--user {u['id']}") for u in list_users(adb)})
    return [u for u, pkgs in per_user.items() if pkg in pkgs]


def _safe(fn, default):
    try:
        return fn()
    except Exception:
        return default


def _ps_rows(adb) -> list[tuple[int, int, int, str]]:
    """(pid, uid, rss_kb, name) from `ps -A -o PID,UID,RSS,NAME`."""
    rows: list[tuple[int, int, int, str]] = []
    for line in adb.shell_sync("ps -A -o PID,UID,RSS,NAME", timeout=20).splitlines()[1:]:
        parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        try:
            rows.append((int(parts[0]), int(parts[1]), int(parts[2]), parts[3].strip()))
        except ValueError:
            continue
    return rows


def _uid_for(dctx, pkg: str, user: int = 0) -> int:
    from .appdata import package_uid
    uid = package_uid(dctx, pkg, user)
    if uid is None:
        raise AdbError("could not resolve the app's uid (is it installed for this user?)")
    return uid


def _frozen(st: dict) -> str | None:
    # 2/3/4 = disabled / disabled by user / disabled until used
    if st.get("enabled_state") in (2, 3, 4):
        return "disabled"
    if st.get("suspended"):
        return "suspended"
    if st.get("hidden"):
        return "hidden"
    return None


def links_for(pkg: str) -> dict:
    return {"play": f"https://play.google.com/store/apps/details?id={pkg}",
            "fdroid": f"https://f-droid.org/packages/{pkg}/",
            "exodus": f"https://reports.exodus-privacy.eu.org/en/reports/{pkg}/latest/"}


def app_detail(dctx, pkg: str, user: int = 0) -> dict:
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
    users_installed = installed_users_cached(dctx, pkg)
    ustate: dict = d.get("users") or {}
    st = ustate.get(user) or ustate.get(str(user)) or {}
    if not st and ustate:
        user, st = next(iter(ustate.items()))
    uid = d.get("uid")
    if uid is None:
        uid = _safe(lambda: _uid_for(dctx, pkg, 0), None)
    stats = dctx.state.get("netstats") or {}
    ns = stats.get(str(uid)) if uid is not None else None
    rows = _safe(lambda: _ps_rows(adb), [])
    # match on appId so a work-profile instance (uid + 100000*user) counts too
    mine = [r for r in rows if uid is not None and r[1] % 100000 == uid % 100000]
    res = {
        "package": pkg,
        "detail": d,
        "appops": ops,
        "godmode": sorted(a for a, pkgs in god.items() if pkg in pkgs),
        "sizes": sizes.get(pkg, {}),
        "apk_paths": _safe(lambda: adb.apk_paths(pkg), []),
        "users_installed": users_installed,
        "state": {"installed": bool(st.get("installed", pkg in users_installed)),
                  "hidden": bool(st.get("hidden")), "suspended": bool(st.get("suspended")),
                  "stopped": bool(st.get("stopped")),
                  "enabled_state": int(st.get("enabled_state", 0) or 0),
                  "frozen": _frozen(st), "user": int(user)},
        "perm_flags": d.get("perm_flags") or {},
        "uid": uid, "shared_user": d.get("shared_user"), "process": d.get("process"),
        "data_usage": ({"wifi_rx": ns.get("wrx", 0), "wifi_tx": ns.get("wtx", 0),
                        "mobile_rx": ns.get("mrx", 0), "mobile_tx": ns.get("mtx", 0)}
                       if isinstance(ns, dict) else None),
        "running": {"pids": [r[0] for r in mine], "rss_kb": sum(r[2] for r in mine)},
        "links": links_for(pkg),
    }
    meta = _snapshot(dctx, "apk_meta").get(pkg)
    if isinstance(meta, dict) and meta:
        res["meta"] = meta
    return res


# ---------------- actions ----------------

# runtime (user-grantable) permissions Android classes as dangerous; the
# only ones `pm revoke` can take away
DANGEROUS_PERMS = frozenset({
    "READ_CALENDAR", "WRITE_CALENDAR", "READ_CALL_LOG", "WRITE_CALL_LOG",
    "PROCESS_OUTGOING_CALLS", "CAMERA", "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "RECORD_AUDIO", "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE",
    "ANSWER_PHONE_CALLS", "ADD_VOICEMAIL", "USE_SIP", "ACCEPT_HANDOVER", "BODY_SENSORS",
    "BODY_SENSORS_BACKGROUND", "ACTIVITY_RECOGNITION", "SEND_SMS", "RECEIVE_SMS", "READ_SMS",
    "RECEIVE_WAP_PUSH", "RECEIVE_MMS", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "ACCESS_MEDIA_LOCATION", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO",
    "READ_MEDIA_VISUAL_USER_SELECTED", "BLUETOOTH_SCAN", "BLUETOOTH_CONNECT",
    "BLUETOOTH_ADVERTISE", "NEARBY_WIFI_DEVICES", "POST_NOTIFICATIONS", "UWB_RANGING",
})
_DANGEROUS_OPS = ("COARSE_LOCATION", "FINE_LOCATION", "CAMERA", "RECORD_AUDIO", "READ_CONTACTS",
                  "READ_CALL_LOG", "READ_SMS", "RECEIVE_SMS", "READ_PHONE_STATE",
                  "READ_CLIPBOARD", "WRITE_CLIPBOARD", "GET_USAGE_STATS", "SYSTEM_ALERT_WINDOW")
_FREEZE = {"disable": "pm disable-user --user {user} {q}", "suspend": "pm suspend --user {user} {q}",
           "hide": "pm hide --user {user} {q}"}
_UNFREEZE = ("pm enable --user {user} {q}", "pm unsuspend --user {user} {q}",
             "pm unhide --user {user} {q}")
_COMPILE_MODES = ("speed", "speed-profile", "verify", "reset")
_SENSOR_STATES = ("active", "idle", "reset")
# tool output that means the command did not do what was asked
_FAIL_MARKERS = ("Failure", "Error", "Exception", "aborted", "Unknown package", "not found",
                 "Permission denied", "must be root", "No chain", "inaccessible")
_IFW_DIR = "/data/system/ifw"
_IFW_TAGS = ("activity", "service", "broadcast")
_APK_PATH = re.compile(r"^/(data|system|system_ext|product|vendor|apex)/.+\.apk$")

DESTRUCTIVE = {"disable", "clear-data", "uninstall", "freeze", "uninstall-updates",
               "appops-deny-dangerous", "deny-dangerous-perms", "firewall", "ifw-block",
               "ifw-unblock", "block-trackers", "unblock-trackers", "prefs-set", "prefs-delete"}


def _ok(out: str) -> bool:
    return not any(m in out for m in _FAIL_MARKERS)


def _cmd(dctx, cmd: str, *, su: bool = False, timeout: float = 60.0) -> dict:
    out = dctx.adb.shell_sync(cmd, su=su, timeout=timeout).strip()
    return {"ok": _ok(out), "output": out or "(done)"}


def _vbool(p: dict, key: str, default: bool | None = None) -> bool:
    v = p.get(key, default)
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)) and v in (0, 1):
        return bool(v)
    if isinstance(v, str) and v.lower() in ("true", "false", "1", "0"):
        return v.lower() in ("true", "1")
    raise _Refused(f"{key} must be true or false")


def _venum(p: dict, key: str, allowed) -> str:
    v = p.get(key)
    if not isinstance(v, str) or v not in allowed:
        raise _Refused(f"{key} must be one of: {', '.join(allowed)}")
    return v


def _vcomp(p: dict, pkg: str) -> str:
    """A component of this package as "pkg/full.Class"; ".Cls" is expanded."""
    comp = p.get("component", "")
    if not isinstance(comp, str) or not _COMPONENT.match(comp):
        raise _Refused("invalid component")
    cpkg, cls = comp.split("/", 1)
    if cpkg != pkg:
        raise _Refused("component must belong to the package")
    if cls.startswith("."):
        cls = pkg + cls
    return f"{pkg}/{cls}"


def _vint(p: dict, key: str, lo: int, hi: int) -> int:
    try:
        v = int(p.get(key))
    except (TypeError, ValueError):
        raise _Refused(f"{key} must be an integer") from None
    if not lo <= v <= hi:
        raise _Refused(f"{key} out of range")
    return v


def _h_launch_activity(dctx, pkg, user, p):
    # su so a non-exported activity still starts on a rooted device
    return _cmd(dctx, f"am start -n {shlex.quote(_vcomp(p, pkg))}", su=True)


def _h_start_service(dctx, pkg, user, p):
    comp = shlex.quote(_vcomp(p, pkg))
    r = _cmd(dctx, f"am start-service -n {comp}")
    if "Unknown command" in r["output"]:      # pre-Android 8 spelling
        r = _cmd(dctx, f"am startservice -n {comp}")
    return r


def _h_freeze(dctx, pkg, user, p):
    method = _venum(p, "method", tuple(_FREEZE))
    return _cmd(dctx, _FREEZE[method].format(user=user, q=shlex.quote(pkg)))


def _h_unfreeze(dctx, pkg, user, p):
    outs, ok = [], False
    for fmt in _UNFREEZE:
        try:
            r = _cmd(dctx, fmt.format(user=user, q=shlex.quote(pkg)))
        except AdbError as e:       # the states that do not apply just fail
            r = {"ok": False, "output": str(e)}
        ok = ok or r["ok"]
        outs.append(r["output"])
    return {"ok": ok, "output": "\n".join(outs)}


def _h_uninstall(dctx, pkg, user, p):
    keep = "-k " if _vbool(p, "keep_data", False) else ""
    return _cmd(dctx, f"pm uninstall {keep}--user {user} {shlex.quote(pkg)}")


def _h_uninstall_updates(dctx, pkg, user, p):
    if pkg not in _pm_set(dctx.adb, "-s -u"):
        return {"ok": False, "output": "not a system app: there is no factory copy to fall back to"}
    return _cmd(dctx, f"pm uninstall {shlex.quote(pkg)}")


def _h_appops_deny_dangerous(dctx, pkg, user, p):
    q = shlex.quote(pkg)
    return _cmd(dctx, "; ".join(f"appops set {q} {op} ignore" for op in _DANGEROUS_OPS))


def _h_prevent_background(dctx, pkg, user, p):
    mode = "ignore" if _vbool(p, "enabled") else "allow"
    q = shlex.quote(pkg)
    a = _cmd(dctx, f"appops set {q} RUN_IN_BACKGROUND {mode}")
    b = _cmd(dctx, f"appops set {q} RUN_ANY_IN_BACKGROUND {mode}")
    return {"ok": a["ok"] and b["ok"], "output": f"{a['output']}\n{b['output']}".strip()}


def _h_deny_dangerous_perms(dctx, pkg, user, p):
    q = shlex.quote(pkg)
    dump = parse_packages_dump(dctx.adb.shell_sync(f"dumpsys package {q}", timeout=40))
    granted = (dump.get(pkg) or {}).get("granted") or []
    hot = [g for g in granted if g.startswith("android.permission.")
           and g.rsplit(".", 1)[-1] in DANGEROUS_PERMS]
    if not hot:
        return {"ok": True, "output": "no dangerous permissions granted"}
    done, failed = [], []
    for perm in hot:
        try:
            r = _cmd(dctx, f"pm revoke --user {user} {q} {shlex.quote(perm)}")
        except AdbError as e:
            r = {"ok": False, "output": str(e)}
        (done if r["ok"] else failed).append(perm.rsplit(".", 1)[-1] +
                                             ("" if r["ok"] else f" ({r['output'][:80]})"))
    out = f"revoked {len(done)}: {', '.join(done)}"
    if failed:
        out += f"\nfailed {len(failed)}: {', '.join(failed)}"
    return {"ok": not failed, "output": out}


def _h_battery(dctx, pkg, user, p):
    sign = "+" if _vbool(p, "whitelist") else "-"
    return _cmd(dctx, f"dumpsys deviceidle whitelist {sign}{shlex.quote(pkg)}")


def _h_netpolicy(dctx, pkg, user, p):
    verb = "add" if _vbool(p, "restrict_background") else "remove"
    uid = _uid_for(dctx, pkg, user)
    return _cmd(dctx, f"cmd netpolicy {verb} restrict-background-blacklist {uid}")


def _h_sensors(dctx, pkg, user, p):
    state = _venum(p, "state", _SENSOR_STATES)
    q = shlex.quote(pkg)
    if state == "reset":
        return _cmd(dctx, f"cmd sensorservice reset-uid-state {q}")
    return _cmd(dctx, f"cmd sensorservice set-uid-state {q} {state}")


def _denylist_available(dctx) -> bool:
    # a missing binary fails the shell (raises) or prints "not found"
    try:
        return _ok(dctx.adb.shell_sync("magisk --denylist ls", su=True, timeout=15))
    except AdbError:
        return False


def _h_denylist(dctx, pkg, user, p):
    on = _vbool(p, "enabled")
    if not _denylist_available(dctx):
        return {"ok": False, "output": "Magisk denylist not available"}
    verb = "add" if on else "rm"
    return _cmd(dctx, f"magisk --denylist {verb} {shlex.quote(pkg)}", su=True)


def _h_app_links(dctx, pkg, user, p):
    val = "true" if _vbool(p, "allowed") else "false"
    return _cmd(dctx, f"pm set-app-links-allowed --user {user} --package {shlex.quote(pkg)} {val}")


def _h_firewall(dctx, pkg, user, p):
    block = _vbool(p, "block")
    uid = _uid_for(dctx, pkg, user)
    flag = "-I" if block else "-D"
    outs, ok = [], True
    for tool in ("iptables", "ip6tables"):
        r = _cmd(dctx, f"{tool} {flag} OUTPUT -m owner --uid-owner {uid} -j REJECT", su=True)
        ok = ok and r["ok"]
        outs.append(f"{tool}: {r['output']}")
    outs.append("note: iptables rules do not survive a reboot")
    return {"ok": ok, "output": "\n".join(outs)}


def _component_tags(dctx, pkg: str, cls: str) -> list[str]:
    """IFW rule tags for one class from the cached manifest; a provider gets
    [] (IFW cannot filter providers); unknown classes get every tag."""
    m = _snapshot(dctx, "manifests").get(pkg)
    if isinstance(m, dict):
        for key, tag in (("activities", "activity"), ("services", "service"),
                         ("receivers", "broadcast"), ("providers", None)):
            for c in m.get(key) or []:
                if isinstance(c, dict) and c.get("name") == cls:
                    return [tag] if tag else []
    return list(_IFW_TAGS)


def _ifw_read(dctx, pkg: str):
    import xml.etree.ElementTree as ET
    raw = dctx.adb.exec_out_bytes(f"cat {_IFW_DIR}/{pkg}.xml 2>/dev/null", su=True, timeout=20)
    if raw.strip():
        try:
            return ET.fromstring(raw)
        except ET.ParseError:
            pass                      # unreadable rules are replaced, not merged
    return ET.Element("rules")


def _ifw_update(dctx, pkg: str, comps: list[str], block: bool) -> dict:
    """Add or remove intent-firewall rules for components of pkg in one
    read-modify-write of /data/system/ifw/<pkg>.xml, then pm disable/enable
    each component so it is off even where IFW does not apply."""
    import xml.etree.ElementTree as ET
    from .appdata import write_device_file
    root = _ifw_read(dctx, pkg)
    for name in comps:
        tags = _component_tags(dctx, pkg, name.split("/", 1)[1])
        for tag in tags:
            rules = [r for r in root.findall(tag)
                     if any(f.get("name") == name for f in r.findall("component-filter"))]
            if block and not rules:
                rule = ET.SubElement(root, tag, {"block": "true", "log": "false"})
                ET.SubElement(rule, "component-filter", {"name": name})
            elif not block:
                for r in rules:
                    for f in [f for f in r.findall("component-filter") if f.get("name") == name]:
                        r.remove(f)
    for r in list(root):                 # rules left without any filter
        if r.tag in _IFW_TAGS and len(r) == 0:
            root.remove(r)
    path = f"{_IFW_DIR}/{pkg}.xml"
    if len(root):
        xml = b"<?xml version='1.0' encoding='utf-8'?>\n" + ET.tostring(root) + b"\n"
        write_device_file(dctx, path, xml, mode="644", mkdir=True)
    else:
        dctx.adb.shell_sync(f"rm -f {shlex.quote(path)}", su=True, timeout=20)
    verb = "disable" if block else "enable"
    outs, ok = [], True
    for name in comps:
        try:
            r = _cmd(dctx, f"pm {verb} {shlex.quote(name)}", su=True)
        except AdbError as e:
            r = {"ok": False, "output": str(e)}
        ok = ok and r["ok"]
        outs.append(f"{name}: {r['output'].splitlines()[0] if r['output'] else ''}")
    head = f"ifw: {'blocked' if block else 'unblocked'} {len(comps)} component(s) in {path}"
    return {"ok": ok, "output": head + "\n" + "\n".join(outs)}


def _h_ifw_block(dctx, pkg, user, p):
    return _ifw_update(dctx, pkg, [_vcomp(p, pkg)], True)


def _h_ifw_unblock(dctx, pkg, user, p):
    return _ifw_update(dctx, pkg, [_vcomp(p, pkg)], False)


def _tracker_components(dctx, pkg: str) -> list[str]:
    scan = _snapshot(dctx, "scans").get(pkg)
    if not isinstance(scan, dict):
        raise _Refused("scan this app first")
    comps = set()
    for t in scan.get("trackers") or []:
        for c in (t.get("components") or []) if isinstance(t, dict) else []:
            if not isinstance(c, str):
                continue
            c = c if "/" in c else f"{pkg}/{c}"
            if _COMPONENT.match(c) and c.startswith(pkg + "/"):
                comps.add(c)
    return sorted(comps)


def _h_block_trackers(dctx, pkg, user, p):
    comps = _tracker_components(dctx, pkg)
    if not comps:
        return {"ok": True, "output": "no tracker components in the cached scan"}
    return _ifw_update(dctx, pkg, comps, True)


def _h_unblock_trackers(dctx, pkg, user, p):
    comps = _tracker_components(dctx, pkg)
    if not comps:
        return {"ok": True, "output": "no tracker components in the cached scan"}
    return _ifw_update(dctx, pkg, comps, False)


def _h_compile(dctx, pkg, user, p):
    mode = _venum(p, "mode", _COMPILE_MODES)
    q = shlex.quote(pkg)
    if mode == "reset":
        return _cmd(dctx, f"pm compile --reset {q}", timeout=600)
    return _cmd(dctx, f"pm compile -m {mode} -f {q}", timeout=600)


def _h_save_apk(dctx, pkg, user, p):
    from pathlib import Path
    adb = dctx.adb
    paths = adb.apk_paths(pkg)
    if not paths:
        raise AdbError("pm path returned no APK (package not found?)")
    cfg = getattr(dctx, "cfg", None)
    base = Path(cfg.data_dir) if cfg is not None else Path.home() / ".android-sentinel"
    serial_safe = re.sub(r"[^A-Za-z0-9._-]", "_", str(getattr(dctx, "serial", "") or "device"))
    dest = base / "apks" / serial_safe / pkg
    dest.mkdir(parents=True, exist_ok=True)
    saved = []
    for i, rp in enumerate(paths):
        if not _APK_PATH.match(rp):      # the device chose this path; only pull real APK spots
            continue
        local = dest / f"{i}_{posixpath.basename(rp) or 'split.apk'}"
        if not adb.pull_file(rp, local):
            data = adb.exec_out_bytes(f"cat {shlex.quote(rp)}", su=True, timeout=600)
            if not data:
                raise AdbError(f"could not pull {rp}")
            local.write_bytes(data)
        saved.append(local.name)
    return {"ok": bool(saved), "output": str(dest), "files": saved}


def _h_kill(dctx, pkg, user, p):
    pid = _vint(p, "pid", 2, 4_194_304)
    uid = _uid_for(dctx, pkg, user)
    row = next((r for r in _ps_rows(dctx.adb) if r[0] == pid), None)
    if row is None:
        return {"ok": False, "output": f"pid {pid} is not running"}
    if row[1] % 100000 != uid % 100000:
        return {"ok": False, "output": f"pid {pid} belongs to uid {row[1]}, not to {pkg}"}
    return _cmd(dctx, f"kill -9 {pid}", su=True)


def _h_prefs_set(dctx, pkg, user, p):
    from .appdata import prefs_set
    out = prefs_set(dctx, pkg, str(p.get("file", "")), str(p.get("key", "")),
                    str(p.get("type", "")), p.get("value"))
    return {"ok": True, "output": out}


def _h_prefs_delete(dctx, pkg, user, p):
    from .appdata import prefs_delete
    return {"ok": True, "output": prefs_delete(dctx, pkg, str(p.get("file", "")),
                                               str(p.get("key", "")))}


def _h_grant_revoke(action):
    def h(dctx, pkg, user, p):
        perm = p.get("permission", "")
        if not isinstance(perm, str) or not _PERM.match(perm):
            raise _Refused("invalid permission")
        return _cmd(dctx, f"pm {action} {shlex.quote(pkg)} {shlex.quote(perm)}")
    return h


def _h_appop(dctx, pkg, user, p):
    op, mode = p.get("op", ""), p.get("mode", "")
    if not isinstance(op, str) or not _OP.match(op) or mode not in _MODES:
        raise _Refused("invalid op or mode")
    return _cmd(dctx, f"appops set {shlex.quote(pkg)} {shlex.quote(op)} {shlex.quote(mode)}")


def _h_component_state(verb):
    def h(dctx, pkg, user, p):
        comp = p.get("component", "")
        if not isinstance(comp, str) or not _COMPONENT.match(comp):
            raise _Refused("invalid component")
        return _cmd(dctx, f"pm {verb} {shlex.quote(comp)}")
    return h


def _simple(fmt: str, *, su: bool = False):
    def h(dctx, pkg, user, p):
        return _cmd(dctx, fmt.format(q=shlex.quote(pkg), user=user, pkg=pkg), su=su)
    return h


ACTIONS: dict = {
    "enable": _simple("pm enable --user {user} {q}"),
    "disable": _simple("pm disable-user --user {user} {q}"),
    "force-stop": _simple("am force-stop {q}"),
    "clear-data": _simple("pm clear --user {user} {q}"),
    "clear-cache": _simple("rm -rf /data/data/{pkg}/cache/* /data/data/{pkg}/code_cache/* "
                           "2>/dev/null; echo cleared", su=True),
    "uninstall": _h_uninstall,
    # bring back an app that was removed for this user (the usual debloat),
    # using the copy still on the device - no download needed
    "reinstall": _simple("pm install-existing --user {user} {q}"),
    "grant": _h_grant_revoke("grant"),
    "revoke": _h_grant_revoke("revoke"),
    "appop": _h_appop,
    "enable-component": _h_component_state("enable"),
    "disable-component": _h_component_state("disable"),
    "launch": _simple("monkey -p {q} -c android.intent.category.LAUNCHER 1"),
    "open-settings": _simple("am start -a android.settings.APPLICATION_DETAILS_SETTINGS "
                             "-d package:{q}"),
    "launch-activity": _h_launch_activity,
    "start-service": _h_start_service,
    "send-broadcast": lambda dctx, pkg, user, p: _cmd(
        dctx, f"am broadcast -n {shlex.quote(_vcomp(p, pkg))}"),
    "freeze": _h_freeze,
    "unfreeze": _h_unfreeze,
    "uninstall-updates": _h_uninstall_updates,
    "appops-reset": _simple("appops reset {q}"),
    "appops-deny-dangerous": _h_appops_deny_dangerous,
    "prevent-background": _h_prevent_background,
    "deny-dangerous-perms": _h_deny_dangerous_perms,
    "battery": _h_battery,
    "netpolicy": _h_netpolicy,
    "sensors": _h_sensors,
    "denylist": _h_denylist,
    "app-links": _h_app_links,
    "firewall": _h_firewall,
    "ifw-block": _h_ifw_block,
    "ifw-unblock": _h_ifw_unblock,
    "block-trackers": _h_block_trackers,
    "unblock-trackers": _h_unblock_trackers,
    "compile": _h_compile,
    "save-apk": _h_save_apk,
    "kill": _h_kill,
    "prefs-set": _h_prefs_set,
    "prefs-delete": _h_prefs_delete,
}

BATCH_ACTIONS = ("force-stop", "freeze", "unfreeze", "clear-cache", "clear-data", "uninstall",
                 "reinstall", "prevent-background", "appops-deny-dangerous", "battery",
                 "netpolicy", "compile", "save-apk", "backup", "block-trackers",
                 "unblock-trackers")


def _emit_action(dctx, action: str, pkg: str, user: int, p: dict, res: dict) -> None:
    """Every action that reached the device lands in the store (Logs/History)."""
    emit = getattr(dctx, "emit_threadsafe", None)
    if not callable(emit):
        return
    params = {}
    for k, v in (p or {}).items():
        if k in ("device", "confirm", "package", "action", "user"):
            continue
        if isinstance(v, str):
            v = v[:200]
        elif v is not None and not isinstance(v, (bool, int, float)):
            v = str(v)[:200]
        params[k] = v
    out = str(res.get("output") or "")
    try:
        emit(Event(kind="app.action", severity=SEV_NOTICE if res.get("ok") else SEV_WARN,
                   title=f"{action}: {pkg}", detail=out[:200], app=pkg or None,
                   data={"action": action, "user": user, "ok": bool(res.get("ok")),
                         "params": params, "output": out[:300]}))
    except Exception:  # noqa: BLE001 - logging never fails the action
        pass


def run_action(dctx, action: str, params: dict) -> dict:
    """Validate and run one owner action. Returns {ok, output, action, package}."""
    p = params or {}
    pkg = p.get("package", "")
    pkg = pkg if isinstance(pkg, str) else ""
    user = 0
    try:
        if action not in ACTIONS:
            raise _Refused(f"unknown action: {action}")
        if action in DESTRUCTIVE and not p.get("confirm"):
            raise _Refused("destructive action requires confirm=true")
        try:
            user = int(p.get("user", 0) or 0)
        except (TypeError, ValueError):
            raise _Refused("invalid user id") from None
        if not 0 <= user <= 999:
            raise _Refused("invalid user id")
        _vpkg(pkg)
        res = ACTIONS[action](dctx, pkg, user, p)
    except _Refused as e:
        return {"ok": False, "output": str(e), "action": action, "package": pkg}
    except AdbError as e:
        res = {"ok": False, "output": str(e)}
    except Exception as e:  # noqa: BLE001 - a surprise must reach the UI, not a 500
        res = {"ok": False, "output": f"{type(e).__name__}: {e}"}
    res.update({"action": action, "package": pkg})
    _emit_action(dctx, action, pkg, user, p, res)
    return res


def _backup_one(dctx, pkg: str) -> dict:
    svc = dctx.hub.backup
    job = svc.new_job(pkg, dctx.serial, {"apk": True, "data": True, "external": False})
    svc.run(dctx, job)
    ok = job.get("state") == "done"
    return {"ok": ok, "output": job.get("path") or job.get("error") or job.get("state", "")}


def batch(dctx, action: str, packages, user=0, confirm: bool = False,
          options: dict | None = None) -> dict:
    """Run one action over many packages, sequentially. Raises AdbError for
    bad input before anything runs."""
    if action not in BATCH_ACTIONS:
        raise _Refused(f"action not allowed in batch: {action}")
    if not isinstance(packages, list) or not packages:
        raise _Refused("packages must be a non-empty list")
    if len(packages) > 500:
        raise _Refused("too many packages (max 500)")
    pkgs = [_vpkg(str(x)) for x in packages]
    user = _vuser(user)
    if action in DESTRUCTIVE and not confirm:
        raise _Refused("destructive action requires confirm=true")
    opts = {k: v for k, v in (options or {}).items()
            if k not in ("device", "package", "packages", "user", "confirm", "action")}
    results = []
    for pkg in pkgs:
        if action == "backup":
            try:
                r = _backup_one(dctx, pkg)
            except Exception as e:  # noqa: BLE001
                r = {"ok": False, "output": str(e)}
            _emit_action(dctx, "backup", pkg, user, {}, r)
        else:
            r = run_action(dctx, action, {**opts, "package": pkg, "user": user,
                                          "confirm": bool(confirm)})
        results.append({"package": pkg, "ok": bool(r.get("ok")),
                        "output": str(r.get("output", ""))[:1000]})
    ok_count = sum(1 for r in results if r["ok"])
    return {"results": results, "ok_count": ok_count, "fail_count": len(results) - ok_count}


# ---------------- one-click ----------------

ONECLICK_OPS = [
    {"id": "block-trackers-all", "title": "Block trackers everywhere",
     "description": "Intent-firewall every tracker component found by the scans cached so far "
                    "(apps without a scan are skipped).", "needs_root": True, "destructive": True},
    {"id": "deny-bg-all", "title": "Deny background activity",
     "description": "Set RUN_IN_BACKGROUND / RUN_ANY_IN_BACKGROUND to ignore for every app.",
     "needs_root": False, "destructive": False},
    {"id": "deny-dangerous-ops-all", "title": "Deny dangerous app-ops",
     "description": "Location, camera, mic, contacts, SMS, call log, clipboard, usage stats and "
                    "overlay ops set to ignore for every app.", "needs_root": False, "destructive": True},
    {"id": "trim-caches", "title": "Trim all caches",
     "description": "One `pm trim-caches 999G`: the system frees every app cache it can.",
     "needs_root": False, "destructive": False},
    {"id": "clear-cache-all", "title": "Clear every app cache",
     "description": "rm the cache and code_cache directories of every app.",
     "needs_root": True, "destructive": False},
    {"id": "backup-all", "title": "Back up every app",
     "description": "APK + private data of every app into this host's backups folder.",
     "needs_root": True, "destructive": False},
    {"id": "compile-all", "title": "Compile every app (speed-profile)",
     "description": "`pm compile -m speed-profile -f` for every app; slow, no data changes.",
     "needs_root": False, "destructive": False},
]
_ONECLICK_BATCH = {
    "block-trackers-all": ("block-trackers", {}),
    "deny-bg-all": ("prevent-background", {"enabled": True}),
    "deny-dangerous-ops-all": ("appops-deny-dangerous", {}),
    "clear-cache-all": ("clear-cache", {}),
    "backup-all": ("backup", {}),
    "compile-all": ("compile", {"mode": "speed-profile"}),
}
# never touched by a one-click op; the launcher (role HOME) joins at runtime
PROTECTED = frozenset({"android", "com.android.systemui", "com.android.settings",
                       "com.android.phone", "com.android.shell"})


def oneclick_packages(dctx, scope: str) -> list[str]:
    """user = third-party apps; all = every app uid >= 10000 minus the core
    system packages and the launcher."""
    adb = dctx.adb
    if scope == "user":
        pkgs = _pm_set(adb, "-3")
    else:
        rows, _ = _pm_list(adb, "")
        if any(r.get("uid") for r in rows.values()):
            pkgs = {p for p, r in rows.items() if (r.get("uid") or 0) >= 10000}
        else:                      # this pm has no -U: keep every non-core package
            pkgs = set(rows)
    launcher = set(_safe(lambda: handlers_cached(dctx, 0)["roles"]["home"], []))
    return sorted(pkgs - PROTECTED - launcher)


def oneclick(dctx, op: str, confirm: bool = False, scope: str = "user") -> dict:
    spec = next((o for o in ONECLICK_OPS if o["id"] == op), None)
    if spec is None:
        raise _Refused(f"unknown op: {op}")
    if scope not in ("user", "all"):
        raise _Refused("scope must be user or all")
    if spec["destructive"] and not confirm:
        raise _Refused("destructive op requires confirm=true")
    if op == "trim-caches":
        try:
            r = _cmd(dctx, "pm trim-caches 999G", timeout=300)
        except AdbError as e:
            r = {"ok": False, "output": str(e)}
        _emit_action(dctx, "trim-caches", "*", 0, {}, r)
        return {"results": [{"package": "*", **r}], "ok_count": int(r["ok"]),
                "fail_count": int(not r["ok"]), "note": "device-wide"}
    pkgs = oneclick_packages(dctx, scope)
    note = f"{len(pkgs)} {scope} app(s)"
    if op == "block-trackers-all":
        scans = _snapshot(dctx, "scans")
        scanned = [p for p in pkgs if isinstance(scans.get(p), dict) and scans[p].get("trackers")]
        note += f"; {len(pkgs) - len(scanned)} skipped without a cached scan showing trackers"
        pkgs = scanned
    action, opts = _ONECLICK_BATCH[op]
    if not pkgs:
        return {"results": [], "ok_count": 0, "fail_count": 0, "note": note}
    res = batch(dctx, action, pkgs, 0, True, opts)
    res["note"] = note
    return res


# ---------------- controls ----------------

_LINK_STATE = re.compile(r"^\s+([A-Za-z0-9*][A-Za-z0-9.\-*]*\.[A-Za-z0-9\-]+):\s+(\S.*?)\s*$")
_LINKS_ALLOWED = re.compile(r"link handling allowed:\s*(true|false)", re.I)
_OVERLAY_LINE = re.compile(r"^(\[[ x]\]|---)\s+(\S+)")
_SETTING_TAG = re.compile(r"<setting\b([^>]*)>")
_ATTR = re.compile(r'(\w+)="([^"]*)"')


def parse_app_links(out: str) -> tuple[list[dict], bool | None]:
    """`pm get-app-links` -> ([{domain, state}], link handling allowed)."""
    links: list[dict] = []
    seen: set[str] = set()
    section = None
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("Domain verification state"):
            section = "verify"
            continue
        if s.startswith("Enabled:"):
            section = "user-enabled"
            continue
        if s.startswith("Disabled:"):
            section = "user-disabled"
            continue
        if s.startswith(("User ", "Selection state", "ID:", "Signatures")):
            section = None if not s.startswith("Selection state") else section
            continue
        if section == "verify":
            m = _LINK_STATE.match(line)
            if m and m.group(1) not in seen:
                seen.add(m.group(1))
                links.append({"domain": m.group(1), "state": m.group(2)})
        elif section in ("user-enabled", "user-disabled") and s and "." in s and " " not in s:
            if s not in seen:
                seen.add(s)
                links.append({"domain": s, "state": section})
    m = _LINKS_ALLOWED.search(out)
    return links, (m.group(1) == "true") if m else None


def parse_overlays(out: str, pkg: str) -> list[dict]:
    """`cmd overlay list` lines under the "<pkg>" target header."""
    res: list[dict] = []
    inside = False
    for line in out.splitlines():
        if not line.strip():
            continue
        m = _OVERLAY_LINE.match(line)
        if m:
            if inside:
                res.append({"name": m.group(2), "enabled": m.group(1) == "[x]"})
            continue
        inside = line.strip() == pkg
    return res


def parse_ssaid(xml: str, pkg: str) -> str | None:
    for m in _SETTING_TAG.finditer(xml):
        attrs = dict(_ATTR.findall(m.group(1)))
        if attrs.get("package") == pkg:
            return attrs.get("value") or None
    return None


def controls(dctx, pkg: str, user: int = 0) -> dict:
    """Every per-app toggle the controls panel shows, each probed on its own
    so one failing command leaves the rest intact (errors[key] says why)."""
    _vpkg(pkg)
    user = _vuser(user)
    adb = dctx.adb
    q = shlex.quote(pkg)
    out: dict = {"battery_whitelisted": None, "net_restricted_background": None,
                 "data_saver": None, "sensors": None, "denylist": None,
                 "denylist_available": False, "app_links": [], "app_links_allowed": None,
                 "firewall_blocked": None, "overlays": [], "ssaid": None,
                 "keystore_files": None, "errors": {}}
    errors = out["errors"]

    def probe(key, fn):
        try:
            out[key] = fn()
        except Exception as e:  # noqa: BLE001 - one probe never hides the rest
            errors[key] = str(e)[:200]

    uid = _safe(lambda: _uid_for(dctx, pkg, user), None)

    def battery():
        txt = adb.shell_sync("dumpsys deviceidle whitelist", timeout=15)
        return any(pkg in [t.strip() for t in ln.split(",")] for ln in txt.splitlines())
    probe("battery_whitelisted", battery)

    def restricted():
        if uid is None:
            raise AdbError("uid unknown")
        txt = adb.shell_sync("cmd netpolicy list restrict-background-blacklist", timeout=15)
        return str(uid) in re.findall(r"\d+", txt.split(":", 1)[-1])
    probe("net_restricted_background", restricted)

    def saver():
        txt = adb.shell_sync("cmd netpolicy get restrict-background", timeout=15).lower()
        if "enabled" in txt:
            return True
        if "disabled" in txt:
            return False
        raise AdbError(txt.strip()[:80] or "no answer")
    probe("data_saver", saver)

    def sensors():
        txt = adb.shell_sync(f"cmd sensorservice get-uid-state {q}", timeout=15).lower()
        if "active" in txt:
            return "active"
        if "idle" in txt:
            return "idle"
        return None
    probe("sensors", sensors)

    def denylist():
        txt = adb.shell_sync("magisk --denylist ls", su=True, timeout=15)
        if not _ok(txt):
            raise AdbError(txt.strip()[:80])
        out["denylist_available"] = True
        return any(ln.split("|", 1)[0].strip() == pkg for ln in txt.splitlines())
    probe("denylist", denylist)

    def app_links():
        txt = adb.shell_sync(f"pm get-app-links --user {user} {q}", timeout=20)
        links, allowed = parse_app_links(txt)
        out["app_links_allowed"] = allowed
        return links
    probe("app_links", app_links)

    def firewall():
        if uid is None:
            raise AdbError("uid unknown")
        txt = adb.shell_sync("iptables -S OUTPUT", su=True, timeout=15)
        if not _ok(txt):
            raise AdbError(txt.strip()[:80])
        return any(f"--uid-owner {uid} " in ln + " " and "REJECT" in ln for ln in txt.splitlines())
    probe("firewall_blocked", firewall)

    probe("overlays", lambda: parse_overlays(
        adb.shell_sync(f"cmd overlay list --user {user}", timeout=20), pkg))

    def ssaid():
        path = f"/data/system/users/{user}/settings_ssaid.xml"
        txt = ""
        try:
            txt = adb.shell_sync(f"abx2xml {path} -", su=True, timeout=15)
        except AdbError:
            pass
        if "<setting" not in txt:
            txt = adb.shell_sync(f"cat {path}", su=True, timeout=15)
        return parse_ssaid(txt, pkg)
    probe("ssaid", ssaid)

    def keystore():
        if uid is None:
            raise AdbError("uid unknown")
        txt = adb.shell_sync(f"ls /data/misc/keystore/user_{user}", su=True, timeout=15)
        if not _ok(txt):
            raise AdbError(txt.strip()[:80])
        return sum(1 for ln in txt.split() if ln.startswith(f"{uid}_"))
    probe("keystore_files", keystore)
    return out


# ---------------- export / history ----------------

EXPORT_COLUMNS = ("label", "package", "version", "system", "enabled", "installed", "installer",
                  "uid", "data_size", "apk_size")


def export_rows(apps: list[dict], inv: dict | None = None) -> list[dict]:
    """Listing rows -> flat export rows (version from the collector inventory)."""
    inv = inv or {}
    rows = []
    for a in apps:
        pkg = a.get("package", "")
        rows.append({"label": a.get("label") or "", "package": pkg,
                     "version": (inv.get(pkg) or {}).get("version_name") or a.get("version_name") or "",
                     "system": bool(a.get("system")), "enabled": bool(a.get("enabled", True)),
                     "installed": bool(a.get("installed", True)),
                     "installer": a.get("installer") or "", "uid": a.get("uid"),
                     "data_size": a.get("data_size") or 0, "apk_size": a.get("apk_size") or 0})
    return rows


def render_export(rows: list[dict], fmt: str) -> tuple[str, str, str]:
    """-> (body, media type, file extension) for csv | json | md."""
    import csv
    import io
    import json
    if fmt == "json":
        return json.dumps({"apps": rows, "count": len(rows)}, indent=1), "application/json", "json"
    if fmt == "md":
        lines = ["| " + " | ".join(EXPORT_COLUMNS) + " |",
                 "|" + "|".join(" --- " for _ in EXPORT_COLUMNS) + "|"]
        for r in rows:
            lines.append("| " + " | ".join(str(r.get(c, "")).replace("|", "\\|")
                                           for c in EXPORT_COLUMNS) + " |")
        return "\n".join(lines) + "\n", "text/markdown", "md"
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(EXPORT_COLUMNS), extrasaction="ignore",
                       lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow(r)
    return buf.getvalue(), "text/csv", "csv"


def export(dctx, fmt: str = "csv", which: str = "all", user=None) -> tuple[str, str, str]:
    data = list_apps(dctx, which or "all", user)
    return render_export(export_rows(data.get("apps", []), dctx.state.get("apps") or {}), fmt)


def history(dctx, limit: int = 200) -> dict:
    """Stored app.action events for this device, newest first."""
    try:
        evs = dctx.store.events(kinds=["app.action"], limit=max(1, min(int(limit), 2000)),
                                device=getattr(dctx, "serial", None))
    except Exception:  # noqa: BLE001
        evs = []
    out = []
    for e in evs:
        d = e.get("data") or {}
        out.append({"ts": e.get("ts"), "action": d.get("action") or (e.get("title") or "").split(":")[0],
                    "package": e.get("app") or "", "ok": bool(d.get("ok")),
                    "output": d.get("output") or e.get("detail") or "",
                    "user": d.get("user", 0), "params": d.get("params") or {}})
    return {"events": out}
