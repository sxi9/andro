"""FastAPI app: REST + WebSocket + static dashboard.

Binds to 127.0.0.1 by default. This dashboard is a window into your own
device; never expose it to the network.
"""
from __future__ import annotations

import asyncio
import contextlib
import errno
import json
import logging
import os
import re
import shutil
import sys
import threading
import time
import uuid
from pathlib import Path

from urllib.parse import urlparse

from fastapi import FastAPI, File, Form, Query, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .. import __version__
from ..adb.client import AdbClient, AdbError
from ..adb.device import DeviceMaps, device_info
from ..config import Config
from ..context import AppContext, DeviceContext, Hub
from ..core.bus import EventBus
from ..core.events import Event, SEV_INFO, SEV_NOTICE
from ..core.rules import RulesEngine
from ..core.store import Store
from ..enrich.geoip import GeoIP
from ..enrich.hostnames import HostnameCache
from ..enrich.trackers import TrackerMatcher
from ..service.appmanager import ONECLICK_OPS, PKG_RE, links_for
from ..service.appdata import DB_FILE, PREF_FILE, TABLE
from ..service.installer import BUNDLE_EXTS, MAX_UPLOAD

log = logging.getLogger("sentinel.app")

_STATIC = Path(__file__).parent / "static"
_DEMO_ACTION = {"ok": False, "output": "needs a real device (not demo mode)"}

# Permissions that materially raise an app's risk, short-named.
_DANGEROUS = {
    "READ_SMS", "RECEIVE_SMS", "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION", "READ_CONTACTS", "READ_CALL_LOG",
    "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "QUERY_ALL_PACKAGES",
    "READ_PHONE_STATE", "PROCESS_OUTGOING_CALLS", "READ_EXTERNAL_STORAGE",
}
def _risk_score(d: dict, godmode: list[str], netstat: dict) -> tuple[int, list[str]]:
    """0-100 blend of the factors a privacy-conscious owner cares about."""
    score = 0
    factors: list[str] = []
    if godmode:
        score += min(30 * len(godmode), 45)
        factors.append("god-mode: " + ", ".join(godmode))
    granted = {p.rsplit(".", 1)[-1] for p in (d.get("granted") or [])}
    hot = sorted(granted & _DANGEROUS)
    if hot:
        score += min(6 * len(hot), 30)
        factors.append(f"{len(hot)} dangerous permissions")
    installer = d.get("installer")
    if installer not in ("com.android.vending", "com.sec.android.app.samsungapps",
                         "(system)", None) or (installer is None and not d.get("system")):
        score += 12
        factors.append("sideloaded")
    mtx = netstat.get("mtx", 0) or 0
    if mtx > 50_000_000:
        score += 8
        factors.append("heavy cellular egress")
    if "READ_SMS" in granted and "INTERNET" in granted:
        score += 10
        factors.append("SMS + internet")
    return min(score, 100), factors


def _inspect_app_storage(dctx, pkg: str) -> dict:
    """Where one app keeps its data (lives in service.appdata now)."""
    from ..service.appdata import storage
    return storage(dctx, pkg)


def _list_files(dctx, path: str) -> dict:
    from ..parsers.storage import parse_ls_la
    try:
        entries = [e.to_dict() for e in parse_ls_la(dctx.adb.list_dir(path))]
        err = None
    except AdbError as e:
        entries, err = [], str(e)
    return {"path": path, "entries": entries, "error": err}


def _export_evidence(hub, serial: str | None, hours: float) -> dict:
    """Write a timestamped JSON + text report of the window to data_dir/reports."""
    import hashlib
    import json
    since = time.time() - hours * 3600
    alerts = [a for a in hub.store.alerts(state=None, limit=1000, device=serial)
              if a["ts"] >= since]
    events = hub.store.events(since=since, limit=2000, device=serial)
    key_events = [e for e in events if e["kind"].startswith(("sensor.", "threat.", "app."))
                  or e["severity"] in ("warn", "crit")]
    dctx = hub.devices.get(serial) if serial else None
    report = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "window_hours": hours,
        "device": dctx.device if dctx else {"serial": serial},
        "alerts": alerts,
        "events": key_events[:1000],
    }
    out_dir = hub.cfg.data_dir / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    json_path = out_dir / f"evidence_{stamp}.json"
    # Write the file, THEN hash its exact bytes, so `sha256sum <file>`
    # reproduces the digest (real chain-of-custody, not a self-referential hash).
    json_path.write_text(json.dumps(report, indent=2, default=str))
    digest = hashlib.sha256(json_path.read_bytes()).hexdigest()
    (out_dir / f"evidence_{stamp}.json.sha256").write_text(f"{digest}  {json_path.name}\n")
    txt = ["Android Sentinel evidence report", f"generated {report['generated']}",
           f"window: last {hours}h",
           f"sha256({json_path.name}) = {digest}  (verify: sha256sum the .json)", ""]
    txt.append(f"ALERTS ({len(alerts)}):")
    for a in alerts:
        txt.append(f"  [{a['severity']}] {a['title']} - {a.get('detail','')}")
    (out_dir / f"evidence_{stamp}.txt").write_text("\n".join(txt))
    return {"path": str(json_path), "sha256": digest,
            "alerts": len(alerts), "events": len(key_events)}


def _demo_app_storage(pkg: str) -> dict:
    data_dir = f"/data/data/{pkg}"
    return {
        "package": pkg, "data_dir": data_dir,
        "external_dir": f"/sdcard/Android/data/{pkg}",
        "sizes": {data_dir: 48 * 1024 * 1024, f"{data_dir}/cache": 12 * 1024 * 1024,
                  f"{data_dir}/databases": 8 * 1024 * 1024,
                  f"{data_dir}/shared_prefs": 64 * 1024, f"{data_dir}/files": 20 * 1024 * 1024},
        "entries": [
            {"name": "cache", "kind": "dir", "size": 4096, "perms": "drwxrws--x", "mtime": "2026-10-15 10:00", "target": None},
            {"name": "databases", "kind": "dir", "size": 4096, "perms": "drwxrwx--x", "mtime": "2026-10-15 10:00", "target": None},
            {"name": "files", "kind": "dir", "size": 4096, "perms": "drwxrwx--x", "mtime": "2026-10-15 10:00", "target": None},
            {"name": "shared_prefs", "kind": "dir", "size": 4096, "perms": "drwxrwx--x", "mtime": "2026-10-15 10:00", "target": None},
        ],
        "log_files": [f"{data_dir}/files/app.log", f"{data_dir}/files/logs/network.log",
                      f"{data_dir}/cache/crash.txt"],
        "subdirs": {"files": f"{data_dir}/files", "cache": f"{data_dir}/cache",
                    "databases": f"{data_dir}/databases", "shared_prefs": f"{data_dir}/shared_prefs",
                    "code_cache": f"{data_dir}/code_cache", "external": f"/sdcard/Android/data/{pkg}"},
    }


def _demo_app_list() -> list[dict]:
    rows = [
        ("com.whatsapp", False, True, "com.android.vending", 10155, 190, 44, False),
        ("com.wx.weatherpro", False, True, None, 10412, 61, 23, True),
        ("com.led.qrflash", False, False, None, 10501, 30, 12, True),
        ("com.android.chrome", False, True, "com.android.vending", 10091, 310, 120, False),
        ("com.android.settings", True, True, "(system)", 1000, 80, 40, False),
        ("com.google.android.gms", True, True, "(system)", 10012, 420, 260, False),
        ("com.android.vending", True, True, "(system)", 10013, 210, 150, False),
    ]
    return [{"package": p, "system": s, "enabled": e, "installer": i, "uid": u,
             "data_size": d * 1024 * 1024, "apk_size": a * 1024 * 1024, "godmode": g}
            for (p, s, e, i, u, d, a, g) in rows]


def _demo_app_detail(pkg: str) -> dict:
    return {
        "package": pkg,
        "detail": {
            "version": 271024, "version_name": "2.26.4", "installer": "com.android.vending",
            "system": False, "sig": "6a8b96e2", "last_update": "2026-10-01 10:00:00",
            "first_install": "2025-02-11 08:00:00", "data_dir": f"/data/data/{pkg}",
            "target_sdk": 34, "min_sdk": 24, "abi": "arm64-v8a", "enabled": True,
            "requested": ["android.permission.INTERNET", "android.permission.CAMERA",
                          "android.permission.RECORD_AUDIO", "android.permission.READ_CONTACTS"],
            "granted": ["android.permission.INTERNET", "android.permission.CAMERA"],
            "disabled_components": [f"{pkg}.AdReceiver"],
            "enabled_components": [],
        },
        "appops": [{"op": "RECORD_AUDIO", "mode": "allow", "background": False, "rejected": False, "ago": 42},
                   {"op": "CAMERA", "mode": "allow", "background": False, "rejected": False, "ago": 300}],
        "godmode": [], "sizes": {"data": 48 * 1024 * 1024, "cache": 12 * 1024 * 1024,
                                 "app": 44 * 1024 * 1024},
        "apk_paths": [f"/data/app/~~x/{pkg}-y/base.apk"],
        "users_installed": [10] if pkg == _DEMO_CHROME else [0],  # matches the demo list / find
        "state": {"installed": True, "hidden": False, "suspended": False, "stopped": False,
                  "enabled_state": 0, "frozen": None, "user": 0},
        "perm_flags": {"android.permission.CAMERA": ["USER_SET", "USER_SENSITIVE_WHEN_GRANTED"],
                       "android.permission.RECORD_AUDIO": ["USER_SET", "USER_FIXED"]},
        "uid": 10155, "shared_user": None, "process": pkg,
        "data_usage": {"wifi_rx": 182_400_000, "wifi_tx": 21_300_000,
                       "mobile_rx": 9_800_000, "mobile_tx": 2_100_000},
        "running": {"pids": [4711, 4790], "rss_kb": 186_432},
        "links": links_for(pkg),
    }


def _demo_root() -> dict:
    return {"demo": True, "root": True, "su_path": "/debug_ramdisk/su",
            "manager": {"name": "Magisk", "version": "27.0:MAGISK:R (27000)"},
            "adbd_root": False, "selinux": "Enforcing", "use_su": True}


def _demo_controls(pkg: str) -> dict:
    return {"demo": True, "battery_whitelisted": pkg == "com.whatsapp",
            "net_restricted_background": pkg == "com.wx.weatherpro", "data_saver": False,
            "sensors": "active", "denylist": pkg == "com.android.vending",
            "denylist_available": True,
            "app_links": [{"domain": f"{pkg.split('.')[1] if '.' in pkg else pkg}.com",
                           "state": "verified"},
                          {"domain": "links.example.org", "state": "none"}],
            "app_links_allowed": True, "firewall_blocked": False,
            "overlays": [{"name": f"{pkg}.overlay.theme", "enabled": True},
                         {"name": f"{pkg}.overlay.icons", "enabled": False}],
            "ssaid": "3f9a1c2e7b4d6a80", "keystore_files": 2, "errors": {}}


def _demo_storage(pkg: str) -> dict:
    base = f"/data/app/~~x/{pkg}-y"
    return {**_demo_app_storage(pkg), "demo": True,
            "obb_dir": f"/sdcard/Android/obb/{pkg}", "media_dir": f"/sdcard/Android/media/{pkg}",
            "de_dir": f"/data/user_de/0/{pkg}", "cache_bytes": 12 * 1024 * 1024,
            "data_bytes": 48 * 1024 * 1024, "app_bytes": 44 * 1024 * 1024,
            "apk_paths": [f"{base}/base.apk", f"{base}/split_config.arm64_v8a.apk"],
            "splits": [{"path": f"{base}/base.apk", "size": 36 * 1024 * 1024},
                       {"path": f"{base}/split_config.arm64_v8a.apk", "size": 8 * 1024 * 1024}],
            "backups": [{"name": f"{pkg}_20261001-100000", "path": f"~/.android-sentinel/backups/demo-pixel7/{pkg}_20261001-100000",
                         "bytes": 52 * 1024 * 1024, "captured": "20261001-100000",
                         "components": ["apk", "data"]}]}


def _demo_component(name: str, kind: str, tracker: str | None = None, exported: bool = False) -> dict:
    c = {"name": name, "exported": exported, "permission": None, "enabled": True,
         "process": None, "tracker": tracker}
    if kind == "provider":
        return {**c, "authorities": [name.lower()], "grant_uri_permissions": False}
    return {**c, "launch_mode": "standard" if kind == "activity" else None,
            "intent_filters": ([{"actions": ["android.intent.action.MAIN"],
                                 "categories": ["android.intent.category.LAUNCHER"], "data": []}]
                               if name.endswith("MainActivity") else [])}


def _demo_manifest(pkg: str) -> dict:
    base = f"/data/app/~~x/{pkg}-y/base.apk"
    return {
        "demo": True, "package": pkg, "version_name": "2.26.4", "version_code": 271024,
        "min_sdk": 24, "target_sdk": 34, "max_sdk": None, "main_activity": f"{pkg}.MainActivity",
        "debuggable": False, "allow_backup": False, "test_only": False,
        "uses_cleartext_traffic": True, "large_heap": True, "multidex": True,
        "activities": [_demo_component(f"{pkg}.MainActivity", "activity", exported=True),
                       _demo_component("com.google.android.gms.ads.AdActivity", "activity",
                                       "Google AdMob", exported=True)],
        "services": [_demo_component(f"{pkg}.SyncService", "service"),
                     _demo_component("com.google.firebase.messaging.FirebaseMessagingService",
                                     "service", "Google Firebase Analytics", exported=True)],
        "receivers": [_demo_component("com.facebook.CampaignTrackingReceiver", "receiver",
                                      "Facebook Analytics", exported=True)],
        "providers": [_demo_component(f"{pkg}.FileProvider", "provider")],
        "uses_permissions": [{"name": "android.permission.INTERNET", "max_sdk": None, "dangerous": False},
                             {"name": "android.permission.CAMERA", "max_sdk": None, "dangerous": True},
                             {"name": "android.permission.RECORD_AUDIO", "max_sdk": None, "dangerous": True},
                             {"name": "android.permission.READ_CONTACTS", "max_sdk": None, "dangerous": True}],
        "declared_permissions": [{"name": f"{pkg}.permission.C2D_MESSAGE", "protection_level": "signature"}],
        "features": [{"name": "android.hardware.camera", "required": False}],
        "libraries": [{"name": "org.apache.http.legacy", "required": False}],
        "native_libs": [{"abi": "arm64-v8a", "files": ["libapp.so", "libsqlcipher.so"]}],
        "dex_files": ["classes.dex", "classes2.dex", "classes3.dex"],
        "meta_data": {"com.google.android.gms.version": "12451000",
                      "firebase_analytics_collection_enabled": "true"},
        "splits": [{"path": base, "size": 36 * 1024 * 1024}],
        "signatures": [{"scheme": "v2", "subject": f"CN={pkg}, O=Demo Corp, C=US",
                        "issuer": f"CN={pkg}, O=Demo Corp, C=US", "serial": "4f3a2b1c",
                        "not_before": "2019-03-01 00:00:00", "not_after": "2049-03-01 00:00:00",
                        "sha256": "6a8b96e2" * 8, "sha1": "6a8b96e2" * 5, "md5": "6a8b96e2" * 4,
                        "algorithm": "SHA256withRSA"}],
        "manifest_xml": (f'<manifest package="{pkg}" android:versionCode="271024">\n'
                         '  <uses-permission android:name="android.permission.INTERNET"/>\n'
                         '  <uses-permission android:name="android.permission.CAMERA"/>\n'
                         f'  <application android:label="Demo">\n    <activity android:name="{pkg}.MainActivity" android:exported="true"/>\n'
                         '  </application>\n</manifest>'),
        "apk_path": base, "apk_size": 36 * 1024 * 1024, "cached": True,
    }


def _demo_scan(pkg: str) -> dict:
    return {
        "demo": True, "package": pkg,
        "trackers": [
            {"name": "Google AdMob", "category": "advertisement",
             "website": "https://admob.google.com/", "signatures_matched": ["com.google.android.gms.ads."],
             "classes": 412, "components": ["com.google.android.gms.ads.AdActivity"]},
            {"name": "Facebook Analytics", "category": "analytics",
             "website": "https://www.facebook.com/", "signatures_matched": ["com.facebook.appevents."],
             "classes": 86, "components": ["com.facebook.CampaignTrackingReceiver"]},
        ],
        "libraries": [{"name": "OkHttp", "website": "https://square.github.io/okhttp/", "classes": 240}],
        "native_libs": [{"abi": "arm64-v8a", "files": ["libapp.so", "libsqlcipher.so"]}],
        "dex_files": 3, "classes_scanned": 18_420, "apk_size": 36 * 1024 * 1024,
        "scanned_at": "2026-10-15T10:00:00+00:00", "scanned_ts": 1760522400.0, "cached": True,
    }


def _demo_prefs(pkg: str) -> dict:
    return {"demo": True, "files": [{"name": f"{pkg}_preferences.xml", "size": 1480, "entries": 3}]}


def _demo_prefs_file(file: str) -> dict:
    return {"demo": True, "file": file,
            "entries": [{"key": "analytics_enabled", "type": "boolean", "value": True},
                        {"key": "user_id", "type": "string", "value": "u-48213"},
                        {"key": "launch_count", "type": "int", "value": 42}]}


def _demo_db() -> dict:
    return {"demo": True, "files": [{"name": "app.db", "size": 245_760}]}


def _demo_db_file(file: str, table: str | None, limit: int) -> dict:
    tables = [{"name": "messages", "rows": 1240}, {"name": "contacts", "rows": 38}]
    columns: list[str] = []
    rows: list[list] = []
    if table == "messages":
        columns = ["id", "sender", "body", "ts"]
        rows = [[1, "+15551234", "hi there", 1760500800], [2, "+15559876", "see you at 8", 1760504400],
                [3, "+15551234", "ok", 1760508000]]
    elif table == "contacts":
        columns = ["id", "name", "phone"]
        rows = [[1, "Alice", "+15551234"], [2, "Bob", "+15559876"]]
    return {"demo": True, "file": file, "tables": tables, "table": table if columns else None,
            "columns": columns, "rows": rows[:limit], "truncated": False}


def _demo_running() -> dict:
    procs = [(4711, 680, 10155, 186_432, "S", "00:04:12", "com.whatsapp"),
             (4790, 680, 10155, 24_100, "S", "00:00:08", "com.whatsapp:push"),
             (3912, 680, 10091, 310_204, "S", "00:12:40", "com.android.chrome"),
             (5120, 680, 10412, 41_800, "S", "00:00:31", "com.wx.weatherpro"),
             (1388, 1, 1000, 98_000, "S", "01:02:03", "system_server")]
    return {"demo": True,
            "processes": [{"pid": p, "ppid": pp, "uid": u, "package": n.split(":")[0] if u >= 10000 else None,
                           "name": n, "rss_kb": r, "state": s, "cputime": t}
                          for (p, pp, u, r, s, t, n) in procs],
            "mem": {"total_kb": 7_900_000, "avail_kb": 2_600_000,
                    "swap_total_kb": 2_000_000, "swap_free_kb": 1_200_000}}


def _demo_history() -> dict:
    now = time.time()
    return {"demo": True, "events": [
        {"ts": now - 120, "action": "force-stop", "package": "com.wx.weatherpro", "ok": True,
         "output": "(done)", "user": 0, "params": {}},
        {"ts": now - 3600, "action": "revoke", "package": "com.led.qrflash", "ok": True,
         "output": "(done)", "user": 0, "params": {"permission": "android.permission.READ_SMS"}},
        {"ts": now - 7200, "action": "freeze", "package": "com.android.chrome", "ok": False,
         "output": "Error: Shell cannot change component state", "user": 0,
         "params": {"method": "disable"}},
    ]}


_DEMO_USERS = [{"id": 0, "name": "Owner", "running": True},
               {"id": 10, "name": "Work profile", "running": True}]
# demo: Chrome is debloated for the owner but still installed in the work profile
_DEMO_CHROME = "com.android.chrome"


def _probe_resolver() -> bool:
    try:
        import pyaxmlparser  # noqa: F401
        return True
    except ImportError:
        return False


# probed once at import: the import pulls in lxml and would otherwise run on
# the event loop inside the first list request
_CAN_RESOLVE = _probe_resolver()


def _probe_multipart() -> bool:
    try:
        import multipart  # noqa: F401  (python-multipart)
        return True
    except ImportError:
        try:
            import python_multipart  # noqa: F401  (newer package name)
            return True
        except ImportError:
            return False


_HAS_MULTIPART = _probe_multipart()


def _can_resolve() -> bool:
    """True when the APK parser is installed on this host."""
    return _CAN_RESOLVE


def _demo_handlers(user: int) -> dict:
    from ..enrich.labels import label_for
    roles = {"browser": [_DEMO_CHROME], "home": ["com.android.launcher3"],
             "sms": ["com.google.android.apps.messaging"],
             "dialer": ["com.google.android.dialer"], "assistant": []}
    comps = {"browser": f"{_DEMO_CHROME}/com.google.android.apps.chrome.Main",
             "launcher": "com.android.launcher3/.Launcher",
             "sms": "com.google.android.apps.messaging/.ui.ConversationListActivity",
             "dialer": "com.google.android.dialer/.DialtactsActivity",
             "camera": "com.android.camera2/com.android.camera.CaptureActivity"}
    handlers = {k: [{"package": c.split("/")[0], "label": label_for(c.split("/")[0]),
                     "component": c}] for k, c in comps.items()}
    return {"user": user, "roles": roles, "handlers": handlers,
            "defaults": {"browser": _DEMO_CHROME, "launcher": "com.android.launcher3",
                         "sms": "com.google.android.apps.messaging",
                         "dialer": "com.google.android.dialer"},
            "default_browser": _DEMO_CHROME}


def _demo_find(q: str) -> dict:
    from ..enrich.labels import label_for
    from ..service.appmanager import QUERY_RE
    if not QUERY_RE.match(q or "") or not q.strip():
        return {"query": (q or "")[:64], "users": [], "scanned": 0, "matches": [],
                "apk_dirs": [], "browsers": [], "error": "invalid query"}
    ql = q.strip().lower()
    apps = _demo_app_list()
    matches = []
    for a in apps:
        label = label_for(a["package"])
        if ql in a["package"].lower() or ql in label.lower():
            chrome = a["package"] == _DEMO_CHROME
            matches.append({"package": a["package"], "label": label, "system": a["system"],
                            "users": [{"id": 0, "installed": not chrome},
                                      {"id": 10, "installed": chrome}]})
    h = _demo_handlers(0)
    return {"query": q.strip(), "users": _DEMO_USERS, "scanned": len(apps), "matches": matches,
            "apk_dirs": ["/product/app/Chrome"] if "chrome" in ql else [],
            "browsers": [{**b, "default": b["package"] == h["default_browser"]}
                         for b in h["handlers"]["browser"]]}


def _demo_files(path: str) -> list[dict]:
    base = [("DCIM", "dir"), ("Download", "dir"), ("Android", "dir"), ("Pictures", "dir"),
            ("whatsapp.db", "file"), ("notes.txt", "file")]
    return [{"name": n, "kind": k, "size": 4096 if k == "dir" else 20480,
             "perms": "drwxrwx---" if k == "dir" else "-rw-rw----",
             "mtime": "2026-10-15 09:30", "target": None} for n, k in base]



def _should_store(ev: Event) -> bool:
    if ev.kind == "net.stats":
        return False                      # latest totals live in state, history is bulky
    if ev.kind == "log.line":
        return ev.severity != SEV_INFO    # keep W/E/F lines only
    return True


async def _event_pump(hub: Hub) -> None:
    """Store every event and route it to its device's rules engine."""
    store = hub.store
    q = hub.bus.subscribe(unbounded=True)
    saves: dict[str, int] = {}
    try:
        while True:
            ev = await q.get()
            if _should_store(ev):
                await asyncio.to_thread(store.add_event, ev)
            if ev.kind != "alert":
                dctx = hub.devices.get(ev.device) if ev.device else None
                if dctx is not None:
                    for a in dctx.rules.handle(ev):
                        a.device = ev.device
                        await asyncio.to_thread(store.add_alert, a)
                        hub.bus.publish(a)          # pump restores it exactly once
                    if ev.kind == "net.conn":
                        saves[ev.device] = saves.get(ev.device, 0) + 1
                        if saves[ev.device] % 50 == 0:
                            await asyncio.to_thread(
                                dctx.store.put_snapshot, "seen_countries",
                                dctx.rules.export_seen_countries())
    except asyncio.CancelledError:
        with contextlib.suppress(Exception):
            for dctx in hub.devices.values():
                dctx.store.put_snapshot("seen_countries",
                                        dctx.rules.export_seen_countries())
        raise


def _make_demo_devices(hub: Hub, n: int) -> list:
    """Create n simulated devices, each running the full demo pipeline."""
    from ..collectors.demo import DemoCollector
    specs = [
        ("demo-pixel7", "Pixel 7", "14", "usb"),
        ("192.168.1.42:5555", "Galaxy S23 (wireless)", "14", "wireless"),
        ("demo-oneplus", "OnePlus 11", "13", "usb"),
        ("192.168.1.77:5555", "Xiaomi 13 (wireless)", "15", "wireless"),
        ("demo-pixel6a", "Pixel 6a", "14", "usb"),
    ]
    tasks = []
    for i in range(max(1, n)):
        serial, model, android, _tr = specs[i % len(specs)]
        if i >= len(specs):
            serial = f"{serial}-{i}"
        dctx = DeviceContext(hub, serial, demo=True)
        dctx.device.update({"connected": True, "model": model, "android": android,
                            "sdk": "34", "root": True, "manufacturer": "Demo",
                            "serial": serial, "wireless": ":" in serial})
        hub.devices[serial] = dctx
        tasks.append(DemoCollector(dctx, model=model))
    return tasks


def create_app(cfg: Config) -> FastAPI:
    hub = Hub(cfg)
    tasks: list[asyncio.Task] = []
    manager = None

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI):
        nonlocal manager
        loop = asyncio.get_running_loop()
        hub.bus.attach_loop(loop)
        tasks.append(asyncio.create_task(_event_pump(hub), name="event-pump"))
        if cfg.demo:
            for c in _make_demo_devices(hub, getattr(cfg, "demo_devices", 2)):
                hub.devices[c.ctx.serial].tasks.append(
                    asyncio.create_task(c.run(), name=f"{c.ctx.serial}:demo"))
        else:
            from ..device_manager import DeviceManager
            manager = DeviceManager(hub)
            tasks.append(asyncio.create_task(manager.run(), name="device-manager"))
        log.info("Android Sentinel v%s on http://%s:%d %s",
                 __version__, cfg.host, cfg.port, "(demo mode)" if cfg.demo else "")
        try:
            yield
        finally:
            if manager is not None:
                await manager.stop_all()
            for dctx in hub.devices.values():
                for t in dctx.tasks:
                    t.cancel()
            for t in tasks:
                t.cancel()
            all_tasks = tasks + [t for d in hub.devices.values() for t in d.tasks]
            await asyncio.gather(*all_tasks, return_exceptions=True)
            hub.geoip.close()
            hub.store.close()

    app = FastAPI(title="Android Sentinel", version=__version__, lifespan=lifespan)
    app.state.hub = hub
    backup = hub.backup

    # Local-only by design. Host validation defeats DNS-rebinding.
    _local_hosts = {"127.0.0.1", "localhost", "::1"}
    if cfg.host not in ("0.0.0.0", "::"):
        _local_hosts.add(cfg.host)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(_local_hosts))

    def _origin_ok(origin: str | None) -> bool:
        # The Origin must be this server itself (scheme, host and port): a page
        # on another local port (a dev server, another tool) is cross-origin to
        # the browser, and a multipart form POST from it needs no preflight.
        if not origin:
            return True
        try:
            u = urlparse(origin)
            port = u.port if u.port is not None else {"http": 80, "https": 443}.get(u.scheme)
        except ValueError:
            return False
        return u.scheme == "http" and (u.hostname or "") in _local_hosts and port == cfg.port

    @app.middleware("http")
    async def _csrf_guard(request, call_next):
        # State-changing routes (ADB restart/kill, connect, backup, exports) must
        # not be triggerable by a cross-site page. A cross-origin fetch carries
        # the attacker's Origin and is rejected; same-origin dashboard calls and
        # non-browser clients (no Origin) pass.
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            if not _origin_ok(request.headers.get("origin")):
                return JSONResponse({"error": "cross-origin request blocked"},
                                    status_code=403)
        return await call_next(request)

    @app.middleware("http")
    async def _upload_cap(request, call_next):
        # FastAPI parses the multipart form before am_install runs, and
        # Starlette spools every file part to the temp dir with no size limit,
        # so the 400 MB cap has to be applied here on Content-Length before a
        # byte of the body is read; the handler's streamed check stays as the
        # backstop (chunked bodies carry no length). 1 MiB covers the form
        # boundaries and the options field.
        if request.method == "POST" and request.url.path == "/api/appmanager/install":
            try:
                length = int(request.headers.get("content-length") or 0)
            except ValueError:
                length = 0
            if length > MAX_UPLOAD + 1024 * 1024:
                return JSONResponse({"ok": False, "output": "file exceeds 400 MB"},
                                    status_code=413)
        return await call_next(request)

    def _dev(serial: object):
        # `device` comes straight out of the JSON body: a list/dict would blow
        # up the `in` test in Hub.resolve, so anything but a string means
        # "the default device"
        return hub.resolve(serial if isinstance(serial, str) else None)

    # ---------- devices & ADB control ----------
    @app.get("/api/devices")
    def devices():
        """Everything adb sees (incl. unauthorized/offline, with why) plus the
        devices actively monitored."""
        # snapshot the registry: DeviceManager mutates it on the event loop
        # while this handler runs in a worker thread
        monitored = {s: d.summary() for s, d in list(hub.devices.items())}
        listing = []
        for row in hub.listing:
            s = row["serial"]
            listing.append({**row, "monitored": s in hub.devices,
                            "summary": monitored.get(s)})
        # demo devices never appear in an adb listing; surface them too
        for s, summ in monitored.items():
            if not any(r["serial"] == s for r in listing):
                listing.append({"serial": s, "state": "device", "ready": True,
                                "transport": "wireless" if ":" in s else "usb",
                                "reason": "", "model": summ.get("model"),
                                "monitored": True, "summary": summ})
        return {"devices": listing, "monitored": list(hub.devices),
                "default": hub.default_serial(), "count": len(hub.devices),
                "adb_version": hub.adb.version() if hub.adb else "demo"}

    def _adb_action(method: str, *a):
        # resolve the method by name so hub.adb is never dereferenced when None
        if hub.adb is None:
            return JSONResponse({"ok": False, "error": "adb controls are off in demo mode"},
                                status_code=400)
        try:
            return {"ok": True, "output": getattr(hub.adb, method)(*a)}
        except AdbError as e:
            return JSONResponse({"ok": False, "error": str(e)}, status_code=400)

    @app.post("/api/adb/restart")
    async def adb_restart():
        return await asyncio.to_thread(_adb_action, "restart_server")

    @app.post("/api/adb/kill")
    async def adb_kill():
        return await asyncio.to_thread(_adb_action, "kill_server")

    @app.post("/api/adb/start")
    async def adb_start():
        return await asyncio.to_thread(_adb_action, "start_server")

    @app.post("/api/adb/reconnect")
    async def adb_reconnect(body: dict | None = None):
        body = body or {}
        if body.get("offline"):
            return await asyncio.to_thread(_adb_action, "reconnect_offline")
        return await asyncio.to_thread(_adb_action, "reconnect", body.get("serial"))

    @app.post("/api/adb/connect")
    async def adb_connect(body: dict):
        return await asyncio.to_thread(_adb_action, "connect", str(body.get("host_port", "")))

    @app.post("/api/adb/disconnect")
    async def adb_disconnect(body: dict | None = None):
        body = body or {}
        return await asyncio.to_thread(_adb_action, "disconnect", body.get("host_port"))

    @app.post("/api/adb/pair")
    async def adb_pair(body: dict):
        return await asyncio.to_thread(_adb_action, "pair",
                                       str(body.get("host_port", "")), str(body.get("code", "")))

    @app.post("/api/adb/tcpip")
    async def adb_tcpip(body: dict):
        serial = str(body.get("serial", ""))
        if not serial:
            return JSONResponse({"ok": False, "error": "serial required"}, status_code=400)
        return await asyncio.to_thread(_adb_action, "tcpip", serial, int(body.get("port", 5555)))

    # ---------- REST (device-scoped) ----------
    @app.get("/api/status")
    def status(device: str | None = None):
        dctx = _dev(device)
        if dctx is None:
            return {"version": __version__, "demo": cfg.demo, "device": {"connected": False},
                    "no_devices": True, "monitored": list(hub.devices),
                    "now": time.time()}
        s = dctx.state
        return {
            "version": __version__, "demo": cfg.demo, "serial": dctx.serial,
            "device": dctx.device, "transport": s.get("transport"),
            "connections": s.get("connections", 0),
            "camera_active": s.get("camera_active", []),
            "capture": s.get("capture", False), "adb_wifi": s.get("adb_wifi", False),
            "telephony": s.get("telephony", {}), "godmode": s.get("godmode", {}),
            "user_cas": s.get("user_cas", []),
            "hostnames_cached": dctx.hostnames.size(),
            "open_alerts": len(hub.store.alerts(state="open", limit=500, device=dctx.serial)),
            "monitored": list(hub.devices), "started": s.get("started"), "now": time.time(),
        }

    @app.get("/api/events")
    def events(prefix: str | None = None, kinds: str | None = None,
               since: float | None = None, limit: int = 200,
               device: str | None = None,
               app_filter: str | None = Query(default=None, alias="app")):
        kind_list = [k for k in (kinds or "").split(",") if k] or None
        serial = device if device else (hub.default_serial() if not device else None)
        return hub.store.events(kinds=kind_list, prefix=prefix, app=app_filter,
                                since=since, limit=limit, device=serial)

    @app.get("/api/alerts")
    def alerts(state: str | None = "open", limit: int = 100, device: str | None = None):
        serial = device if device else hub.default_serial()
        return hub.store.alerts(state=state if state != "all" else None, limit=limit,
                                device=serial)

    @app.post("/api/alerts/{alert_id}/state")
    def set_alert_state(alert_id: int, body: dict):
        ok = hub.store.set_alert_state(alert_id, str(body.get("state", "")))
        return JSONResponse({"ok": ok}, status_code=200 if ok else 400)

    @app.get("/api/apps")
    def apps(device: str | None = None):
        dctx = _dev(device)
        if dctx is None:
            return []
        inv = dict(dctx.state.get("apps") or {})
        god = dctx.state.get("godmode") or {}
        stats = dctx.state.get("netstats") or {}
        storage = (dctx.state.get("storage") or {}).get("apps") or {}
        uid_stats = {int(u): v for u, v in stats.items() if str(u).isdigit()}
        out = []
        for pkg, d in inv.items():
            uid = d.get("uid")
            st = uid_stats.get(uid, {}) if uid else {}
            godlist = sorted(a for a, pkgs in god.items() if pkg in pkgs)
            szd = storage.get(pkg, {})
            risk, factors = _risk_score(d, godlist, st)
            out.append({"package": pkg, **d, "godmode": godlist,
                        "rx": st.get("rx", 0), "tx": st.get("tx", 0),
                        "mtx": st.get("mtx", 0), "mrx": st.get("mrx", 0),
                        "data_size": szd.get("data", 0), "cache_size": szd.get("cache", 0),
                        "apk_size": szd.get("app", 0), "risk": risk, "risk_factors": factors})
        out.sort(key=lambda a: (-a["risk"], -(a["tx"] or 0), a["package"]))
        return out

    @app.get("/api/netstats")
    def netstats(device: str | None = None):
        dctx = _dev(device)
        return (dctx.state.get("netstats") if dctx else {}) or {}

    @app.get("/api/rules")
    def rules(device: str | None = None):
        dctx = _dev(device)
        eng = dctx.rules if dctx else RulesEngine()
        return [{"id": r.id, "name": r.name, "severity": r.severity,
                 "description": r.description, "enabled": r.enabled}
                for r in eng.rules.values()]

    @app.post("/api/rules/{rule_id}")
    def toggle_rule(rule_id: str, body: dict):
        on = bool(body.get("enabled", True))
        if rule_id not in RulesEngine().rules:   # validate against the catalog
            return JSONResponse({"ok": False, "error": "unknown rule"}, status_code=404)
        for dctx in list(hub.devices.values()):  # applies to every attached device
            dctx.rules.set_enabled(rule_id, on)
        # merge into the persisted map so other rules' states are never clobbered
        m = hub.store.get_snapshot("rules_enabled") or {}
        m[rule_id] = on
        hub.store.put_snapshot("rules_enabled", m)
        return {"ok": True, "devices": len(hub.devices)}

    # ---------- storage / files / backup ----------
    @app.get("/api/storage")
    def storage(device: str | None = None):
        dctx = _dev(device)
        return (dctx.state.get("storage") if dctx else None) or {"apps": {}, "totals": {}}

    async def _get(fn, *a):
        """Run a blocking read in a thread; device-side failures are 400s."""
        try:
            return await asyncio.to_thread(fn, *a)
        except (AdbError, ValueError, OSError, RuntimeError) as e:
            return JSONResponse({"error": str(e)}, status_code=400)

    @app.get("/api/storage/app/{pkg}")
    async def storage_app(pkg: str, device: str | None = None):
        if not PKG_RE.match(pkg):
            return JSONResponse({"error": "invalid package name"}, status_code=400)
        dctx = _dev(device)
        if dctx is None or dctx.adb is None:
            return _demo_storage(pkg)
        return await _get(_inspect_app_storage, dctx, pkg)

    @app.get("/api/files")
    async def files(path: str = "/sdcard", device: str | None = None):
        dctx = _dev(device)
        if dctx is None or dctx.adb is None:
            return {"path": path, "demo": True, "entries": _demo_files(path)}
        return await asyncio.to_thread(_list_files, dctx, path)

    @app.post("/api/backup/{pkg}")
    async def start_backup(pkg: str, body: dict | None = None,
                           device: str | None = None):
        dctx = _dev(device)
        if dctx is None or dctx.adb is None:
            return JSONResponse({"error": "backup needs a real device (not demo mode)"},
                                status_code=400)
        body = body or {}
        job = backup.new_job(pkg, dctx.serial,
                             {"apk": bool(body.get("apk", True)),
                              "data": bool(body.get("data", True)),
                              "external": bool(body.get("external", False))})
        _track(dctx, asyncio.to_thread(backup.run, dctx, job))
        return {"job": job["id"], "pkg": pkg, "serial": dctx.serial, "state": job["state"]}

    @app.get("/api/backup/jobs")
    def backup_jobs():
        return sorted(backup.jobs.values(), key=lambda j: j["id"], reverse=True)

    @app.get("/api/backups")
    def backups(device: str | None = None):
        return backup.list_backups(serial=device)

    @app.post("/api/export/evidence")
    def export_evidence(body: dict | None = None):
        # POST (not GET) so the CSRF guard covers it: it writes files to disk
        body = body or {}
        try:
            hours = float(body.get("hours", 24.0))
        except (TypeError, ValueError):
            hours = 24.0
        device = body.get("device")
        serial = device if device else hub.default_serial()
        return _export_evidence(hub, serial, hours)

    # ---------- app manager ----------
    @app.get("/api/appmanager/list")
    async def am_list(which: str = "all", device: str | None = None,
                      user: str | None = None, uninstalled: int = 1):
        # user: omitted = owner (pm's default), "all" = every user/profile, or an id
        uid: int | str | None
        if user is None or user == "":
            uid = None
        elif user == "all":
            uid = "all"
        elif re.fullmatch(r"\d{1,3}", user):  # ASCII only: str.isdigit() lets "²" through to int()
            uid = int(user)
        else:
            return JSONResponse({"error": "invalid user"}, status_code=400)
        dctx = _dev(device)
        if dctx is None or dctx.adb is None:
            from ..enrich.labels import BUILTIN_LABELS, label_for
            apps = _demo_app_list()
            for a in apps:
                a["label"] = label_for(a["package"])
                a["label_source"] = "known" if a["package"] in BUILTIN_LABELS else "guess"
                a["users_installed"] = [10] if a["package"] == _DEMO_CHROME else [0]
                a["installed"] = uid == "all" or (uid or 0) in a["users_installed"]
            if which == "uninstalled":
                apps = [a for a in apps if not a["installed"]]
            return {"demo": True, "apps": apps, "count": len(apps), "flags": "demo",
                    "users": _DEMO_USERS, "user": uid if uid is not None else 0,
                    "uninstalled": sum(1 for a in apps if not a["installed"]),
                    "labels_resolved": 0, "can_resolve": _can_resolve()}
        from ..service import appmanager
        res = await asyncio.to_thread(appmanager.list_apps, dctx, which, uid,
                                      bool(uninstalled))
        res["can_resolve"] = _can_resolve()
        return res

    @app.get("/api/appmanager/find")
    async def am_find(q: str = "", device: str | None = None):
        """Prove whether a package exists anywhere: every user (incl.
        uninstalled-for-user), the APK folders on disk, registered browsers."""
        dctx = _dev(device)
        if dctx is None or dctx.adb is None:
            return {"demo": True, **_demo_find(q)}
        from ..service import appmanager
        return await asyncio.to_thread(appmanager.find_package, dctx, q)

    @app.get("/api/appmanager/handlers")
    async def am_handlers(user: int = 0, device: str | None = None):
        """Role holders (browser/home/sms/dialer/assistant) and the activities
        answering the browser/launcher/sms/dialer/camera intents for a user."""
        if not 0 <= user <= 999:
            return JSONResponse({"error": "invalid user"}, status_code=400)
        dctx = _dev(device)
        if dctx is None or dctx.adb is None:
            return {"demo": True, **_demo_handlers(user)}
        from ..service import appmanager
        return await asyncio.to_thread(appmanager.handlers, dctx, user)

    @app.post("/api/appmanager/resolve-labels")
    async def am_resolve_labels(body: dict | None = None):
        """Extract real app names from each APK's resources (manifest +
        resources.arsc fetched by byte range, never the whole APK)."""
        body = body or {}
        dctx = _dev(body.get("device"))
        if dctx is None or dctx.adb is None:
            return JSONResponse({"ok": False, "error": "needs a real device"}, status_code=400)
        try:
            import pyaxmlparser  # noqa: F401
        except ImportError:
            return JSONResponse({"ok": False, "error": "install the optional parser: "
                                 "pip install pyaxmlparser"}, status_code=400)
        from ..enrich.labels import resolve_labels
        from ..service import appmanager
        data = await asyncio.to_thread(appmanager.list_apps, dctx, "all")
        # hand over every package: resolve_labels skips what is cached and
        # back-fills WebAPK meta for ones labelled before meta existed
        pkgs = [a["package"] for a in data.get("apps", [])]

        def progress(i: int, n: int) -> None:
            dctx.emit_threadsafe(Event(kind="log.line", severity=SEV_INFO,
                                       title="resolving app names", detail=f"{i}/{n}",
                                       data={"level": "I", "tag": "sentinel", "buffer": "sys",
                                             "labels": True, "done": i, "total": n}))

        # one resolve per device at a time: a second tab (or the auto-resolve)
        # must not start a parallel pass over the same APKs
        running = dctx.state.get("labels_task")
        if running is not None and not running.done():
            return {"ok": True, "started": False, "running": True, "packages": len(pkgs)}
        task = asyncio.create_task(asyncio.to_thread(resolve_labels, dctx, pkgs, progress))
        dctx.state["labels_task"] = task
        dctx.tasks.append(task)
        task.add_done_callback(lambda t: t in dctx.tasks and dctx.tasks.remove(t))
        return {"ok": True, "started": True, "packages": len(pkgs)}

    def _bad(msg: str):
        return JSONResponse({"error": msg}, status_code=400)

    def _refuse(msg: str):
        return JSONResponse({"ok": False, "output": msg}, status_code=400)

    def _demo_refuse():
        return JSONResponse(_DEMO_ACTION, status_code=400)

    def _track(dctx, coro) -> None:
        # keep the task alive and tear it down with the device / the server
        task = asyncio.create_task(coro)
        dctx.tasks.append(task)
        task.add_done_callback(lambda t: t in dctx.tasks and dctx.tasks.remove(t))

    @app.get("/api/appmanager/app/{pkg}")
    async def am_detail(pkg: str, device: str | None = None, user: int = 0):
        if not PKG_RE.match(pkg):
            return _bad("invalid package name")
        if not 0 <= user <= 999:
            return _bad("invalid user")
        dctx = _dev(device)
        if dctx is None or dctx.adb is None:
            return {"demo": True, **_demo_app_detail(pkg)}
        from ..service import appmanager
        return await _get(appmanager.app_detail, dctx, pkg, user)

    @app.post("/api/appmanager/action")
    async def am_action(body: dict):
        dctx = _dev(body.get("device"))
        if dctx is None or dctx.adb is None:
            return _demo_refuse()
        from ..service import appmanager
        res = await asyncio.to_thread(appmanager.run_action, dctx,
                                      str(body.get("action", "")), body)
        return res

    # ---------- app manager: per-app detail data ----------
    @app.get("/api/appmanager/app/{pkg}/controls")
    async def am_controls(pkg: str, device: str | None = None, user: int = 0):
        if not PKG_RE.match(pkg):
            return _bad("invalid package name")
        if not 0 <= user <= 999:
            return _bad("invalid user")
        dctx = _dev(device)
        if dctx is None or dctx.adb is None:
            return _demo_controls(pkg)
        from ..service import appmanager
        return await _get(appmanager.controls, dctx, pkg, user)

    @app.get("/api/appmanager/app/{pkg}/storage")
    async def am_storage(pkg: str, device: str | None = None):
        return await storage_app(pkg, device)

    @app.get("/api/appmanager/app/{pkg}/manifest")
    async def am_manifest(pkg: str, device: str | None = None, refresh: int = 0):
        if not PKG_RE.match(pkg):
            return _bad("invalid package name")
        dctx = _dev(device)
        if dctx is None or dctx.adb is None:
            return _demo_manifest(pkg)
        try:
            from ..enrich.manifest import inspect_apk
        except ImportError:
            return {"package": pkg, "cached": False, "error": "manifest module not available"}
        return await _get(inspect_apk, dctx, pkg, bool(refresh))

    @app.get("/api/appmanager/app/{pkg}/scan")
    async def am_scan(pkg: str, device: str | None = None, refresh: int = 0):
        if not PKG_RE.match(pkg):
            return _bad("invalid package name")
        dctx = _dev(device)
        if dctx is None or dctx.adb is None:
            return _demo_scan(pkg)
        try:
            from ..enrich.manifest import scan_app
        except ImportError:
            return {"package": pkg, "cached": False, "error": "manifest module not available"}
        return await _get(scan_app, dctx, pkg, bool(refresh))

    @app.get("/api/appmanager/app/{pkg}/prefs")
    async def am_prefs(pkg: str, device: str | None = None, user: int = 0):
        if not PKG_RE.match(pkg):
            return _bad("invalid package name")
        if not 0 <= user <= 999:
            return _bad("invalid user")
        dctx = _dev(device)
        if dctx is None or dctx.adb is None:
            return _demo_prefs(pkg)
        from ..service import appdata
        return await _get(appdata.prefs_list, dctx, pkg, user)

    @app.get("/api/appmanager/app/{pkg}/prefs/{file}")
    async def am_prefs_file(pkg: str, file: str, device: str | None = None, user: int = 0):
        if not PKG_RE.match(pkg):
            return _bad("invalid package name")
        if not PREF_FILE.match(file) or ".." in file:
            return _bad("invalid prefs file name")
        if not 0 <= user <= 999:
            return _bad("invalid user")
        dctx = _dev(device)
        if dctx is None or dctx.adb is None:
            return _demo_prefs_file(file)
        from ..service import appdata
        return await _get(appdata.prefs_read, dctx, pkg, file, user)

    @app.get("/api/appmanager/app/{pkg}/db")
    async def am_db(pkg: str, device: str | None = None):
        if not PKG_RE.match(pkg):
            return _bad("invalid package name")
        dctx = _dev(device)
        if dctx is None or dctx.adb is None:
            return _demo_db()
        from ..service import appdata
        return await _get(appdata.db_list, dctx, pkg)

    @app.get("/api/appmanager/app/{pkg}/db/{file}")
    async def am_db_file(pkg: str, file: str, device: str | None = None,
                         table: str | None = None, limit: int = 200):
        if not PKG_RE.match(pkg):
            return _bad("invalid package name")
        if not DB_FILE.match(file) or ".." in file:
            return _bad("invalid database file name")
        if table and not TABLE.match(table):
            return _bad("invalid table name")
        if not 1 <= limit <= 1000:
            return _bad("limit must be 1..1000")
        dctx = _dev(device)
        if dctx is None or dctx.adb is None:
            return _demo_db_file(file, table or None, limit)
        from ..service import appdata
        return await _get(appdata.db_read, dctx, pkg, file, table or None, limit)

    @app.get("/api/appmanager/running")
    async def am_running(device: str | None = None):
        dctx = _dev(device)
        if dctx is None or dctx.adb is None:
            return _demo_running()
        from ..service import appdata
        return await _get(appdata.processes, dctx)

    @app.get("/api/appmanager/history")
    async def am_history(device: str | None = None, limit: int = 200):
        dctx = _dev(device)
        if dctx is None or dctx.adb is None:
            return _demo_history()
        from ..service import appmanager
        return await _get(appmanager.history, dctx, limit)

    @app.get("/api/appmanager/export")
    async def am_export(device: str | None = None, which: str = "all",
                        user: str | None = None,
                        fmt: str = Query(default="csv", alias="format")):
        from ..service import appmanager
        if fmt not in ("csv", "json", "md"):
            return _bad("format must be csv, json or md")
        if which not in ("all", "user", "system", "disabled", "enabled", "uninstalled"):
            return _bad("invalid which")
        uid: int | str | None
        if user is None or user == "":
            uid = None
        elif user == "all":
            uid = "all"
        elif re.fullmatch(r"\d{1,3}", user):
            uid = int(user)
        else:
            return _bad("invalid user")
        dctx = _dev(device)
        serial = "demo"
        if dctx is None or dctx.adb is None:
            from ..enrich.labels import label_for
            apps = _demo_app_list()
            for a in apps:
                a["label"] = label_for(a["package"])
                a["installed"] = a["package"] != _DEMO_CHROME
            if which == "user":
                apps = [a for a in apps if not a["system"]]
            elif which == "system":
                apps = [a for a in apps if a["system"]]
            body, media, ext = appmanager.render_export(appmanager.export_rows(apps), fmt)
        else:
            serial = re.sub(r"[^A-Za-z0-9._-]", "_", dctx.serial)
            try:
                body, media, ext = await asyncio.to_thread(appmanager.export, dctx, fmt, which, uid)
            except AdbError as e:
                return _bad(str(e))
        name = f"apps-{serial}-{time.strftime('%Y%m%d-%H%M%S')}.{ext}"
        return Response(content=body, media_type=media,
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})

    # ---------- app manager: bulk ----------
    @app.get("/api/appmanager/oneclick")
    def am_oneclick_ops(device: str | None = None):
        dctx = _dev(device)
        return {"ops": ONECLICK_OPS, "demo": dctx is None or dctx.adb is None}

    async def _bulk(dctx, fn, *args):
        # One bulk pass per device at a time: a second click on the same
        # one-click op, or a batch while one runs, must not interleave
        # pm/appops commands over the same packages (cf. labels_task). The
        # check-and-acquire happens on the event loop, so it cannot race.
        lock = dctx.state.setdefault("bulk_lock", threading.Lock())
        if not lock.acquire(blocking=False):
            return JSONResponse({"ok": False, "output": "a batch is already running on this device"},
                                status_code=409)
        try:
            return await asyncio.to_thread(fn, dctx, *args)
        except AdbError as e:
            return _refuse(str(e))
        finally:
            lock.release()

    @app.post("/api/appmanager/oneclick")
    async def am_oneclick(body: dict):
        dctx = _dev(body.get("device"))
        if dctx is None or dctx.adb is None:
            return _demo_refuse()
        from ..service import appmanager
        return await _bulk(dctx, appmanager.oneclick, str(body.get("op", "")),
                           bool(body.get("confirm")), str(body.get("scope", "user")))

    @app.post("/api/appmanager/batch")
    async def am_batch(body: dict):
        dctx = _dev(body.get("device"))
        if dctx is None or dctx.adb is None:
            return _demo_refuse()
        from ..service import appmanager
        return await _bulk(dctx, appmanager.batch, str(body.get("action", "")),
                           body.get("packages"), body.get("user", 0),
                           bool(body.get("confirm")), body.get("options") or {})

    if _HAS_MULTIPART:
        @app.post("/api/appmanager/install")
        async def am_install(file: UploadFile = File(...), options: str = Form("{}")):
            """Multipart upload of one .apk or an .apks/.xapk/.apkm bundle, then
            `adb install[-multiple]` with the chosen flags."""
            from ..service import installer
            try:
                opts = json.loads(options or "{}")
            except ValueError:
                return _refuse("options must be a JSON object")
            if not isinstance(opts, dict):
                return _refuse("options must be a JSON object")
            dctx = _dev(opts.get("device"))
            if dctx is None or dctx.adb is None:
                return _demo_refuse()
            name = os.path.basename((file.filename or "").replace("\\", "/"))
            ext = os.path.splitext(name)[1].lower()
            if ext != ".apk" and ext not in BUNDLE_EXTS:
                return _refuse("expected a .apk, .apks, .xapk or .apkm file")
            try:
                installer.install_flags(opts)   # user / installer validation up front
            except AdbError as e:
                return _refuse(str(e))
            safe = (re.sub(r"[^A-Za-z0-9_.\-]", "_", name)[-120:] or "upload")
            if not safe.lower().endswith(ext):
                safe += ext
            updir = cfg.data_dir / "uploads" / uuid.uuid4().hex
            dest = updir / safe
            size = 0
            try:
                updir.mkdir(parents=True, exist_ok=True)
                with open(dest, "wb") as fh:
                    while True:
                        chunk = await file.read(1024 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > MAX_UPLOAD:
                            raise ValueError("file exceeds 400 MB")
                        fh.write(chunk)
            except ValueError as e:
                shutil.rmtree(updir, ignore_errors=True)
                return _refuse(str(e))
            except OSError as e:
                # disk full / unwritable data_dir: say why instead of a bare
                # 500, and do not leave the partial upload behind
                shutil.rmtree(updir, ignore_errors=True)
                return JSONResponse({"ok": False, "output": f"cannot save upload: {e.strerror or e}"},
                                    status_code=507 if e.errno == errno.ENOSPC else 400)
            finally:
                await file.close()
            if size == 0:
                shutil.rmtree(updir, ignore_errors=True)
                return _refuse("empty upload")
            return await asyncio.to_thread(installer.install_upload, dctx, dest, opts)

    else:
        @app.post("/api/appmanager/install")
        async def am_install_unavailable():
            # FastAPI needs python-multipart to parse uploads; the rest of the
            # dashboard keeps working on a venv that predates it
            return _refuse("installing APKs needs the python-multipart package on this computer: "
                           "run install.ps1 / install.sh again, or "
                           f"{sys.executable} -m pip install -r requirements.txt")

    @app.post("/api/restore")
    async def restore(body: dict):
        from ..service import installer
        dctx = _dev(body.get("device"))
        if dctx is None or dctx.adb is None:
            return _demo_refuse()
        if not body.get("confirm"):
            return _refuse("restore requires confirm=true")
        apk, data = bool(body.get("apk", True)), bool(body.get("data", True))
        if not apk and not data:
            return _refuse("nothing to restore: choose apk and/or data")
        try:
            job = await asyncio.to_thread(installer.new_restore_job, hub, dctx,
                                          str(body.get("name", "")), apk, data)
        except AdbError as e:
            return _refuse(str(e))
        _track(dctx, asyncio.to_thread(installer.run_restore, hub, dctx, job))
        return {"job": job["id"], "name": job["name"], "pkg": job["pkg"],
                "serial": dctx.serial, "state": job["state"]}

    # ---------- root / su ----------
    @app.get("/api/root")
    async def root_status(device: str | None = None):
        dctx = _dev(device)
        if dctx is None or dctx.adb is None:
            return _demo_root()
        from ..service import rootctl
        return await asyncio.to_thread(rootctl.root_status, dctx)

    @app.post("/api/root/request")
    async def root_request(body: dict | None = None):
        body = body or {}
        dctx = _dev(body.get("device"))
        if dctx is None or dctx.adb is None:
            return _demo_refuse()
        from ..service import rootctl
        return await asyncio.to_thread(rootctl.request_root, dctx)

    @app.post("/api/root/use")
    async def root_use(body: dict):
        dctx = _dev(body.get("device"))
        if dctx is None or dctx.adb is None:
            return _demo_refuse()
        enabled = body.get("enabled")
        if not isinstance(enabled, bool):
            return _refuse("enabled must be true or false")
        from ..service import rootctl
        return await asyncio.to_thread(rootctl.set_use_su, dctx, enabled)

    async def _adbd(body: dict | None, verb: str):
        body = body or {}
        dctx = _dev(body.get("device"))
        if dctx is None or dctx.adb is None:
            return _demo_refuse()
        ok, out = await asyncio.to_thread(getattr(dctx.adb, verb))
        return {"ok": ok, "output": out}

    @app.post("/api/adb/root")
    async def adb_root(body: dict | None = None):
        return await _adbd(body, "root")

    @app.post("/api/adb/unroot")
    async def adb_unroot(body: dict | None = None):
        return await _adbd(body, "unroot")

    # ---------- WebSocket ----------
    @app.websocket("/ws")
    async def ws(sock: WebSocket):
        if not _origin_ok(sock.headers.get("origin")):
            await sock.close(code=4403)
            return
        await sock.accept()
        q = hub.bus.subscribe()
        try:
            while True:
                ev = await q.get()
                await sock.send_text(ev.to_json())
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            hub.bus.unsubscribe(q)

    # ---------- static ----------
    @app.get("/")
    async def index():
        return FileResponse(_STATIC / "index.html")

    app.mount("/static", StaticFiles(directory=_STATIC), name="static")
    return app
