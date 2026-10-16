"""FastAPI app: REST + WebSocket + static dashboard.

Binds to 127.0.0.1 by default. This dashboard is a window into your own
device; never expose it to the network.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from pathlib import Path

from urllib.parse import urlparse

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
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

log = logging.getLogger("sentinel.app")

_STATIC = Path(__file__).parent / "static"

# Permissions that materially raise an app's risk, short-named.
_DANGEROUS = {
    "READ_SMS", "RECEIVE_SMS", "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION", "READ_CONTACTS", "READ_CALL_LOG",
    "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "QUERY_ALL_PACKAGES",
    "READ_PHONE_STATE", "PROCESS_OUTGOING_CALLS", "READ_EXTERNAL_STORAGE",
}
# where apps commonly keep logs, relative to /data/data/<pkg>
_LOG_HINTS = ("*.log", "*.txt", "*log*", "*.trace", "*.out")


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
    """Where one app keeps its data, and its log-like files. Root, on demand."""
    adb = dctx.adb
    from ..parsers.storage import parse_du_k, parse_ls_la
    data_dir = f"/data/data/{pkg}"
    ext_dir = f"/sdcard/Android/data/{pkg}"
    try:
        sizes = parse_du_k(adb.du_sizes([data_dir, ext_dir, f"{data_dir}/cache",
                                         f"{data_dir}/databases", f"{data_dir}/shared_prefs",
                                         f"{data_dir}/files"]))
    except AdbError:
        sizes = {}
    try:
        listing = [e.to_dict() for e in parse_ls_la(adb.list_dir(data_dir))]
    except AdbError:
        listing = []
    try:
        log_out = adb.find_files(data_dir, list(_LOG_HINTS), limit=100)
        logs = [ln.strip() for ln in log_out.splitlines() if ln.strip()]
    except AdbError:
        logs = []
    return {
        "package": pkg, "data_dir": data_dir, "external_dir": ext_dir,
        "sizes": sizes, "entries": listing, "log_files": logs,
        "subdirs": {
            "files": f"{data_dir}/files", "cache": f"{data_dir}/cache",
            "databases": f"{data_dir}/databases", "shared_prefs": f"{data_dir}/shared_prefs",
            "code_cache": f"{data_dir}/code_cache", "external": ext_dir,
        },
    }


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
        if not origin:
            return True
        try:
            return (urlparse(origin).hostname or "") in _local_hosts
        except ValueError:
            return False

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

    def _dev(serial: str | None):
        return hub.resolve(serial)

    # ---------- devices & ADB control ----------
    @app.get("/api/devices")
    def devices():
        """Everything adb sees (incl. unauthorized/offline, with why) plus the
        devices actively monitored."""
        monitored = {s: d.summary() for s, d in hub.devices.items()}
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
        ok = False
        for dctx in hub.devices.values():     # rule toggles apply to every device
            ok = dctx.rules.set_enabled(rule_id, on) or ok
        hub.store.put_snapshot("rules_enabled",
                               {rid: on for rid in [rule_id]} if not hub.devices
                               else next(iter(hub.devices.values())).rules.enabled_map())
        return JSONResponse({"ok": ok}, status_code=200 if ok else 404)

    # ---------- storage / files / backup ----------
    @app.get("/api/storage")
    def storage(device: str | None = None):
        dctx = _dev(device)
        return (dctx.state.get("storage") if dctx else None) or {"apps": {}, "totals": {}}

    @app.get("/api/storage/app/{pkg}")
    async def storage_app(pkg: str, device: str | None = None):
        dctx = _dev(device)
        if dctx is None or dctx.adb is None:
            return {"demo": True, **_demo_app_storage(pkg)}
        return await asyncio.to_thread(_inspect_app_storage, dctx, pkg)

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
        asyncio.create_task(asyncio.to_thread(backup.run, dctx, job))
        return {"job": job["id"], "pkg": pkg, "serial": dctx.serial, "state": job["state"]}

    @app.get("/api/backup/jobs")
    def backup_jobs():
        return sorted(backup.jobs.values(), key=lambda j: j["id"], reverse=True)

    @app.get("/api/backups")
    def backups(device: str | None = None):
        return backup.list_backups(serial=device)

    @app.get("/api/export/evidence")
    def export_evidence(hours: float = 24.0, device: str | None = None):
        serial = device if device else hub.default_serial()
        return _export_evidence(hub, serial, hours)

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
