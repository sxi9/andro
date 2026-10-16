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
from ..context import AppContext
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


def _inspect_app_storage(ctx, pkg: str) -> dict:
    """Where one app keeps its data, and its log-like files. Root, on demand."""
    adb = ctx.adb
    from ..parsers.storage import parse_du_k, parse_ls_la
    data_dir = f"/data/data/{pkg}"
    ext_dir = f"/sdcard/Android/data/{pkg}"
    sizes = parse_du_k(adb.du_sizes([data_dir, ext_dir, f"{data_dir}/cache",
                                     f"{data_dir}/databases", f"{data_dir}/shared_prefs",
                                     f"{data_dir}/files"]))
    try:
        listing = [e.to_dict() for e in parse_ls_la(adb.list_dir(data_dir))]
    except AdbError:
        listing = []
    extra = " ".join(f'-o -name "{p}"' for p in _LOG_HINTS)
    extra = extra[3:] if extra.startswith("-o ") else extra  # drop leading -o
    log_out = adb.find_files(data_dir, extra=f"\\( {extra} \\)", limit=100)
    logs = [ln.strip() for ln in log_out.splitlines() if ln.strip()]
    return {
        "package": pkg, "data_dir": data_dir, "external_dir": ext_dir,
        "sizes": sizes, "entries": listing, "log_files": logs,
        "subdirs": {
            "files": f"{data_dir}/files", "cache": f"{data_dir}/cache",
            "databases": f"{data_dir}/databases", "shared_prefs": f"{data_dir}/shared_prefs",
            "code_cache": f"{data_dir}/code_cache", "external": ext_dir,
        },
    }


def _list_files(ctx, path: str) -> dict:
    from ..parsers.storage import parse_ls_la
    try:
        entries = [e.to_dict() for e in parse_ls_la(ctx.adb.list_dir(path))]
        err = None
    except AdbError as e:
        entries, err = [], str(e)
    return {"path": path, "entries": entries, "error": err}


def _export_evidence(ctx, hours: float) -> dict:
    """Write a timestamped JSON + text report of the window to data_dir/reports."""
    import hashlib
    import json
    since = time.time() - hours * 3600
    alerts = ctx.store.alerts(state=None, limit=1000)
    alerts = [a for a in alerts if a["ts"] >= since]
    events = ctx.store.events(since=since, limit=2000)
    key_events = [e for e in events if e["kind"].startswith(("sensor.", "threat.", "app."))
                  or e["severity"] in ("warn", "crit")]
    report = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "window_hours": hours,
        "device": ctx.device,
        "alerts": alerts,
        "events": key_events[:1000],
    }
    body = json.dumps(report, indent=2, default=str)
    digest = hashlib.sha256(body.encode()).hexdigest()
    report["sha256"] = digest
    body = json.dumps(report, indent=2, default=str)
    out_dir = ctx.cfg.data_dir / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    (out_dir / f"evidence_{stamp}.json").write_text(body)
    txt = [f"Android Sentinel evidence report", f"generated {report['generated']}",
           f"window: last {hours}h", f"sha256: {digest}", ""]
    txt.append(f"ALERTS ({len(alerts)}):")
    for a in alerts:
        txt.append(f"  [{a['severity']}] {a['title']} - {a.get('detail','')}")
    (out_dir / f"evidence_{stamp}.txt").write_text("\n".join(txt))
    return {"path": str(out_dir / f"evidence_{stamp}.json"),
            "sha256": digest, "alerts": len(alerts), "events": len(key_events)}


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


def build_context(cfg: Config) -> AppContext:
    bus = EventBus()
    store = Store(cfg.db_path)
    rules = RulesEngine(egress_spike_mb_per_min=cfg.egress_spike_mb_per_min)
    rules.apply_enabled_map(store.get_snapshot("rules_enabled") or {})
    rules.seed_seen_countries(store.get_snapshot("seen_countries"))

    adb: AdbClient | None = None
    maps: DeviceMaps | None = None
    if not cfg.demo:
        adb = AdbClient(adb_path=cfg.adb_path, serial=cfg.serial, use_su=cfg.use_su)
        maps = DeviceMaps(adb)

    return AppContext(
        cfg=cfg, bus=bus, store=store, rules=rules, adb=adb, maps=maps,
        hostnames=HostnameCache(),
        geoip=GeoIP(cfg.geoip_db, cfg.asn_db),
        trackers=TrackerMatcher(cfg.data_dir / "trackers.txt"),
    )


def _should_store(ev: Event) -> bool:
    if ev.kind == "net.stats":
        return False                      # latest totals live in state, history is bulky
    if ev.kind == "log.line":
        return ev.severity != SEV_INFO    # keep W/E/F lines only
    return True


async def _event_pump(ctx: AppContext) -> None:
    """store + rules for every event on the bus."""
    q = ctx.bus.subscribe(unbounded=True)
    country_saves = 0
    try:
        while True:
            ev = await q.get()
            if _should_store(ev):
                await asyncio.to_thread(ctx.store.add_event, ev)
            if ev.kind != "alert":
                alerts = ctx.rules.handle(ev)
                for a in alerts:
                    await asyncio.to_thread(ctx.store.add_alert, a)
                    # republish only: the pump sees the alert again on its own
                    # queue and stores it in the events table exactly once
                    ctx.bus.publish(a)
                if ev.kind == "net.conn":
                    country_saves += 1
                    if country_saves % 50 == 0:
                        await asyncio.to_thread(
                            ctx.store.put_snapshot, "seen_countries",
                            ctx.rules.export_seen_countries())
    except asyncio.CancelledError:
        with contextlib.suppress(Exception):
            ctx.store.put_snapshot("seen_countries", ctx.rules.export_seen_countries())
        raise


async def _device_watch(ctx: AppContext) -> None:
    """Keep ctx.device fresh; notice connects / disconnects."""
    assert ctx.adb is not None
    was_connected: bool | None = None
    while True:
        try:
            if ctx.adb.serial is None:
                devs = await asyncio.to_thread(ctx.adb.devices)
                live = [d for d in devs if d["state"] == "device"]
                if live:
                    ctx.adb.serial = live[0]["serial"]
            info = await asyncio.to_thread(device_info, ctx.adb)
            ctx.device.clear()
            ctx.device.update(info)
            if info.get("connected") and ctx.maps:
                # keep the uid→package map fresh off the event loop
                await asyncio.to_thread(ctx.maps.ensure_uid_map)
            if was_connected is not None and was_connected != info.get("connected"):
                ctx.emit(Event(
                    kind="log.line",
                    severity=SEV_NOTICE,
                    title="device " + ("connected" if info.get("connected") else "disconnected"),
                    detail=info.get("model", ""),
                    data={"level": "I", "tag": "sentinel", "buffer": "sys"},
                ))
            was_connected = bool(info.get("connected"))
        except (AdbError, Exception) as e:  # noqa: BLE001 - keep watching regardless
            log.debug("device watch: %s", e)
        await asyncio.sleep(20)


def _collectors_for(ctx: AppContext) -> list:
    if ctx.cfg.demo:
        from ..collectors.demo import DemoCollector
        return [DemoCollector(ctx)]
    from ..collectors.capture import CaptureCollector
    from ..collectors.logcat import LogcatCollector
    from ..collectors.netstats import NetstatsCollector
    from ..collectors.network import NetworkCollector
    from ..collectors.packages import PackagesCollector
    from ..collectors.radio import RadioCollector
    from ..collectors.sensors import SensorsCollector
    from ..collectors.storage import StorageCollector
    from ..collectors.threats import ThreatsCollector
    return [
        LogcatCollector(ctx), SensorsCollector(ctx), NetworkCollector(ctx),
        CaptureCollector(ctx), NetstatsCollector(ctx), PackagesCollector(ctx),
        ThreatsCollector(ctx), RadioCollector(ctx), StorageCollector(ctx),
    ]


def create_app(cfg: Config) -> FastAPI:
    ctx = build_context(cfg)
    tasks: list[asyncio.Task] = []

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI):
        loop = asyncio.get_running_loop()
        ctx.bus.attach_loop(loop)
        tasks.append(asyncio.create_task(_event_pump(ctx), name="event-pump"))
        if not cfg.demo:
            tasks.append(asyncio.create_task(_device_watch(ctx), name="device-watch"))
        for c in _collectors_for(ctx):
            tasks.append(asyncio.create_task(c.run(), name=f"collector-{c.name}"))
        log.info("Android Sentinel v%s on http://%s:%d %s",
                 __version__, cfg.host, cfg.port, "(demo mode)" if cfg.demo else "")
        try:
            yield
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            ctx.geoip.close()
            ctx.store.close()

    app = FastAPI(title="Android Sentinel", version=__version__, lifespan=lifespan)
    app.state.ctx = ctx

    from ..service.backup import BackupService
    backup = BackupService(ctx)

    # This dashboard reads your whole device; it is local-only by design.
    # Host validation defeats DNS-rebinding (a remote page resolving its own
    # domain to 127.0.0.1 to reach the REST API with a non-local Host header).
    _local_hosts = {"127.0.0.1", "localhost", "::1"}
    if cfg.host not in ("0.0.0.0", "::"):
        _local_hosts.add(cfg.host)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(_local_hosts))

    def _origin_ok(origin: str | None) -> bool:
        """Browsers send Origin on WebSocket upgrades; a cross-site page gets
        rejected here (CSWSH). Non-browser clients send no Origin — allowed."""
        if not origin:
            return True
        try:
            return (urlparse(origin).hostname or "") in _local_hosts
        except ValueError:
            return False

    # ---------- REST ----------
    # handlers are plain `def`: FastAPI runs them in its threadpool, keeping
    # the (synchronous) sqlite reads off the event loop
    @app.get("/api/status")
    def status():
        s = ctx.state
        return {
            "version": __version__,
            "demo": s.get("demo", False),
            "device": ctx.device,
            "transport": s.get("transport"),
            "connections": s.get("connections", 0),
            "camera_active": s.get("camera_active", []),
            "capture": s.get("capture", False),
            "adb_wifi": s.get("adb_wifi", False),
            "telephony": s.get("telephony", {}),
            "godmode": s.get("godmode", {}),
            "user_cas": s.get("user_cas", []),
            "hostnames_cached": ctx.hostnames.size(),
            "open_alerts": len(ctx.store.alerts(state="open", limit=500)),
            "started": s.get("started"),
            "now": time.time(),
        }

    @app.get("/api/events")
    def events(prefix: str | None = None, kinds: str | None = None,
               since: float | None = None, limit: int = 200,
               app_filter: str | None = Query(default=None, alias="app")):
        kind_list = [k for k in (kinds or "").split(",") if k] or None
        return ctx.store.events(kinds=kind_list, prefix=prefix, app=app_filter,
                                since=since, limit=limit)

    @app.get("/api/alerts")
    def alerts(state: str | None = "open", limit: int = 100):
        return ctx.store.alerts(state=state if state != "all" else None, limit=limit)

    @app.post("/api/alerts/{alert_id}/state")
    def set_alert_state(alert_id: int, body: dict):
        ok = ctx.store.set_alert_state(alert_id, str(body.get("state", "")))
        return JSONResponse({"ok": ok}, status_code=200 if ok else 400)

    @app.get("/api/apps")
    def apps():
        inv = dict(ctx.state.get("apps") or {})
        god = ctx.state.get("godmode") or {}
        stats = ctx.state.get("netstats") or {}
        storage = (ctx.state.get("storage") or {}).get("apps") or {}
        uid_stats = {int(u): v for u, v in stats.items() if str(u).isdigit()}
        out = []
        for pkg, d in inv.items():
            uid = d.get("uid")
            st = uid_stats.get(uid, {}) if uid else {}
            godlist = sorted(a for a, pkgs in god.items() if pkg in pkgs)
            szd = storage.get(pkg, {})
            risk, factors = _risk_score(d, godlist, st)
            out.append({
                "package": pkg, **d,
                "godmode": godlist,
                "rx": st.get("rx", 0), "tx": st.get("tx", 0),
                "mtx": st.get("mtx", 0), "mrx": st.get("mrx", 0),
                "data_size": szd.get("data", 0), "cache_size": szd.get("cache", 0),
                "apk_size": szd.get("app", 0),
                "risk": risk, "risk_factors": factors,
            })
        out.sort(key=lambda a: (-a["risk"], -(a["tx"] or 0), a["package"]))
        return out

    @app.get("/api/netstats")
    def netstats():
        return ctx.state.get("netstats") or {}

    @app.get("/api/rules")
    def rules():
        return [{"id": r.id, "name": r.name, "severity": r.severity,
                 "description": r.description, "enabled": r.enabled}
                for r in ctx.rules.rules.values()]

    @app.post("/api/rules/{rule_id}")
    def toggle_rule(rule_id: str, body: dict):
        ok = ctx.rules.set_enabled(rule_id, bool(body.get("enabled", True)))
        if ok:
            ctx.store.put_snapshot("rules_enabled", ctx.rules.enabled_map())
        return JSONResponse({"ok": ok}, status_code=200 if ok else 404)

    # ---------- storage / files / backup (own-device) ----------
    @app.get("/api/storage")
    def storage():
        return ctx.state.get("storage") or {"apps": {}, "totals": {}}

    @app.get("/api/storage/app/{pkg}")
    async def storage_app(pkg: str):
        """On-demand deep look at where one app keeps its data and logs."""
        if ctx.adb is None:
            return {"demo": True, **_demo_app_storage(pkg)}
        return await asyncio.to_thread(_inspect_app_storage, ctx, pkg)

    @app.get("/api/files")
    async def files(path: str = "/sdcard"):
        if ctx.adb is None:
            return {"path": path, "demo": True, "entries": _demo_files(path)}
        return await asyncio.to_thread(_list_files, ctx, path)

    @app.post("/api/backup/{pkg}")
    async def start_backup(pkg: str, body: dict | None = None):
        if ctx.adb is None:
            return JSONResponse({"error": "backup needs a real device (not demo mode)"},
                                status_code=400)
        body = body or {}
        job = backup.new_job(pkg, {"apk": bool(body.get("apk", True)),
                                   "data": bool(body.get("data", True)),
                                   "external": bool(body.get("external", False))})
        asyncio.create_task(asyncio.to_thread(backup.run, job))
        return {"job": job["id"], "pkg": pkg, "state": job["state"]}

    @app.get("/api/backup/jobs")
    def backup_jobs():
        return sorted(backup.jobs.values(), key=lambda j: j["id"], reverse=True)

    @app.get("/api/backups")
    def backups():
        return backup.list_backups()

    @app.get("/api/export/evidence")
    def export_evidence(hours: float = 24.0):
        """Signed, timestamped local report for the last N hours."""
        return _export_evidence(ctx, hours)

    # ---------- WebSocket ----------
    @app.websocket("/ws")
    async def ws(sock: WebSocket):
        if not _origin_ok(sock.headers.get("origin")):
            await sock.close(code=4403)
            return
        await sock.accept()
        q = ctx.bus.subscribe()
        try:
            while True:
                ev = await q.get()
                await sock.send_text(ev.to_json())
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            ctx.bus.unsubscribe(q)

    # ---------- static ----------
    @app.get("/")
    async def index():
        return FileResponse(_STATIC / "index.html")

    app.mount("/static", StaticFiles(directory=_STATIC), name="static")
    return app
