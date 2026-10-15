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
    from ..collectors.threats import ThreatsCollector
    return [
        LogcatCollector(ctx), SensorsCollector(ctx), NetworkCollector(ctx),
        CaptureCollector(ctx), NetstatsCollector(ctx), PackagesCollector(ctx),
        ThreatsCollector(ctx), RadioCollector(ctx),
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
        uid_stats = {int(u): v for u, v in stats.items() if str(u).isdigit()}
        out = []
        for pkg, d in inv.items():
            uid = d.get("uid")
            st = uid_stats.get(uid, {}) if uid else {}
            out.append({
                "package": pkg, **d,
                "godmode": sorted(a for a, pkgs in god.items() if pkg in pkgs),
                "rx": st.get("rx", 0), "tx": st.get("tx", 0),
                "mtx": st.get("mtx", 0), "mrx": st.get("mrx", 0),
            })
        out.sort(key=lambda a: (-(len(a["godmode"]) > 0), -(a["tx"] or 0), a["package"]))
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
