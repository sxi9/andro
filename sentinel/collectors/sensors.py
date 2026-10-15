"""Mic / camera / location / clipboard access via appops + live camera clients.

Polls `dumpsys appops` (filtered per-op where the build supports it) and
`dumpsys media.camera`. There is no push channel for sensor access over ADB,
so near-real-time means a short poll; the appops relative timestamps let us
emit each access exactly once.
"""
from __future__ import annotations

import time

from ..core.events import Event, SEV_INFO, SEV_NOTICE, SEV_WARN
from ..parsers.appops import parse_appops
from ..parsers.camera import parse_camera_clients
from .base import Collector

WATCHED_OPS = {
    "RECORD_AUDIO": ("sensor.mic", "microphone"),
    "CAMERA": ("sensor.cam", "camera"),
    "FINE_LOCATION": ("sensor.loc", "location"),
    "COARSE_LOCATION": ("sensor.loc", "location"),
    "READ_CLIPBOARD": ("sensor.clip", "clipboard"),
}
# how far back we accept an access as "new" on the very first poll
_FRESH_WINDOW = 30.0


class SensorsCollector(Collector):
    name = "sensors"

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self._last_abs: dict[tuple[str, str], float] = {}  # (pkg, op) -> newest abs ts seen
        self._filtered_ok: bool | None = None               # does --op filtering work here?
        self._cam_active: set[str] = set()
        self._pkg2uid: dict[str, int] = {}
        self._first_poll = True

    async def run(self) -> None:
        await self.poll_loop(self.ctx.cfg.poll_sensors, self._poll)

    async def _dump_appops(self) -> str:
        adb = self.ctx.adb
        assert adb is not None
        if self._filtered_ok is None or self._filtered_ok:
            chunks = []
            ok = True
            for op in ("RECORD_AUDIO", "CAMERA", "FINE_LOCATION", "COARSE_LOCATION",
                       "READ_CLIPBOARD"):
                out = await adb.shell(f"dumpsys appops --op {op}", timeout=15)
                if "Unknown option" in out or "usage:" in out.lower()[:200]:
                    ok = False
                    break
                chunks.append(out)
            if ok:
                self._filtered_ok = True
                return "\n".join(chunks)
            self._filtered_ok = False
            self.log.info("per-op appops filter unsupported; using full dump")
        return await adb.shell("dumpsys appops", timeout=30)

    async def _poll(self) -> None:
        adb = self.ctx.adb
        assert adb is not None
        now = time.time()

        # ---- appops accesses ----
        text = await self._dump_appops()
        accesses = parse_appops(text, ops=set(WATCHED_OPS))
        if self.ctx.maps:
            # rebuilt each poll from the cached map (pure dict work) so newly
            # installed apps attribute correctly; the device watcher refreshes
            # the underlying map off the event loop
            self._pkg2uid = {p: u for u, p in self.ctx.maps.all_packages().items()}
        fresh_cut = _FRESH_WINDOW if self._first_poll else self.ctx.cfg.poll_sensors * 4
        for a in accesses:
            abs_ts = now - a.ago
            key = (a.package, a.op)
            if a.ago > fresh_cut:
                # old access: just record the baseline so later polls diff correctly
                if abs_ts > self._last_abs.get(key, 0):
                    self._last_abs[key] = abs_ts
                continue
            if abs_ts <= self._last_abs.get(key, 0) + 0.5:
                continue  # already reported
            self._last_abs[key] = abs_ts
            kind, label = WATCHED_OPS[a.op]
            where = "background" if a.background else "foreground"
            sev = SEV_WARN if (a.background and kind in ("sensor.mic", "sensor.cam")) else (
                SEV_NOTICE if a.background else SEV_INFO)
            verb = "was denied" if a.rejected else "used"
            self.ctx.emit(Event(
                kind=kind, severity=sev,
                title=f"{a.package} {verb} {label}",
                detail=f"{where}"
                       + (f", {a.duration:.0f}s" if a.duration else "")
                       + (f" [{a.uid_state}]" if a.uid_state else ""),
                app=a.package, uid=self._pkg2uid.get(a.package),
                data={"op": a.op, "background": a.background, "rejected": a.rejected,
                      "duration": a.duration, "source": "appops"},
                ts=abs_ts,
            ))
        self._first_poll = False

        # ---- live camera clients ----
        cam_text = await adb.shell("dumpsys media.camera", timeout=15)
        active = parse_camera_clients(cam_text)
        for pkg in active - self._cam_active:
            self.ctx.emit(Event(
                kind="sensor.cam", severity=SEV_NOTICE,
                title=f"{pkg} opened the camera",
                detail="camera device open (live)",
                app=pkg, uid=self._pkg2uid.get(pkg),
                data={"op": "CAMERA", "background": False, "live": True,
                      "source": "camera_service"},
            ))
        self._cam_active = active
        self.ctx.state["camera_active"] = sorted(active)
