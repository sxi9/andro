"""Stream logcat (main/system/crash/events buffers) and attribute lines to apps."""
from __future__ import annotations

import asyncio
import time

from ..core.events import Event, SEV_INFO, SEV_NOTICE, SEV_WARN
from .base import Collector

_LEVEL_SEV = {"W": SEV_NOTICE, "E": SEV_WARN, "F": SEV_WARN}
_KEEP_LEVELS = {"I", "W", "E", "F"}  # V/D are too chatty to ship across the bus


class LogcatCollector(Collector):
    name = "logcat"

    async def run(self) -> None:
        from ..parsers.logcat import parse_line
        assert self.ctx.adb is not None
        backoff = 2.0
        while True:
            try:
                proc = self.ctx.adb.popen_lines("logcat -b main,system,crash,events -v threadtime -T 1")
            except Exception as e:
                self.log.warning("logcat start failed: %s", e)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60)
                continue
            backoff = 2.0
            self.log.info("logcat stream attached")
            try:
                await asyncio.to_thread(self._pump, proc, parse_line)
            finally:
                try:
                    proc.kill()
                except Exception:
                    pass
            self.log.warning("logcat stream ended; reattaching")
            await asyncio.sleep(2.0)

    def _pump(self, proc, parse_line) -> None:
        assert proc.stdout is not None
        for raw in proc.stdout:
            ln = parse_line(raw)
            if ln is None or ln.level not in _KEEP_LEVELS:
                continue
            uid, pkg = (None, None)
            if self.ctx.maps:
                uid, pkg = self.ctx.maps.proc_for_pid(ln.pid)
                if pkg is None and uid is not None:
                    pkg = self.ctx.maps.app_for_uid(uid)
            self.ctx.emit_threadsafe(Event(
                kind="log.line",
                severity=_LEVEL_SEV.get(ln.level, SEV_INFO),
                title=f"{ln.tag}",
                detail=ln.msg[:500],
                app=pkg,
                uid=uid,
                data={"level": ln.level, "tag": ln.tag, "pid": ln.pid,
                      "buffer": "sys", "t": ln.time},
                ts=time.time(),
            ))
