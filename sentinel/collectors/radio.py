"""Cellular / telephony layer: call state, serving cell, network type, and the
radio logcat buffer.

What this can see: call and SMS *events*, the cell tower identity, and the
radio access technology (the 2G-downgrade IMSI-catcher tell). What it cannot
see: the content of calls — VoLTE media is carrier-encrypted and never
exposed. Deeper baseband inspection (silent-SMS detection) needs a
Qualcomm diag reader like SnoopSnitch and is out of scope here.
"""
from __future__ import annotations

import asyncio
import time

from ..core.events import Event, SEV_INFO, SEV_NOTICE, SEV_WARN
from ..parsers.logcat import parse_line
from ..parsers.telephony import parse_telephony_registry
from .base import Collector

_KEEP_LEVELS = {"I", "W", "E", "F"}


class RadioCollector(Collector):
    name = "radio"

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self._last: dict = {}

    async def run(self) -> None:
        await asyncio.gather(
            self.poll_loop(self.ctx.cfg.poll_radio, self._poll_registry),
            self._stream_radio_log(),
        )

    # ---- telephony registry poll ----
    async def _poll_registry(self) -> None:
        adb = self.ctx.adb
        assert adb is not None
        text = await adb.shell("dumpsys telephony.registry", timeout=20)
        cur = parse_telephony_registry(text)
        self.ctx.state["telephony"] = cur
        last = self._last
        self._last = cur

        if last.get("call_state") is not None and cur["call_state"] != last.get("call_state"):
            self.ctx.emit(Event(
                kind="radio.call", severity=SEV_NOTICE,
                title=f"Call state: {cur['call_state']}",
                detail=f"was {last.get('call_state')}",
                data={"state": cur["call_state"]},
            ))
        if cur.get("network_type") and cur["network_type"] != last.get("network_type"):
            self.ctx.emit(Event(
                kind="radio.cell", severity=SEV_INFO,
                title=f"Network type: {cur['network_type']}",
                detail=f"operator: {cur.get('operator') or '?'}",
                data={"network_type": cur["network_type"], "cell": cur.get("cell")},
            ))
        lc, cc = last.get("cell") or {}, cur.get("cell") or {}
        if cc and lc and (cc.get("ci") != lc.get("ci") or cc.get("tac") != lc.get("tac")):
            self.ctx.emit(Event(
                kind="radio.cell", severity=SEV_INFO,
                title="Serving cell changed",
                detail=f"ci {lc.get('ci')} → {cc.get('ci')}, tac {lc.get('tac')} → {cc.get('tac')}",
                data={"network_type": cur.get("network_type"), "cell": cc},
            ))

    # ---- radio log buffer ----
    async def _stream_radio_log(self) -> None:
        adb = self.ctx.adb
        assert adb is not None
        backoff = 2.0
        while True:
            started = time.time()
            try:
                proc = adb.popen_lines("logcat -b radio -v threadtime -T 1")
                try:
                    await asyncio.to_thread(self._pump, proc)
                finally:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            except Exception as e:
                self.log.warning("radio logcat failed: %s", e)
            backoff = 2.0 if time.time() - started > 30 else min(backoff * 2, 60)
            await asyncio.sleep(backoff)

    def _pump(self, proc) -> None:
        assert proc.stdout is not None
        for raw in proc.stdout:
            ln = parse_line(raw)
            if ln is None or ln.level not in _KEEP_LEVELS:
                continue
            self.ctx.emit_threadsafe(Event(
                kind="log.line",
                severity=SEV_WARN if ln.level in ("E", "F") else SEV_INFO,
                title=ln.tag, detail=ln.msg[:500],
                data={"level": ln.level, "tag": ln.tag, "pid": ln.pid,
                      "buffer": "radio", "t": ln.time},
                ts=time.time(),
            ))
