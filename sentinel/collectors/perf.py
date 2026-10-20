"""Device performance collector: memory, swap, CPU and the top processes.

Feeds ctx.state["perf"] with a cheap snapshot (meminfo + one `top` batch) so the
Performance tab can show what is eating RAM and whether the device is thrashing.
Kernel-log reads, memory-freeing and tunable writes are done on demand by the
service layer, not polled.
"""
from __future__ import annotations

import time

from ..parsers.perf import parse_cpu_summary, parse_meminfo, parse_top
from .base import Collector


class PerfCollector(Collector):
    name = "perf"

    async def run(self) -> None:
        await self.poll_loop(6.0, self._poll)

    async def _poll(self) -> None:
        adb = self.ctx.adb
        assert adb is not None
        meminfo = await adb.shell("cat /proc/meminfo", timeout=15)
        mem = parse_meminfo(meminfo)
        top = await adb.shell("top -b -n1 -m 20 -s 5", timeout=20)
        procs = parse_top(top, limit=20)
        cpu = parse_cpu_summary(top)
        loadavg = (await adb.shell("cat /proc/loadavg", timeout=10) or "").strip()
        snap = {
            "ts": time.time(),
            "mem": mem,
            "cpu": cpu,
            "loadavg": loadavg.split()[:3] if loadavg else [],
            "procs": procs,
        }
        self.ctx.state["perf"] = snap
