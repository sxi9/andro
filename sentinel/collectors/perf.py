"""Device performance collector: memory, swap, CPU and the top processes.

Feeds ctx.state["perf"] with a cheap snapshot (meminfo + one `top` batch) so the
Performance tab can show what is eating RAM and whether the device is thrashing.
Kernel-log reads, memory-freeing and tunable writes are done on demand by the
service layer, not polled.
"""
from __future__ import annotations

import time

from ..parsers.perf import (parse_battery, parse_cores, parse_cpu_summary,
                            parse_meminfo, parse_thermal, parse_top)
from .base import Collector

# one shell read for every per-core cpufreq file
_CORES_CMD = (
    'for c in /sys/devices/system/cpu/cpu[0-9]*; do n=${c##*cpu}; '
    'echo "$n|$(cat $c/online 2>/dev/null || echo 1)|'
    '$(cat $c/cpufreq/scaling_cur_freq 2>/dev/null)|'
    '$(cat $c/cpufreq/scaling_min_freq 2>/dev/null)|'
    '$(cat $c/cpufreq/scaling_max_freq 2>/dev/null)|'
    '$(cat $c/cpufreq/scaling_governor 2>/dev/null)"; done'
)
_THERMAL_CMD = ('for z in /sys/class/thermal/thermal_zone*; do '
                'echo "$(cat $z/type 2>/dev/null)|$(cat $z/temp 2>/dev/null)"; done')


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
        # per-core, thermal and battery — best effort, never block the snapshot
        try:
            snap["cores"] = parse_cores(await adb.shell(_CORES_CMD, timeout=15))
        except Exception:  # noqa: BLE001
            snap["cores"] = []
        try:
            snap["thermal"] = parse_thermal(await adb.shell(_THERMAL_CMD, timeout=15))
        except Exception:  # noqa: BLE001
            snap["thermal"] = []
        try:
            snap["battery"] = parse_battery(await adb.shell("dumpsys battery", timeout=15))
        except Exception:  # noqa: BLE001
            snap["battery"] = {}
        self.ctx.state["perf"] = snap
