"""Device performance actions for the owner's own device.

On-demand reads (kernel log, tunables) and state-changing actions (free memory,
kill a process, set a tunable) that the Performance tab calls. Everything that
mutates runs over the device's own ADB, needs root for the kernel/VM bits, and
is validated here (no open shell, whitelisted tunables). All failures degrade to
an {ok: false, output} dict rather than raising to the route.
"""
from __future__ import annotations

import re

from ..adb.client import AdbError
from ..parsers.perf import parse_meminfo, parse_top, parse_cpu_summary

_PKG_RE = re.compile(r"^[A-Za-z0-9_.]+$")

# tunables the UI may write, with validation. key -> (sysfs/proc path glob, validator)
_SWAPPINESS = "/proc/sys/vm/swappiness"
_GOV_GLOB = "/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"


def snapshot(dctx) -> dict:
    """Fresh one-shot perf snapshot (used when state has none yet)."""
    adb = dctx.adb
    mem = parse_meminfo(adb.shell_sync("cat /proc/meminfo", timeout=15))
    top = adb.shell_sync("top -b -n1 -m 20 -s 5", timeout=20)
    return {"mem": mem, "cpu": parse_cpu_summary(top), "procs": parse_top(top, 20)}


def kernel_log(dctx, lines: int = 400) -> dict:
    """Recent kernel ring buffer (dmesg). Needs root on most devices; falls back
    to logcat's kernel buffer if dmesg is denied."""
    adb = dctx.adb
    lines = max(50, min(int(lines or 400), 2000))
    text = ""
    try:
        text = adb.shell_sync("dmesg", su=True, timeout=20)
    except AdbError:
        text = ""
    if not text.strip():
        try:
            text = adb.shell_sync(f"logcat -b kernel -d -t {lines}", timeout=20)
        except AdbError as e:
            return {"ok": False, "output": str(e), "lines": []}
    rows = [ln for ln in text.splitlines() if ln.strip()][-lines:]
    # flag the scary lines so the UI can colour them
    sev = re.compile(r"\b(SIGSEGV|SIGABRT|panic|oom|lowmemorykiller|out of memory|"
                     r"fatal|segfault|thermal|throttl|killing|watchdog)\b", re.I)
    out = [{"text": ln, "warn": bool(sev.search(ln))} for ln in rows]
    return {"ok": True, "lines": out, "count": len(out)}


def free_memory(dctx) -> dict:
    """"Fast phone": reclaim RAM without touching foreground apps. Kills cached
    background processes (am kill-all — the same thing Android does under
    pressure), drops the page cache and compacts memory (root). Returns before
    and after so the UI can show what was reclaimed."""
    adb = dctx.adb
    before = parse_meminfo(adb.shell_sync("cat /proc/meminfo", timeout=15))
    steps: list[str] = []
    try:
        adb.shell_sync("am kill-all", timeout=25)
        steps.append("killed background apps")
    except AdbError as e:
        steps.append(f"am kill-all failed: {e}")
    for cmd, label in (
        ("sync; echo 3 > /proc/sys/vm/drop_caches", "dropped page cache"),
        ("echo 1 > /proc/sys/vm/compact_memory", "compacted memory"),
    ):
        try:
            adb.shell_sync(cmd, su=True, timeout=20)
            steps.append(label)
        except AdbError as e:
            steps.append(f"{label} failed (root?): {e}")
    after = parse_meminfo(adb.shell_sync("cat /proc/meminfo", timeout=15))
    freed = after.get("mem_available", 0) - before.get("mem_available", 0)
    return {"ok": True, "freed": freed, "before": before, "after": after, "steps": steps}


def kill_process(dctx, *, pid: int | None = None, package: str | None = None) -> dict:
    """Stop one process by pid, or force-stop an app by package."""
    adb = dctx.adb
    if package:
        if not _PKG_RE.match(package):
            return {"ok": False, "output": "invalid package name"}
        try:
            adb.shell_sync(f"am force-stop {package}", timeout=20)
            return {"ok": True, "output": f"force-stopped {package}"}
        except AdbError as e:
            return {"ok": False, "output": str(e)}
    if pid is not None:
        try:
            p = int(pid)
        except (TypeError, ValueError):
            return {"ok": False, "output": "invalid pid"}
        if p <= 100:
            return {"ok": False, "output": "refusing to kill a system/low pid"}
        try:
            adb.shell_sync(f"kill {p}", su=True, timeout=15)
            return {"ok": True, "output": f"killed pid {p}"}
        except AdbError as e:
            return {"ok": False, "output": str(e)}
    return {"ok": False, "output": "pid or package required"}


def tunables(dctx) -> dict:
    """Read the kernel knobs the UI exposes: vm.swappiness, the CPU governor and
    its available choices, and zram usage."""
    adb = dctx.adb

    def _read(path: str, su: bool = False) -> str:
        try:
            return (adb.shell_sync(f"cat {path} 2>/dev/null", su=su, timeout=10) or "").strip()
        except AdbError:
            return ""

    swappiness = _read(_SWAPPINESS) or _read(_SWAPPINESS, su=True)
    gov = _read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    gov_avail = _read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors")
    zram = _read("/sys/block/zram0/mm_stat")
    return {
        "ok": True,
        "swappiness": int(swappiness) if swappiness.isdigit() else None,
        "governor": gov or None,
        "governors": gov_avail.split() if gov_avail else [],
        "zram_present": bool(zram),
    }


def set_tunable(dctx, key: str, value: str) -> dict:
    """Write one whitelisted kernel knob (root). Only swappiness and the CPU
    governor are writable, and both are validated against the device."""
    adb = dctx.adb
    key = str(key or "")
    value = str(value or "").strip()
    if key == "swappiness":
        if not value.isdigit() or not (0 <= int(value) <= 200):
            return {"ok": False, "output": "swappiness must be 0-200"}
        try:
            adb.shell_sync(f"echo {int(value)} > {_SWAPPINESS}", su=True, timeout=15)
            return {"ok": True, "output": f"swappiness = {int(value)}"}
        except AdbError as e:
            return {"ok": False, "output": str(e)}
    if key == "governor":
        avail = tunables(dctx).get("governors", [])
        if value not in avail:
            return {"ok": False, "output": f"governor must be one of: {', '.join(avail) or 'n/a'}"}
        try:
            # apply to every online CPU
            adb.shell_sync(
                "for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do "
                f"echo {value} > $f; done", su=True, timeout=20)
            return {"ok": True, "output": f"governor = {value}"}
        except AdbError as e:
            return {"ok": False, "output": str(e)}
    return {"ok": False, "output": f"unknown or read-only tunable: {key}"}
