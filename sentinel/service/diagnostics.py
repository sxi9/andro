"""Diagnostics & benchmarks for the owner's own device: quick CPU and storage
benchmarks, per-app FPS / jank from `dumpsys gfxinfo`, and a one-shot log capture
(logcat + dmesg + key state) the operator can download. All over the device's
own ADB; benchmarks need no root, log capture uses root where available.
"""
from __future__ import annotations

import re
import time

from ..adb.client import AdbError

_PKG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.]{1,254}\Z")


def cpu_bench(dctx) -> dict:
    """Rough CPU score: time a fixed md5sum over zeros (pure compute, no I/O).
    Higher MB/s = faster. Indicative, not a lab benchmark."""
    adb = dctx.adb
    mb = 256
    t0 = time.time()
    try:
        adb.shell_sync(f"dd if=/dev/zero bs=1m count={mb} 2>/dev/null | md5sum", timeout=90)
    except AdbError as e:
        return {"ok": False, "output": str(e)}
    dt = time.time() - t0
    return {"ok": True, "metric": "cpu_hash", "mb": mb,
            "seconds": round(dt, 2), "mb_per_s": round(mb / dt, 1) if dt else None,
            "output": f"hashed {mb} MB in {dt:.2f}s ({mb/dt:.0f} MB/s)"}


def storage_bench(dctx) -> dict:
    """Sequential write + read throughput with dd to a temp file on /data."""
    adb = dctx.adb
    f = "/data/local/tmp/.sentinel_bench.bin"
    mb = 256
    try:
        t0 = time.time()
        adb.shell_sync(f"dd if=/dev/zero of={f} bs=1m count={mb} conv=fsync 2>/dev/null", timeout=120)
        wt = time.time() - t0
        adb.shell_sync("sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true", su=True, timeout=15)
        t0 = time.time()
        adb.shell_sync(f"dd if={f} of=/dev/null bs=1m 2>/dev/null", timeout=120)
        rt = time.time() - t0
        adb.shell_sync(f"rm -f {f}", timeout=15)
    except AdbError as e:
        return {"ok": False, "output": str(e)}
    return {"ok": True, "mb": mb,
            "write_mb_s": round(mb / wt, 1) if wt else None,
            "read_mb_s": round(mb / rt, 1) if rt else None,
            "output": f"write {mb/wt:.0f} MB/s · read {mb/rt:.0f} MB/s"}


def _foreground_pkg(adb) -> str | None:
    try:
        out = adb.shell_sync("dumpsys activity activities | grep -m1 topResumedActivity", timeout=12) or ""
    except AdbError:
        return ""
    m = re.search(r"\s([A-Za-z0-9_.]+)/", out)
    return m.group(1) if m else None


def gfxinfo(dctx, package: str | None = None) -> dict:
    """Frame stats for an app from `dumpsys gfxinfo` — total frames, jank %, and
    the 50/90/95/99th percentile frame times. Defaults to the foreground app."""
    adb = dctx.adb
    pkg = package or _foreground_pkg(adb)
    if not pkg or not _PKG_RE.match(pkg):
        return {"ok": False, "output": "no valid foreground app"}
    try:
        out = adb.shell_sync(f"dumpsys gfxinfo {pkg}", timeout=15) or ""
    except AdbError as e:
        return {"ok": False, "output": str(e)}
    def _n(rx, cast=int):
        m = re.search(rx, out)
        return cast(m.group(1)) if m else None
    total = _n(r"Total frames rendered:\s*(\d+)")
    janky = _n(r"Janky frames:\s*(\d+)")
    jankpct = _n(r"Janky frames:\s*\d+\s*\(([\d.]+)%\)", float)
    pct = {p: _n(rf"{p}th percentile:\s*(\d+)ms") for p in (50, 90, 95, 99)}
    if total is None:
        return {"ok": False, "output": f"{pkg}: no frame data (open/use the app first)"}
    return {"ok": True, "package": pkg, "total_frames": total, "janky_frames": janky,
            "jank_pct": jankpct, "percentiles_ms": pct,
            "output": f"{pkg}: {total} frames, {jankpct}% janky"}


def capture_logs(dctx) -> dict:
    """Grab logcat + dmesg + key state into one file under the data dir and
    return its path for the route to serve as a download."""
    import os
    adb = dctx.adb
    hub = getattr(dctx, "hub", None)
    data_dir = getattr(getattr(hub, "cfg", None), "data_dir", None) or os.path.expanduser("~/.android-sentinel")
    out_dir = os.path.join(data_dir, "logs")
    os.makedirs(out_dir, exist_ok=True)
    name = time.strftime("sentinel-logs-%Y%m%d-%H%M%S.txt")
    path = os.path.join(out_dir, name)
    parts = []
    for title, cmd, su in (
        ("== getprop ==", "getprop", False),
        ("== dmesg ==", "dmesg", True),
        ("== logcat (last 2000) ==", "logcat -d -t 2000", False),
    ):
        try:
            parts.append(title + "\n" + (adb.shell_sync(cmd, su=su, timeout=40) or ""))
        except AdbError as e:
            parts.append(f"{title}\n(failed: {e})")
    try:
        with open(path, "w", encoding="utf-8", errors="replace") as fh:
            fh.write("\n\n".join(parts))
    except OSError as e:
        return {"ok": False, "output": str(e)}
    return {"ok": True, "path": path, "name": name,
            "size": os.path.getsize(path), "output": f"captured {os.path.getsize(path)//1024} KB"}
