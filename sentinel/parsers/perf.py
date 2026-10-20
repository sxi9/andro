"""Parsers for device performance: /proc/meminfo, `top`, and loadavg.

Pure string -> dict transforms, no adb. Used by the perf collector to turn
cheap shell reads into the structured state the Performance tab renders.
"""
from __future__ import annotations

import re


def parse_meminfo(text: str) -> dict:
    """/proc/meminfo -> bytes. Keys are the lowercase field names; values bytes."""
    out: dict[str, int] = {}
    for line in (text or "").splitlines():
        m = re.match(r"^(\w+):\s+(\d+)\s*kB", line.strip())
        if m:
            out[m.group(1).lower()] = int(m.group(2)) * 1024
    total = out.get("memtotal", 0)
    avail = out.get("memavailable", out.get("memfree", 0))
    swap_total = out.get("swaptotal", 0)
    swap_free = out.get("swapfree", 0)
    used = max(total - avail, 0)
    return {
        "mem_total": total,
        "mem_free": out.get("memfree", 0),
        "mem_available": avail,
        "mem_used": used,
        "mem_used_pct": round(used / total * 100, 1) if total else 0.0,
        "cached": out.get("cached", 0),
        "swap_total": swap_total,
        "swap_free": swap_free,
        "swap_used": max(swap_total - swap_free, 0),
        "swap_used_pct": round((swap_total - swap_free) / swap_total * 100, 1) if swap_total else 0.0,
    }


# toybox `top -b -n1 -m N -s COL` columns:
# PID USER PR NI VIRT RES SHR S %CPU %MEM TIME+ ARGS
_TOP_ROW = re.compile(
    r"^\s*(\d+)\s+(\S+)\s+\S+\s+\S+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S)\s+([\d.]+)\s+([\d.]+)\s+(\S+)\s+(.+?)\s*$"
)


def _to_bytes(tok: str) -> int:
    """Turn toybox sizes like 326M, 1.2G, 92K, 10240 into bytes."""
    tok = (tok or "").strip()
    m = re.match(r"^([\d.]+)\s*([KMGT]?)$", tok)
    if not m:
        return 0
    val = float(m.group(1))
    mult = {"": 1024, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}[m.group(2)]
    # toybox RES with no suffix is in KB
    if m.group(2) == "":
        mult = 1024
    return int(val * mult)


def parse_top(text: str, limit: int = 20) -> list[dict]:
    """`top -b -n1` -> list of process dicts sorted by RES (memory) desc."""
    rows: list[dict] = []
    for line in (text or "").splitlines():
        m = _TOP_ROW.match(line)
        if not m:
            continue
        name = m.group(10).strip()
        if name in ("ARGS", "COMMAND") or m.group(1) == "PID":
            continue
        rows.append({
            "pid": int(m.group(1)),
            "user": m.group(2),
            "res": _to_bytes(m.group(4)),
            "state": m.group(6),
            "cpu": float(m.group(7)),
            "mem_pct": float(m.group(8)),
            "name": name,
        })
    rows.sort(key=lambda r: r["res"], reverse=True)
    return rows[:limit]


def parse_cpu_summary(text: str) -> dict:
    """Pull the toybox top header '... %cpu  22%user ... 327%iow ... 133%idle'."""
    out: dict[str, float] = {}
    m = re.search(r"(\d+)%cpu", text or "")
    if m:
        out["cpu_total"] = float(m.group(1))
    for key in ("user", "sys", "idle", "iow", "irq", "sirq", "nice"):
        mm = re.search(r"([\d.]+)%" + key + r"\b", text or "")
        if mm:
            out[key] = float(mm.group(1))
    return out
