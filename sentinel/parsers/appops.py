"""Parse `dumpsys appops` — who used mic / camera / location / clipboard, when,
and whether the app was in the background.

Handles both output generations:

Android 10+ (per-access lines with the uid-state in brackets):
    Uid u0a155:
      Package com.whatsapp:
        RECORD_AUDIO (allow):
          Access: [fgsvc-s] 2026-10-15 18:40:01.123 (-5m3s211ms) duration=+4s211ms
          Reject: [cch-s]  2026-10-15 18:41:09.000 (-4m)

Android 9 and older (single summary line per op):
      Package com.whatsapp:
        RECORD_AUDIO: mode=allow; time=+2m3s411ms ago; duration=+5s

Background = uid state bg* or cch* (cached). The relative "(-5m3s)" is the
age of the access at dump time.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_PKG = re.compile(r"^\s*Package ([A-Za-z0-9_.]+):")
_OP_NEW = re.compile(r"^\s*([A-Z][A-Z0-9_]+)\s*\(([a-z]+)[^)]*\):\s*$")
_ACCESS = re.compile(
    r"^\s*(Access|Reject):\s*\[([a-z]+)(?:-[a-z]+)?\]\s*"
    r"[\d\-]+\s[\d:.]+\s*\(-([^)]+)\)"
    r"(?:.*?duration=\+?([\w.]+))?"
)
_OP_OLD = re.compile(
    r"^\s*([A-Z][A-Z0-9_]+):\s*mode=([a-z]+);.*?time=\+?([\w.]+) ago"
    r"(?:;.*?duration=\+?([\w.]+))?"
)

_DUR = re.compile(r"(\d+)(ms|d|h|m|s)")
_BG_STATES = ("bg", "cch")


def parse_duration(tok: str | None) -> float | None:
    """'5m3s211ms' → seconds. Returns None for empty/unparsable."""
    if not tok:
        return None
    total = 0.0
    found = False
    for num, unit in _DUR.findall(tok):
        found = True
        n = int(num)
        total += {"d": 86400, "h": 3600, "m": 60, "s": 1, "ms": 0.001}[unit] * n
    return total if found else None


@dataclass
class OpAccess:
    package: str
    op: str
    ago: float            # seconds before the dump was taken
    background: bool
    rejected: bool        # True when the OS blocked the attempt
    duration: float | None
    uid_state: str | None = None


def parse_appops(text: str, ops: set[str] | None = None) -> list[OpAccess]:
    out: list[OpAccess] = []
    pkg: str | None = None
    op: str | None = None
    for line in text.splitlines():
        m = _PKG.match(line)
        if m:
            pkg, op = m.group(1), None
            continue
        if pkg is None:
            continue
        m = _OP_NEW.match(line)
        if m:
            op = m.group(1)
            continue
        m = _ACCESS.match(line)
        if m and op and (ops is None or op in ops):
            ago = parse_duration(m.group(3))
            if ago is None:
                continue
            state = m.group(2)
            out.append(OpAccess(
                package=pkg, op=op, ago=ago,
                background=state.startswith(_BG_STATES),
                rejected=m.group(1) == "Reject",
                duration=parse_duration(m.group(4)),
                uid_state=state,
            ))
            continue
        m = _OP_OLD.match(line)
        if m and (ops is None or m.group(1) in ops):
            ago = parse_duration(m.group(3))
            if ago is None:
                continue
            out.append(OpAccess(
                package=pkg, op=m.group(1), ago=ago,
                background=False,  # pre-10 dumps don't carry uid state
                rejected=False,
                duration=parse_duration(m.group(4)),
            ))
    return out
