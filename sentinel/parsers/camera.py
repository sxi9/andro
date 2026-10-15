"""Parse `dumpsys media.camera` for live camera clients (who holds the camera NOW).

The dump also lists CLOSED sessions' client packages on some builds, so client
matching is scoped to the section of a device that is currently open: we walk
lines, tracking open/closed state per device section, and only collect client
packages while inside an open section.
"""
from __future__ import annotations

import re

_CLIENT = re.compile(r"[Cc]lient package(?: name)?[:=]?\s*([A-Za-z0-9_.]+)")
_OPEN = re.compile(r"[Dd]evice\s+\S+\s+is\s+open", re.I)
_CLOSED = re.compile(r"[Dd]evice\s+\S+\s+is\s+closed", re.I)


def parse_camera_clients(text: str) -> set[str]:
    """Returns package names with an open camera device. Empty set = camera idle."""
    out: set[str] = set()
    open_ctx = False
    for line in (text or "").splitlines():
        if _CLOSED.search(line):
            open_ctx = False
            continue
        if _OPEN.search(line):
            open_ctx = True
        if open_ctx:
            m = _CLIENT.search(line)
            if m and m.group(1) not in ("android", "null"):
                out.add(m.group(1))
    return out
