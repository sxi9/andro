"""Parse `dumpsys media.camera` for live camera clients (who holds the camera NOW)."""
from __future__ import annotations

import re

_CLIENT = re.compile(r"[Cc]lient package(?: name)?[:=]?\s*([A-Za-z0-9_.]+)")
_OPEN = re.compile(r"[Dd]evice\s+\S+\s+is\s+open|CameraService.*active|is open\.", re.I)


def parse_camera_clients(text: str) -> set[str]:
    """Returns package names with an open camera device. Empty set = camera idle."""
    if not text:
        return set()
    # Only trust client-package mentions when the dump says a device is open;
    # closed-session history also lists packages on some builds.
    if not _OPEN.search(text):
        return set()
    return {m.group(1) for m in _CLIENT.finditer(text)
            if m.group(1) not in ("android", "null")}
