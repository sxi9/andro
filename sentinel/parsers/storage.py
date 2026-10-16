"""Parsers for filesystem listing, directory sizes and the diskstats overview."""
from __future__ import annotations

import re
from dataclasses import dataclass

# toybox `ls -la`:  drwxrwx--x 4 u0_a155 u0_a155 4096 2026-10-01 10:00 cache
# tolerate a trailing '+'/'.' on the mode (ACL / SELinux), seconds, and a tz.
_LS = re.compile(
    r"^([bcdlps-][rwxsStT.+-]{9,10})\s+\d+\s+\S+\s+\S+\s+(\d+)\s+"
    r"(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?)(?:\s+[+-]\d{4})?\s+(.*)$"
)
_KIND = {"d": "dir", "l": "link", "-": "file"}


@dataclass
class FileEntry:
    name: str
    kind: str          # dir | file | link | other
    size: int
    perms: str
    mtime: str
    target: str | None = None

    def to_dict(self) -> dict:
        return {"name": self.name, "kind": self.kind, "size": self.size,
                "perms": self.perms, "mtime": self.mtime, "target": self.target}


def parse_ls_la(text: str) -> list[FileEntry]:
    out: list[FileEntry] = []
    for line in text.splitlines():
        line = line.rstrip("\n")
        if not line or line.startswith("total "):
            continue
        m = _LS.match(line)
        if not m:
            continue
        perms, size, date, tm, name = m.groups()
        kind = _KIND.get(perms[0], "other")
        target = None
        if kind == "link" and " -> " in name:
            name, target = name.split(" -> ", 1)
        if name in (".", ".."):
            continue
        out.append(FileEntry(name=name, kind=kind, size=int(size),
                             perms=perms, mtime=f"{date} {tm}", target=target))
    # directories first, then by name
    out.sort(key=lambda e: (e.kind != "dir", e.name.lower()))
    return out


def parse_du_k(text: str) -> dict[str, int]:
    """`du -sk` output -> {path: bytes}."""
    out: dict[str, int] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t", 1) if "\t" in line else line.split(None, 1)
        if len(parts) != 2:
            continue
        kb, path = parts
        try:
            out[path.strip()] = int(kb.strip()) * 1024
        except ValueError:
            continue
    return out


def _arr(text: str, label: str) -> list[str]:
    m = re.search(re.escape(label) + r":\s*\[([^\]]*)\]", text)
    if not m:
        return []
    raw = m.group(1).strip()
    return [x.strip() for x in raw.split(",")] if raw else []


def parse_diskstats(text: str) -> dict:
    """`dumpsys diskstats` -> {apps: {pkg: {app,data,cache}}, totals: {...}}.

    Gives per-app code/data/cache sizes in one cheap call, no `du` needed.
    """
    names = _arr(text, "Package Names")
    app = _arr(text, "App Sizes")
    data = _arr(text, "App Data Sizes")
    cache = _arr(text, "Cache Sizes")

    def gi(a: list[str], i: int) -> int:
        try:
            return int(a[i])
        except (IndexError, ValueError):
            return 0

    apps: dict[str, dict] = {}
    for i, n in enumerate(names):
        apps[n] = {"app": gi(app, i), "data": gi(data, i), "cache": gi(cache, i)}

    totals: dict[str, int] = {}
    for key, label in (("data_free", "Data-Free"), ("cache_free", "Cache-Free"),
                       ("system_free", "System-Free")):
        m = re.search(re.escape(label) + r":\s*(\d+)K", text)
        if m:
            totals[key] = int(m.group(1)) * 1024
    return {"apps": apps, "totals": totals}
