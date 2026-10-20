"""Per-app firewall for the owner's own device: block an app's Wi-Fi and/or
mobile-data egress with iptables owner-match (AFWall-style), in a dedicated
`sentinel_fw` chain so it never touches the system's own rules. Needs root.
Not persistent across reboot by itself (pair with a service.d script later).
"""
from __future__ import annotations

import re

from ..adb.client import AdbError

_CHAIN = "sentinel_fw"
_WIFI = "wlan+"
_DATA = "rmnet+"       # mobile data (Qualcomm rmnet); ccmni+ handled too
_DATA2 = "ccmni+"
_PKG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.]{1,254}\Z")


def _uid(adb, pkg: str) -> int | None:
    try:
        out = adb.shell_sync(f"cmd package list packages -U {pkg}", timeout=12) or ""
    except AdbError:
        out = ""
    m = re.search(r"\b" + re.escape(pkg) + r"\s+uid:(\d+)", out)
    if m:
        return int(m.group(1))
    # fallback: owner uid of the data dir
    try:
        out = adb.shell_sync(f"stat -c %u /data/data/{pkg} 2>/dev/null", su=True, timeout=10)
        return int(out.strip()) if out.strip().isdigit() else None
    except (AdbError, ValueError):
        return None


def _ensure_chain(adb) -> None:
    for cmd in (
        f"iptables -N {_CHAIN} 2>/dev/null || true",
        f"iptables -C OUTPUT -j {_CHAIN} 2>/dev/null || iptables -I OUTPUT -j {_CHAIN}",
        f"ip6tables -N {_CHAIN} 2>/dev/null || true",
        f"ip6tables -C OUTPUT -j {_CHAIN} 2>/dev/null || ip6tables -I OUTPUT -j {_CHAIN}",
    ):
        try:
            adb.shell_sync(cmd, su=True, timeout=12)
        except AdbError:
            pass


def _rule(uid: int, iface: str) -> str:
    return f"{_CHAIN} -m owner --uid-owner {uid} -o {iface} -j REJECT"


def set_app(dctx, package: str, block_wifi: bool, block_data: bool) -> dict:
    """Set the Wi-Fi / mobile-data block state for one app."""
    if not _PKG_RE.match(package or ""):
        return {"ok": False, "output": "invalid package name"}
    adb = dctx.adb
    uid = _uid(adb, package)
    if uid is None:
        return {"ok": False, "output": "could not resolve app uid"}
    _ensure_chain(adb)
    plan = [(_WIFI, block_wifi), (_DATA, block_data), (_DATA2, block_data)]
    for iface, block in plan:
        for ipt in ("iptables", "ip6tables"):
            # delete any existing copy first (idempotent), then add if blocking
            try:
                adb.shell_sync(f"{ipt} -D {_rule(uid, iface)} 2>/dev/null || true", su=True, timeout=10)
            except AdbError:
                pass
            if block:
                try:
                    adb.shell_sync(f"{ipt} -A {_rule(uid, iface)}", su=True, timeout=10)
                except AdbError as e:
                    return {"ok": False, "output": str(e)}
    return {"ok": True, "uid": uid, "package": package,
            "wifi_blocked": bool(block_wifi), "data_blocked": bool(block_data),
            "output": f"{package}: wifi {'blocked' if block_wifi else 'allowed'}, "
                      f"data {'blocked' if block_data else 'allowed'}"}


def status(dctx) -> dict:
    """Current blocks, as {uid: {wifi, data}}, from the sentinel_fw chain."""
    adb = dctx.adb
    try:
        dump = adb.shell_sync(f"iptables -S {_CHAIN} 2>/dev/null", su=True, timeout=12) or ""
    except AdbError:
        return {"blocks": []}
    by_uid: dict[int, dict] = {}
    for line in dump.splitlines():
        m = re.search(r"--uid-owner (\d+).*-o (\S+).*-j REJECT", line)
        if not m:
            continue
        uid = int(m.group(1))
        iface = m.group(2)
        row = by_uid.setdefault(uid, {"uid": uid, "wifi": False, "data": False})
        if iface.startswith("wlan"):
            row["wifi"] = True
        else:
            row["data"] = True
    return {"blocks": list(by_uid.values())}


def clear(dctx) -> dict:
    """Remove all app firewall rules."""
    adb = dctx.adb
    for ipt in ("iptables", "ip6tables"):
        try:
            adb.shell_sync(f"{ipt} -F {_CHAIN} 2>/dev/null || true", su=True, timeout=12)
        except AdbError:
            pass
    return {"ok": True, "output": "firewall cleared"}
