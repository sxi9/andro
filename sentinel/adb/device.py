"""Device identity and UID/PID → package attribution maps."""
from __future__ import annotations

import logging
import re
import time

from .client import AdbClient, AdbError

log = logging.getLogger("sentinel.device")

# Well-known Android system UIDs that aren't packages.
SYSTEM_UIDS = {
    0: "root", 1000: "system", 1001: "radio", 1002: "bluetooth",
    1013: "mediaserver", 1021: "gps", 1041: "audioserver", 1047: "cameraserver",
    2000: "adb shell", 9999: "nobody",
}

_PKG_UID_RE = re.compile(r"^package:(\S+)\s+uid:(\d+)", re.M)


def device_info(adb: AdbClient) -> dict:
    """One-shot device identity used by /api/status and the dashboard header."""
    info: dict = {"connected": False}
    try:
        props = adb.shell_sync(
            "getprop ro.product.model; getprop ro.build.version.release; "
            "getprop ro.build.version.sdk; getprop ro.product.manufacturer",
            timeout=10)
        lines = [ln.strip() for ln in props.splitlines()]
        while len(lines) < 4:
            lines.append("")
        info.update({
            "connected": True,
            "model": lines[0] or "Android device",
            "android": lines[1],
            "sdk": lines[2],
            "manufacturer": lines[3],
            "serial": adb.serial or "",
            "root": adb.has_root(),
            "wireless": bool(adb.serial and ":" in adb.serial),
        })
    except AdbError as e:
        info["error"] = str(e)
    return info


class DeviceMaps:
    """Caches uid→package and pid→(uid, name), refreshed on a short TTL."""

    def __init__(self, adb: AdbClient, ttl: float = 20.0) -> None:
        self.adb = adb
        self.ttl = ttl
        self._uid2pkg: dict[int, str] = {}
        self._pid2proc: dict[int, tuple[int, str]] = {}
        self._uid_ts = 0.0
        self._pid_ts = 0.0

    # ---- uid map ----
    def refresh_uid_map(self) -> None:
        try:
            out = self.adb.shell_sync("pm list packages -U", timeout=25)
        except AdbError as e:
            log.debug("uid map refresh failed: %s", e)
            return
        m: dict[int, str] = {}
        for pkg, uid in _PKG_UID_RE.findall(out):
            u = int(uid)
            # shared UIDs: keep the first package but note the share
            if u in m and m[u] != pkg:
                m[u] = m[u]
            else:
                m[u] = pkg
        if m:
            self._uid2pkg = m
            self._uid_ts = time.time()

    def app_for_uid(self, uid: int | None) -> str | None:
        if uid is None:
            return None
        if time.time() - self._uid_ts > max(self.ttl * 10, 120):
            self.refresh_uid_map()
        if uid in SYSTEM_UIDS:
            return SYSTEM_UIDS[uid]
        pkg = self._uid2pkg.get(uid)
        if pkg:
            return pkg
        # work-profile / secondary-user uids: 10xxxxx → appId in main user
        app_id = uid % 100000
        return self._uid2pkg.get(app_id)

    # ---- pid map ----
    def refresh_pid_map(self) -> None:
        try:
            out = self.adb.shell_sync("ps -A -o PID,UID,NAME", timeout=20)
        except AdbError as e:
            log.debug("pid map refresh failed: %s", e)
            return
        m: dict[int, tuple[int, str]] = {}
        for line in out.splitlines()[1:]:
            parts = line.split(None, 2)
            if len(parts) >= 3:
                try:
                    m[int(parts[0])] = (int(parts[1]), parts[2].strip())
                except ValueError:
                    continue
        if m:
            self._pid2proc = m
            self._pid_ts = time.time()

    def proc_for_pid(self, pid: int | None) -> tuple[int | None, str | None]:
        if pid is None:
            return None, None
        if time.time() - self._pid_ts > self.ttl:
            self.refresh_pid_map()
        entry = self._pid2proc.get(pid)
        if not entry:
            return None, None
        uid, name = entry
        # process names are usually the package (possibly with :service suffix)
        return uid, name.split(":", 1)[0]

    def all_packages(self) -> dict[int, str]:
        if not self._uid2pkg:
            self.refresh_uid_map()
        return dict(self._uid2pkg)
