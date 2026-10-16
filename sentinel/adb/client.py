"""Thin wrapper around the adb binary.

Works identically over USB and wireless debugging: pair/connect once with
`adb pair` / `adb connect host:port`, then pass that host:port as --serial.
Privileged reads are wrapped in `su -c` on rooted devices.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import shlex
import subprocess
from dataclasses import dataclass

log = logging.getLogger("sentinel.adb")


class AdbError(RuntimeError):
    pass


# Every state `adb devices` can print, with a plain-language explanation and
# whether the device is ready for monitoring.
STATE_INFO: dict[str, tuple[bool, str]] = {
    "device": (True, "Connected and authorized."),
    "unauthorized": (False, "Tap 'Allow USB debugging' on the phone (check 'Always allow'). "
                            "If no prompt appears, toggle USB debugging off and on."),
    "offline": (False, "Device is unresponsive. Replug the cable, or use Reconnect / Restart ADB."),
    "no permissions": (False, "The OS is blocking adb access to the USB device "
                              "(udev rules on Linux). See the adb udev setup."),
    "authorizing": (False, "Authorizing - waiting for the phone to confirm the debugging key."),
    "connecting": (False, "Connecting over the network - give it a moment."),
    "recovery": (False, "Device is in recovery mode, not normal Android."),
    "sideload": (False, "Device is in sideload mode."),
    "bootloader": (False, "Device is in the bootloader / fastboot, not Android."),
    "host": (False, "Host transport, not a monitorable device."),
}


def _looks_wireless(serial: str) -> bool:
    # ip:port (adb connect / Android 11+ wireless), or an mDNS _adb-tls name
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}:\d+$", serial)) or \
        "_adb-tls" in serial or bool(re.match(r"^adb-.*\._adb", serial))


def parse_devices_output(text: str) -> list[dict[str, str]]:
    """Parse `adb devices -l` into [{serial, state, transport, ready, reason, model, ...}]."""
    out: list[dict[str, str]] = []
    for line in (text or "").splitlines():
        line = line.rstrip()
        if not line or line.startswith("List of devices") or line.startswith("*"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        serial = parts[0]
        rest = parts[1:]
        # state can be two words ("no permissions")
        if rest[0] == "no" and len(rest) > 1 and rest[1].startswith("permission"):
            state, extras = "no permissions", rest[2:]
        else:
            state, extras = rest[0], rest[1:]
        kv = {}
        for tok in extras:
            if ":" in tok:
                k, v = tok.split(":", 1)
                kv[k] = v
        ready, reason = STATE_INFO.get(state, (False, f"Unknown adb state: {state}"))
        out.append({
            "serial": serial, "state": state,
            "transport": "wireless" if _looks_wireless(serial) else "usb",
            "ready": ready, "reason": reason,
            "model": kv.get("model", "").replace("_", " "),
            "device": kv.get("device", ""),
            "desc": " ".join(extras),
        })
    return out


def validate_host_port(host_port: str) -> None:
    """Guard adb connect/disconnect/pair args: host:port only, no shell metachars."""
    if not isinstance(host_port, str) or not re.fullmatch(
            r"[A-Za-z0-9._\-]+:\d{1,5}", host_port or ""):
        raise AdbError("expected host:port, e.g. 192.168.1.42:5555")
    if not 1 <= int(host_port.rsplit(":", 1)[1]) <= 65535:
        raise AdbError("port out of range")


@dataclass
class AdbClient:
    adb_path: str = "adb"
    serial: str | None = None
    use_su: bool = True

    # ---- command building ----
    def _base(self) -> list[str]:
        cmd = [self.adb_path]
        if self.serial:
            cmd += ["-s", self.serial]
        return cmd

    def _device_cmd(self, cmd: str, su: bool) -> str:
        if su and self.use_su:
            return f"su -c {shlex.quote(cmd)}"
        return cmd

    # ---- one-shot ----
    def shell_sync(self, cmd: str, *, su: bool = False, timeout: float = 20.0) -> str:
        full = self._base() + ["shell", self._device_cmd(cmd, su)]
        try:
            p = subprocess.run(full, capture_output=True, text=True, timeout=timeout,
                               errors="replace")
        except FileNotFoundError as e:
            raise AdbError(f"adb binary not found: {self.adb_path}") from e
        except subprocess.TimeoutExpired as e:
            raise AdbError(f"adb shell timed out: {cmd[:80]}") from e
        if p.returncode != 0 and not p.stdout:
            raise AdbError(f"adb shell failed ({p.returncode}): {(p.stderr or '').strip()[:200]}")
        return p.stdout

    async def shell(self, cmd: str, *, su: bool = False, timeout: float = 20.0) -> str:
        return await asyncio.to_thread(self.shell_sync, cmd, su=su, timeout=timeout)

    # ---- streaming ----
    def popen_lines(self, cmd: str, *, su: bool = False) -> subprocess.Popen:
        """Long-running text stream (e.g. logcat). Caller reads proc.stdout lines."""
        full = self._base() + ["shell", self._device_cmd(cmd, su)]
        return subprocess.Popen(full, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, errors="replace", bufsize=1)

    def popen_raw(self, cmd: str, *, su: bool = False) -> subprocess.Popen:
        """Long-running binary stream via exec-out (e.g. tcpdump -w -)."""
        full = self._base() + ["exec-out", self._device_cmd(cmd, su)]
        return subprocess.Popen(full, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    # ---- device management ----
    def devices(self) -> list[dict[str, str]]:
        """Parse `adb devices -l`. Every state adb can report is kept
        (device, unauthorized, offline, no permissions, authorizing,
        connecting, recovery, sideload, bootloader) so the UI can explain it."""
        try:
            p = subprocess.run([self.adb_path, "devices", "-l"], capture_output=True,
                               text=True, timeout=15, errors="replace")
        except FileNotFoundError as e:
            raise AdbError(f"adb binary not found: {self.adb_path}") from e
        except subprocess.TimeoutExpired as e:
            raise AdbError("adb devices timed out (server hung? try Restart ADB)") from e
        return parse_devices_output(p.stdout)

    def version(self) -> str:
        try:
            p = subprocess.run([self.adb_path, "version"], capture_output=True, text=True,
                               timeout=10, errors="replace")
            return (p.stdout.splitlines() or [""])[0].strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return ""

    # ---- server controls (fixed, validated commands; never an open shell) ----
    def _server_cmd(self, args: list[str], timeout: float = 20.0) -> str:
        try:
            p = subprocess.run([self.adb_path, *args], capture_output=True, text=True,
                               timeout=timeout, errors="replace")
        except FileNotFoundError as e:
            raise AdbError(f"adb binary not found: {self.adb_path}") from e
        except subprocess.TimeoutExpired as e:
            raise AdbError(f"adb {' '.join(args)} timed out") from e
        return ((p.stdout or "") + (p.stderr or "")).strip()

    def kill_server(self) -> str:
        return self._server_cmd(["kill-server"]) or "adb server stopped"

    def start_server(self) -> str:
        return self._server_cmd(["start-server"]) or "adb server started"

    def restart_server(self) -> str:
        a = self.kill_server()
        b = self.start_server()
        return f"{a}\n{b}".strip()

    def reconnect(self, serial: str | None = None) -> str:
        args = ["-s", serial, "reconnect"] if serial else ["reconnect"]
        return self._server_cmd(args)

    def reconnect_offline(self) -> str:
        return self._server_cmd(["reconnect", "offline"])

    def connect(self, host_port: str) -> str:
        validate_host_port(host_port)
        return self._server_cmd(["connect", host_port], timeout=25)

    def disconnect(self, host_port: str | None = None) -> str:
        if host_port:
            validate_host_port(host_port)
            return self._server_cmd(["disconnect", host_port])
        return self._server_cmd(["disconnect"])

    def pair(self, host_port: str, code: str) -> str:
        """Wireless-debugging pairing (Android 11+): the phone shows an
        ip:port and a 6-digit code under Developer options → Wireless debugging."""
        validate_host_port(host_port)
        if not re.fullmatch(r"\d{6}", code or ""):
            raise AdbError("pairing code must be the 6 digits shown on the phone")
        return self._server_cmd(["pair", host_port, code], timeout=30)

    def tcpip(self, serial: str, port: int = 5555) -> str:
        """Switch a USB-connected device to listen on TCP (legacy wireless adb)."""
        if not 1024 <= int(port) <= 65535:
            raise AdbError("port out of range")
        return self._server_cmd(["-s", serial, "tcpip", str(int(port))])

    # ---- capability probes ----
    def has_root(self) -> bool:
        try:
            out = self.shell_sync("id", su=True, timeout=8)
            return "uid=0" in out
        except AdbError:
            return False

    def has_binary(self, name: str) -> bool:
        try:
            out = self.shell_sync(f"command -v {shlex.quote(name)} || which {shlex.quote(name)}",
                                  su=True, timeout=8)
            return bool(out.strip())
        except AdbError:
            return False

    # ---- filesystem inspection (own-device backup / forensics) ----
    def list_dir(self, path: str, *, su: bool = True, timeout: float = 20.0) -> str:
        """`ls -la` on a directory. Needs root to read another app's data dir."""
        return self.shell_sync(f"ls -la {shlex.quote(path)}", su=su, timeout=timeout)

    def du_sizes(self, paths: list[str], *, su: bool = True, timeout: float = 180.0) -> str:
        """`du -sk` for several paths at once; output is '<kb>\\t<path>' per line."""
        if not paths:
            return ""
        joined = " ".join(shlex.quote(p) for p in paths)
        return self.shell_sync(f"du -sk {joined} 2>/dev/null", su=su, timeout=timeout)

    def find_files(self, root: str, name_globs: list[str] | None = None, *,
                   limit: int = 200, su: bool = True, timeout: float = 40.0) -> str:
        """`find` under a directory for files matching any of name_globs. Each
        glob is quoted internally, so no caller can inject shell."""
        pred = ""
        if name_globs:
            parts = " -o ".join(f"-name {shlex.quote(g)}" for g in name_globs)
            pred = f"\\( {parts} \\)"
        cmd = f"find {shlex.quote(root)} -type f {pred} 2>/dev/null | head -n {int(limit)}"
        return self.shell_sync(cmd, su=su, timeout=timeout)

    def exec_out_bytes(self, cmd: str, *, su: bool = False, timeout: float = 120.0) -> bytes:
        """Run a command via exec-out and return its raw stdout bytes (no CRLF
        mangling). Used for byte-range reads of device files."""
        full = self._base() + ["exec-out", self._device_cmd(cmd, su)]
        try:
            p = subprocess.run(full, capture_output=True, timeout=timeout)
        except FileNotFoundError as e:
            raise AdbError(f"adb binary not found: {self.adb_path}") from e
        except subprocess.TimeoutExpired as e:
            raise AdbError("adb exec-out timed out") from e
        return p.stdout or b""

    # ---- file transfer ----
    def pull_file(self, remote: str, local, *, timeout: float = 600.0) -> bool:
        """`adb pull` for a world-readable file (APKs). Returns True on success."""
        full = self._base() + ["pull", remote, str(local)]
        try:
            p = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return False
        return p.returncode == 0 and os.path.exists(local) and os.path.getsize(local) > 0

    def pull_tar(self, remote_path: str, local_tar, *, su: bool = True,
                 timeout: float = 3600.0) -> tuple[int, bool]:
        """Stream a remote file or directory tree to a local .tar via
        `exec-out su -c tar`. The only reliable way to copy a root-owned data
        directory off the device. Returns (bytes_written, completed_cleanly) so
        the caller can tell a finished archive from a timed-out / truncated one."""
        rp = remote_path.rstrip("/") or "/"
        parent = os.path.dirname(rp) or "/"
        name = os.path.basename(rp) or "."
        inner = f"tar -c -C {shlex.quote(parent)} {shlex.quote(name)} 2>/dev/null"
        full = self._base() + ["exec-out", self._device_cmd(inner, su)]
        ok = False
        with open(local_tar, "wb") as fh:
            try:
                p = subprocess.run(full, stdout=fh, stderr=subprocess.DEVNULL,
                                   timeout=timeout, check=False)
                ok = p.returncode == 0
            except subprocess.TimeoutExpired:
                ok = False
        size = os.path.getsize(local_tar) if os.path.exists(local_tar) else 0
        return size, ok

    def apk_paths(self, pkg: str, *, timeout: float = 20.0) -> list[str]:
        """Remote APK paths (base + splits) for a package, via `pm path`."""
        out = self.shell_sync(f"pm path {shlex.quote(pkg)}", timeout=timeout)
        return [ln.split("package:", 1)[1].strip()
                for ln in out.splitlines() if ln.startswith("package:")]
