"""Thin wrapper around the adb binary.

Works identically over USB and wireless debugging: pair/connect once with
`adb pair` / `adb connect host:port`, then pass that host:port as --serial.
Privileged reads are wrapped in `su -c` on rooted devices.
"""
from __future__ import annotations

import asyncio
import logging
import shlex
import subprocess
from dataclasses import dataclass

log = logging.getLogger("sentinel.adb")


class AdbError(RuntimeError):
    pass


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
        try:
            p = subprocess.run([self.adb_path, "devices", "-l"], capture_output=True,
                               text=True, timeout=10)
        except FileNotFoundError as e:
            raise AdbError(f"adb binary not found: {self.adb_path}") from e
        out = []
        for line in p.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] in ("device", "unauthorized", "offline"):
                out.append({"serial": parts[0], "state": parts[1],
                            "desc": " ".join(parts[2:])})
        return out

    def connect(self, host_port: str) -> str:
        p = subprocess.run([self.adb_path, "connect", host_port], capture_output=True,
                           text=True, timeout=15)
        return (p.stdout or p.stderr).strip()

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
