"""Root / su control for the owner's own device.

Probes whether `su` works, which root manager provides it (Magisk, KernelSU,
APatch, SuperSU), whether adbd itself runs as root (userdebug / custom ROMs),
the SELinux mode, and lets the owner request root (so the manager's Grant
prompt can be tapped) or stop using su for a device. Every probe is wrapped
and short-timed; a device without root answers in a few seconds.
"""
from __future__ import annotations

from ..adb.client import AdbError

_SNAP_USE_SU = "use_su"


def _probe(adb, cmd: str, *, su: bool = False, timeout: float = 8.0) -> str:
    try:
        return (adb.shell_sync(cmd, su=su, timeout=timeout) or "").strip()
    except AdbError:
        return ""


def _manager(adb, su_ok: bool) -> dict:
    """{name, version} of the root provider, best effort. `su -v` names the
    manager on every modern provider; magisk's own binary gives the version."""
    name: str | None = None
    version: str | None = None
    sv = _probe(adb, "su -v")
    low = sv.lower()
    if "kernelsu" in low:
        name = "KernelSU"
    elif "apatch" in low:
        name = "APatch"
    elif "supersu" in low:
        name = "SuperSU"
    elif "magisk" in low:
        name = "Magisk"
    if name is None:
        # provider daemons live under /data/adb; the names are fixed
        probe = _probe(adb, "ls /data/adb/ksud /data/adb/apd /data/adb/magisk 2>/dev/null",
                       su=True)
        if "ksud" in probe:
            name = "KernelSU"
        elif "apd" in probe:
            name = "APatch"
        elif "magisk" in probe:
            name = "Magisk"
    if name == "Magisk" or (name is None and su_ok):
        mv = _probe(adb, "magisk -v", su=True) or _probe(adb, "magisk -V", su=True)
        if mv:
            name = "Magisk"
            version = mv.splitlines()[0].strip()[:64]
    if version is None and sv:
        version = sv.splitlines()[0].strip()[:64]
    if name is None and su_ok:
        name = "unknown"
    return {"name": name, "version": version}


def root_status(dctx) -> dict:
    """What root looks like on this device right now."""
    adb = dctx.adb
    out: dict = {"root": False, "su_path": None, "manager": {"name": None, "version": None},
                 "adbd_root": False, "selinux": None, "use_su": bool(adb.use_su)}
    try:
        plain = _probe(adb, "id")
        out["adbd_root"] = plain.startswith("uid=0")
        su_id = _probe(adb, "su -c id")
        out["root"] = "uid=0" in su_id
        path = _probe(adb, "command -v su || which su")
        out["su_path"] = path.splitlines()[0].strip() if path and path.startswith("/") else None
        out["manager"] = _manager(adb, out["root"])
        se = _probe(adb, "getenforce")
        if se in ("Enforcing", "Permissive"):
            out["selinux"] = se
        if isinstance(getattr(dctx, "device", None), dict):
            dctx.device["root"] = out["root"]
    except Exception as e:  # noqa: BLE001 - a status probe never raises to the route
        out["error"] = str(e)
    return out


def request_root(dctx) -> dict:
    """Run `su -c id` with a long timeout so the owner can tap Grant on the
    phone when the manager prompts."""
    adb = dctx.adb
    try:
        out = (adb.shell_sync("su -c id", timeout=45) or "").strip()
    except AdbError as e:
        return {"ok": False, "root": False, "output": str(e)}
    root = "uid=0" in out
    if isinstance(getattr(dctx, "device", None), dict):
        dctx.device["root"] = root
    return {"ok": root, "root": root,
            "output": out or ("granted" if root else "su returned nothing (denied?)")}


def set_use_su(dctx, enabled: bool) -> dict:
    """Flip whether privileged commands are wrapped in `su -c` for this device
    and remember it, so the choice survives a reconnect."""
    on = bool(enabled)
    dctx.adb.use_su = on
    try:
        dctx.store.put_snapshot(_SNAP_USE_SU, on)
    except Exception:  # noqa: BLE001 - the live flag is already set
        pass
    return {"ok": True, "use_su": on}
