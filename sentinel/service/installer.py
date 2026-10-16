"""Install an uploaded APK / split bundle, and restore a backup.

An upload lands under <data_dir>/uploads/<uuid>/ and is removed once adb has
installed it. Bundles (.apks / .xapk / .apkm) are plain zips: only their *.apk
entries are taken, flattened to their basenames so no archive path can escape
the upload directory. A restore reinstalls the saved APK files with `adb
install-multiple -r`, then (with root) unpacks data.tar over the app's data
directory and hands ownership back to the app's uid.
"""
from __future__ import annotations

import os
import re
import shutil
import time
import uuid
import zipfile
from pathlib import Path

from ..adb.client import AdbError
from ..core.events import Event, SEV_INFO, SEV_WARN

_PKG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.]{1,254}$")
BACKUP_NAME = re.compile(r"^[A-Za-z0-9_.\-]{1,200}$")
BUNDLE_EXTS = (".apks", ".xapk", ".apkm")
MAX_UPLOAD = 400 * 1024 * 1024
_MAX_EXTRACT = 1024 * 1024 * 1024        # a bundle may decompress larger than the cap
_MAX_ENTRIES = 200


def serial_safe(serial: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", serial or "device")


def install_flags(options: dict) -> list[str]:
    flags: list[str] = []
    if options.get("replace", True):
        flags.append("-r")
    if options.get("downgrade"):
        flags.append("-d")
    if options.get("grant_all"):
        flags.append("-g")
    if options.get("allow_test"):
        flags.append("-t")
    user = options.get("user")
    if user is not None and user != "":
        try:
            u = int(user)
        except (TypeError, ValueError):
            raise AdbError("invalid user id") from None
        if not 0 <= u <= 999:
            raise AdbError("invalid user id")
        flags += ["--user", str(u)]
    installer = options.get("installer")
    if installer:
        if not isinstance(installer, str) or not _PKG.match(installer):
            raise AdbError("invalid installer package")
        flags += ["-i", installer]
    return flags


def extract_apks(bundle: Path, dest: Path) -> list[Path]:
    """Only *.apk members, written as <dest>/<basename> (zip-slip safe); a
    duplicate basename gets a numeric prefix. Size-capped."""
    out: list[Path] = []
    total = 0
    seen: set[str] = set()
    with zipfile.ZipFile(bundle) as zf:
        for info in zf.infolist():
            if info.is_dir() or not info.filename.lower().endswith(".apk"):
                continue
            name = os.path.basename(info.filename.replace("\\", "/"))
            if not name or not re.fullmatch(r"[A-Za-z0-9_.\-]{1,200}\.apk", name, re.I):
                continue
            if info.file_size < 0 or info.file_size > _MAX_EXTRACT:
                raise AdbError(f"{name} is too large")
            total += info.file_size
            if total > _MAX_EXTRACT or len(out) >= _MAX_ENTRIES:
                raise AdbError("bundle too large")
            if name in seen:
                name = f"{len(out)}_{name}"
            seen.add(name)
            target = dest / name
            with zf.open(info) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
            out.append(target)
    # base first, then splits in a stable order
    out.sort(key=lambda p: (not p.name.startswith("base"), p.name))
    return out


def install_upload(dctx, saved_path: Path, options: dict | None = None) -> dict:
    """Blocking: install one .apk, or every APK inside a bundle, then delete
    the upload directory. Returns {ok, output, files}."""
    saved_path = Path(saved_path)
    upload_dir = saved_path.parent
    options = options or {}
    files: list[Path] = []
    try:
        try:
            flags = install_flags(options)
            ext = saved_path.suffix.lower()
            if ext == ".apk":
                files = [saved_path]
            elif ext in BUNDLE_EXTS:
                if not zipfile.is_zipfile(saved_path):
                    raise AdbError("bundle is not a zip file")
                ex = upload_dir / "extracted"
                ex.mkdir(exist_ok=True)
                files = extract_apks(saved_path, ex)
                if not files:
                    raise AdbError("bundle contains no .apk entries")
            else:
                raise AdbError("expected a .apk, .apks, .xapk or .apkm file")
        except (AdbError, zipfile.BadZipFile, OSError) as e:
            return {"ok": False, "output": str(e), "files": [f.name for f in files]}
        ok, out = dctx.adb.install([str(f) for f in files], flags, timeout=1200)
        return {"ok": ok, "output": out, "files": [f.name for f in files]}
    finally:
        shutil.rmtree(upload_dir, ignore_errors=True)


# ---------------- restore ----------------

def backup_dir(hub, serial: str, name: str) -> Path:
    if not BACKUP_NAME.match(name or "") or name in (".", ".."):
        raise AdbError("invalid backup name")
    d = hub.backup.root / serial_safe(serial) / name
    if not d.is_dir() or not (d / "manifest.json").is_file():
        raise AdbError("no such backup for this device")
    return d


def new_restore_job(hub, dctx, name: str, apk: bool, data: bool) -> dict:
    d = backup_dir(hub, dctx.serial, name)
    import json
    try:
        pkg = json.loads((d / "manifest.json").read_text()).get("package") or ""
    except (OSError, ValueError):
        pkg = ""
    if not _PKG.match(pkg):
        raise AdbError("backup manifest has no valid package name")
    return hub.backup.new_job(pkg, dctx.serial, {"type": "restore", "name": name,
                                                 "apk": bool(apk), "data": bool(data)})


def run_restore(hub, dctx, job: dict) -> dict:
    """Blocking - call from a worker thread. Reinstalls the saved APKs and/or
    unpacks data.tar over /data/data/<pkg> as root."""
    import shlex
    pkg = job["pkg"]
    adb = dctx.adb
    dctx.emit_threadsafe(Event(kind="app.backup", severity=SEV_INFO,
                               title=f"Restore started: {pkg}", app=pkg,
                               data={"job": job["id"], "name": job.get("name")}))
    try:
        d = backup_dir(hub, dctx.serial, job["name"])
        if job.get("apk"):
            apks = sorted((d / "apk").glob("*.apk")) if (d / "apk").is_dir() else []
            apks.sort(key=lambda p: (not p.name.split("_", 1)[-1].startswith("base"), p.name))
            if not apks:
                raise RuntimeError("backup has no APK files")
            ok, out = adb.install([str(p) for p in apks], ["-r"], timeout=1200)
            if not ok and "INSTALL_FAILED_TEST_ONLY" in out:
                ok, out = adb.install([str(p) for p in apks], ["-r", "-t"], timeout=1200)
            job["steps"].append(f"apk: {'installed' if ok else out[:200]}")
            if not ok:
                raise RuntimeError(f"install failed: {out[:300]}")
        if job.get("data"):
            tar = d / "data.tar"
            if not tar.is_file() or tar.stat().st_size == 0:
                raise RuntimeError("backup has no data.tar")
            from .appdata import package_uid
            uid = package_uid(dctx, pkg)
            if uid is None:
                raise RuntimeError("app is not installed (restore its APK first)")
            tmp = f"/data/local/tmp/sentinel-{uuid.uuid4().hex}.tar"
            if not adb.push_file(tar, tmp, timeout=3600):
                raise RuntimeError("adb push of data.tar failed")
            q_tmp, q_pkg = shlex.quote(tmp), shlex.quote(pkg)
            try:
                adb.shell_sync(f"am force-stop {q_pkg}", timeout=30)
                # data.tar holds "<pkg>/..." (made with tar -C /data/data <pkg>),
                # so it unpacks over the existing directory; nothing is cleared
                cmd = (f"(tar -xf {q_tmp} -C /data/data && chown -R {uid}:{uid} /data/data/{q_pkg} "
                       f"&& restorecon -R /data/data/{q_pkg} && echo RESTORED)")
                out = adb.shell_sync(cmd, su=True, timeout=3600)
            finally:
                try:
                    adb.shell_sync(f"rm -f {q_tmp}", timeout=30)
                except AdbError:
                    pass
            if "RESTORED" not in out:
                raise RuntimeError(f"data restore failed: {out.strip()[:300] or 'needs root'}")
            job["steps"].append(f"data: restored ({tar.stat().st_size} bytes)")
            job["bytes"] = tar.stat().st_size
        job["path"] = str(d)
        job["state"] = "done"
        job["finished"] = time.time()
        dctx.emit_threadsafe(Event(kind="app.backup", severity=SEV_INFO,
                                   title=f"Restore complete: {pkg}", app=pkg,
                                   detail="; ".join(job["steps"]),
                                   data={"job": job["id"], "path": str(d)}))
    except Exception as e:  # noqa: BLE001 - report, never crash the server
        job["state"] = "error"
        job["error"] = str(e)
        job["finished"] = time.time()
        dctx.emit_threadsafe(Event(kind="app.backup", severity=SEV_WARN,
                                   title=f"Restore failed: {pkg}", app=pkg, detail=str(e),
                                   data={"job": job["id"]}))
    return job
