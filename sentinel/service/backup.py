"""App extraction / backup service (own-device).

Pulls an app exactly as it sits on the device: its APK (base + splits) and its
private data directory, tarred as-is, plus an optional external data dir. Writes
everything under <data_dir>/backups/<pkg>_<timestamp>/ on this machine, with a
manifest. This is the same operation Titanium Backup / Neo Backup perform; it
needs root and stays entirely local.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path

from ..core.events import Event, SEV_INFO, SEV_WARN

# A real APK lives under one of these roots and ends in .apk; anything else
# from `pm path` on a semi-trusted device is refused rather than pulled.
_APK_PATH = re.compile(r"^/(data|system|system_ext|product|vendor|apex)/.+\.apk$")


class BackupService:
    def __init__(self, hub) -> None:
        self.hub = hub
        self.jobs: dict[int, dict] = {}
        self._seq = 0
        self._lock = threading.Lock()
        self.root: Path = hub.cfg.data_dir / "backups"
        self.root.mkdir(parents=True, exist_ok=True)

    def new_job(self, pkg: str, serial: str, opts: dict) -> dict:
        with self._lock:
            self._seq += 1
            jid = self._seq
        job = {"id": jid, "pkg": pkg, "serial": serial, "state": "running",
               "started": time.time(), "finished": None, "steps": [], "path": None,
               "error": None, "bytes": 0, **opts}
        self.jobs[jid] = job
        return job

    def run(self, dctx, job: dict) -> dict:
        """Blocking - call from a worker thread. dctx is the target device."""
        pkg = job["pkg"]
        adb = dctx.adb
        dctx.emit_threadsafe(Event(
            kind="app.backup", severity=SEV_INFO, title=f"Backup started: {pkg}",
            app=pkg, data={"job": job["id"]}))
        try:
            ts = time.strftime("%Y%m%d-%H%M%S")
            safe = pkg.replace("/", "_")
            serial_safe = re.sub(r"[^A-Za-z0-9._-]", "_", dctx.serial)
            dest = self.root / serial_safe / f"{safe}_{ts}"
            dest.mkdir(parents=True, exist_ok=True)
            inv = (dctx.state.get("apps") or {}).get(pkg, {})
            manifest: dict = {
                "package": pkg, "captured": ts, "serial": dctx.serial,
                "device": dctx.device.get("model"),
                "android": dctx.device.get("android"),
                "version": inv.get("version"), "version_name": inv.get("version_name"),
                "installer": inv.get("installer"), "granted": inv.get("granted"),
                "components": [],
            }

            if job.get("apk"):
                apkdir = dest / "apk"
                apkdir.mkdir(exist_ok=True)
                paths = adb.apk_paths(pkg)
                if not paths:
                    raise RuntimeError("pm path returned no APK (package not found?)")
                for i, rp in enumerate(paths):
                    # the device chose this path; only pull a real APK location,
                    # and prefix the index so colliding split basenames don't clobber
                    if not _APK_PATH.match(rp):
                        job["steps"].append(f"skipped non-APK path from device: {rp}")
                        continue
                    name = f"{i}_{os.path.basename(rp) or 'split.apk'}"
                    local = apkdir / name
                    if not adb.pull_file(rp, local):
                        _, ok = adb.pull_tar(rp, str(local) + ".tar")
                        local = Path(str(local) + ".tar")
                    job["bytes"] += local.stat().st_size if local.exists() else 0
                    job["steps"].append(f"apk: {local.name}")
                manifest["components"].append("apk")
                manifest["apk_files"] = [p.name for p in sorted(apkdir.iterdir())]

            if job.get("data"):
                tar = dest / "data.tar"
                size, ok = adb.pull_tar(f"/data/data/{pkg}", tar)
                job["bytes"] += size
                status = "" if ok else " [TRUNCATED - did not finish]"
                job["steps"].append(f"data.tar ({_h(size)}){status}")
                manifest["components"].append("data")
                manifest["data_tar_bytes"] = size
                manifest["data_complete"] = ok
                if size == 0:
                    job["steps"].append("note: data.tar empty (needs root)")
                elif not ok:
                    job["partial"] = True

            if job.get("external"):
                tar = dest / "external.tar"
                size, ok = adb.pull_tar(f"/sdcard/Android/data/{pkg}", tar)
                job["bytes"] += size
                job["steps"].append(f"external.tar ({_h(size)})" + ("" if ok else " [TRUNCATED]"))
                manifest["components"].append("external")
                manifest["external_tar_bytes"] = size
                manifest["external_complete"] = ok
                if not ok and size:
                    job["partial"] = True

            (dest / "manifest.json").write_text(json.dumps(manifest, indent=2))
            job["path"] = str(dest)
            job["state"] = "partial" if job.get("partial") else "done"
            job["finished"] = time.time()
            dctx.emit_threadsafe(Event(
                kind="app.backup", severity=SEV_INFO, title=f"Backup complete: {pkg}",
                app=pkg, detail=f"{_h(job['bytes'])} -> {dest}",
                data={"job": job["id"], "path": str(dest), "bytes": job["bytes"]}))
        except Exception as e:  # noqa: BLE001 - report, never crash the server
            job["state"] = "error"
            job["error"] = str(e)
            job["finished"] = time.time()
            dctx.emit_threadsafe(Event(
                kind="app.backup", severity=SEV_WARN, title=f"Backup failed: {pkg}",
                app=pkg, detail=str(e), data={"job": job["id"]}))
        return job

    def list_backups(self, serial: str | None = None) -> list[dict]:
        out: list[dict] = []
        for mf in self.root.rglob("manifest.json"):
            d = mf.parent
            try:
                meta = json.loads(mf.read_text())
            except Exception:
                meta = {}
            if serial and meta.get("serial") != serial:
                continue
            total = sum(f.stat().st_size for f in d.rglob("*") if f.is_file())
            out.append({"name": d.name, "path": str(d), "bytes": total,
                        "package": meta.get("package"), "serial": meta.get("serial"),
                        "captured": meta.get("captured"),
                        "components": meta.get("components", [])})
        out.sort(key=lambda b: b.get("captured") or "", reverse=True)
        return out


def _h(n: float) -> str:
    """Human-readable byte size."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{int(n)} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"
