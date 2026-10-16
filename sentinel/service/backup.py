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
import threading
import time
from pathlib import Path

from ..core.events import Event, SEV_INFO, SEV_WARN


class BackupService:
    def __init__(self, ctx) -> None:
        self.ctx = ctx
        self.jobs: dict[int, dict] = {}
        self._seq = 0
        self._lock = threading.Lock()
        self.root: Path = ctx.cfg.data_dir / "backups"
        self.root.mkdir(parents=True, exist_ok=True)

    def new_job(self, pkg: str, opts: dict) -> dict:
        with self._lock:
            self._seq += 1
            jid = self._seq
        job = {"id": jid, "pkg": pkg, "state": "running", "started": time.time(),
               "finished": None, "steps": [], "path": None, "error": None,
               "bytes": 0, **opts}
        self.jobs[jid] = job
        return job

    def run(self, job: dict) -> dict:
        """Blocking — call from a worker thread."""
        pkg = job["pkg"]
        adb = self.ctx.adb
        self.ctx.emit_threadsafe(Event(
            kind="app.backup", severity=SEV_INFO, title=f"Backup started: {pkg}",
            app=pkg, data={"job": job["id"]}))
        try:
            ts = time.strftime("%Y%m%d-%H%M%S")
            safe = pkg.replace("/", "_")
            dest = self.root / f"{safe}_{ts}"
            dest.mkdir(parents=True, exist_ok=True)
            inv = (self.ctx.state.get("apps") or {}).get(pkg, {})
            manifest: dict = {
                "package": pkg, "captured": ts,
                "device": self.ctx.device.get("model"),
                "android": self.ctx.device.get("android"),
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
                    local = apkdir / (os.path.basename(rp) or f"split_{i}.apk")
                    if not adb.pull_file(rp, local):
                        adb.pull_tar(rp, str(local) + ".tar")
                        local = Path(str(local) + ".tar")
                    job["bytes"] += local.stat().st_size if local.exists() else 0
                    job["steps"].append(f"apk: {local.name}")
                manifest["components"].append("apk")
                manifest["apk_files"] = [p.name for p in sorted(apkdir.iterdir())]

            if job.get("data"):
                tar = dest / "data.tar"
                size = adb.pull_tar(f"/data/data/{pkg}", tar)
                job["bytes"] += size
                job["steps"].append(f"data.tar ({_h(size)})")
                manifest["components"].append("data")
                manifest["data_tar_bytes"] = size
                if size == 0:
                    job["steps"].append("note: data.tar empty (needs root)")

            if job.get("external"):
                tar = dest / "external.tar"
                size = adb.pull_tar(f"/sdcard/Android/data/{pkg}", tar)
                job["bytes"] += size
                job["steps"].append(f"external.tar ({_h(size)})")
                manifest["components"].append("external")
                manifest["external_tar_bytes"] = size

            (dest / "manifest.json").write_text(json.dumps(manifest, indent=2))
            job["path"] = str(dest)
            job["state"] = "done"
            job["finished"] = time.time()
            self.ctx.emit_threadsafe(Event(
                kind="app.backup", severity=SEV_INFO, title=f"Backup complete: {pkg}",
                app=pkg, detail=f"{_h(job['bytes'])} -> {dest}",
                data={"job": job["id"], "path": str(dest), "bytes": job["bytes"]}))
        except Exception as e:  # noqa: BLE001 - report, never crash the server
            job["state"] = "error"
            job["error"] = str(e)
            job["finished"] = time.time()
            self.ctx.emit_threadsafe(Event(
                kind="app.backup", severity=SEV_WARN, title=f"Backup failed: {pkg}",
                app=pkg, detail=str(e), data={"job": job["id"]}))
        return job

    def list_backups(self) -> list[dict]:
        out: list[dict] = []
        for d in sorted(self.root.glob("*"), reverse=True):
            if not d.is_dir():
                continue
            mf = d / "manifest.json"
            meta = {}
            if mf.exists():
                try:
                    meta = json.loads(mf.read_text())
                except Exception:
                    meta = {}
            total = sum(f.stat().st_size for f in d.rglob("*") if f.is_file())
            out.append({"name": d.name, "path": str(d), "bytes": total,
                        "package": meta.get("package"), "captured": meta.get("captured"),
                        "components": meta.get("components", [])})
        return out


def _h(n: float) -> str:
    """Human-readable byte size."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{int(n)} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"
