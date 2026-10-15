"""App inventory and diffing: installs, removals, updates, signer changes and
silently-granted permissions. Baseline lives in the local store, so changes
survive restarts of the dashboard.
"""
from __future__ import annotations

import asyncio

from ..core.events import Event, SEV_INFO, SEV_NOTICE, SEV_WARN
from ..parsers.packagedump import parse_packages_dump, parse_pm_list
from .base import Collector

_SMS_PERMS = {"android.permission.READ_SMS", "android.permission.RECEIVE_SMS"}
_SNAPSHOT_KEY = "packages_baseline"


class PackagesCollector(Collector):
    name = "packages"

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self._combo_flagged: set[str] = set()

    async def run(self) -> None:
        await self.poll_loop(self.ctx.cfg.poll_packages, self._poll)

    async def _poll(self) -> None:
        adb = self.ctx.adb
        assert adb is not None

        third = parse_pm_list(await adb.shell("pm list packages -f -i -U -3", timeout=30))
        dump = parse_packages_dump(await adb.shell("dumpsys package packages", timeout=90))
        default_sms = (await adb.shell(
            "settings get secure sms_default_application", timeout=10)).strip()

        inv: dict[str, dict] = {}
        for pkg, basic in third.items():
            d = dump.get(pkg, {})
            inv[pkg] = {
                "uid": basic.get("uid"),
                "installer": d.get("installer") or basic.get("installer"),
                "version": d.get("version"),
                "version_name": d.get("version_name"),
                "sig": d.get("sig"),
                "system": False,
                "requested": sorted(set(d.get("requested") or [])),
                "granted": sorted(set(d.get("granted") or [])),
                "last_update": d.get("last_update"),
            }
        self.ctx.state["apps"] = inv

        baseline = await asyncio.to_thread(self.ctx.store.get_snapshot, _SNAPSHOT_KEY)
        if baseline is None:
            await asyncio.to_thread(self.ctx.store.put_snapshot, _SNAPSHOT_KEY, inv)
            self.log.info("package baseline recorded: %d third-party apps", len(inv))
            self._check_combos(inv, default_sms)
            return

        for pkg, cur in inv.items():
            old = baseline.get(pkg)
            if old is None:
                self.ctx.emit(Event(
                    kind="app.install", severity=SEV_NOTICE,
                    title=f"App installed: {pkg}",
                    detail=f"installer: {cur.get('installer') or 'unknown'}",
                    app=pkg, uid=cur.get("uid"),
                    data={"installer": cur.get("installer")},
                ))
                continue
            if cur.get("version") and old.get("version") and cur["version"] != old["version"]:
                signer_changed = bool(cur.get("sig") and old.get("sig")
                                      and cur["sig"] != old["sig"])
                self.ctx.emit(Event(
                    kind="app.update",
                    severity=SEV_WARN if signer_changed else SEV_INFO,
                    title=f"App updated: {pkg}",
                    detail=f"v{old.get('version')} → v{cur.get('version')}"
                           + (" — SIGNER CHANGED" if signer_changed else ""),
                    app=pkg, uid=cur.get("uid"),
                    data={"signer_changed": signer_changed,
                          "from": old.get("version"), "to": cur.get("version")},
                ))
            added = sorted(set(cur.get("granted") or []) - set(old.get("granted") or []))
            if added:
                self.ctx.emit(Event(
                    kind="app.perm", severity=SEV_NOTICE,
                    title=f"{pkg}: permissions granted",
                    detail=", ".join(p.rsplit(".", 1)[-1] for p in added),
                    app=pkg, uid=cur.get("uid"),
                    data={"added": added},
                ))
        for pkg in set(baseline) - set(inv):
            self.ctx.emit(Event(
                kind="app.remove", severity=SEV_INFO,
                title=f"App removed: {pkg}", app=pkg, data={},
            ))

        await asyncio.to_thread(self.ctx.store.put_snapshot, _SNAPSHOT_KEY, inv)
        self._check_combos(inv, default_sms)

    def _check_combos(self, inv: dict[str, dict], default_sms: str) -> None:
        for pkg, d in inv.items():
            if pkg in self._combo_flagged or pkg == default_sms:
                continue
            granted = set(d.get("granted") or [])
            if granted & _SMS_PERMS and "android.permission.INTERNET" in set(
                    d.get("requested") or []) | granted:
                self._combo_flagged.add(pkg)
                self.ctx.emit(Event(
                    kind="threat.combo", severity=SEV_WARN,
                    title=f"{pkg} can read SMS and reach the internet",
                    detail="not the default SMS app",
                    app=pkg, uid=d.get("uid"),
                    data={"combo": "sms_internet"},
                ))
