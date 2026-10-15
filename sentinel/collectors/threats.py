"""God-mode and tamper auditing.

Watches the four big abuse surfaces:
  - Accessibility services (screen reading + input injection)
  - Device admins (anti-uninstall, wipe, policy control)
  - Notification listeners (reads every notification, 2FA codes included)
  - User-installed CA certificates (HTTPS interception against the owner)
plus the state of wireless debugging itself, since leaving it on is a risk
this tool introduces.
"""
from __future__ import annotations

import asyncio
import re

from ..core.events import Event, SEV_NOTICE, SEV_WARN
from .base import Collector

_COMPONENT = re.compile(r"ComponentInfo\{([A-Za-z0-9_.]+)/")
_SNAPSHOT_KEY = "threats_baseline"

# user-added CA stores across versions
_CA_PATHS = (
    "/data/misc/user/0/cacerts-added",
    "/data/misc/keychain/cacerts-added",
)


def _components_to_pkgs(value: str) -> set[str]:
    """'pkg/cls:pkg2/cls2' (settings) → {pkg, pkg2}."""
    out: set[str] = set()
    for part in (value or "").replace("\n", "").split(":"):
        part = part.strip()
        if not part or part == "null":
            continue
        out.add(part.split("/", 1)[0])
    return out


class ThreatsCollector(Collector):
    name = "threats"

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self._iocs: set[str] = set()
        ioc_file = ctx.cfg.data_dir / "stalkerware-pkgs.txt"
        if ioc_file.exists():
            self._iocs = {ln.strip().lower() for ln in
                          ioc_file.read_text(errors="replace").splitlines()
                          if ln.strip() and not ln.startswith("#")}
            self.log.info("loaded %d stalkerware indicators", len(self._iocs))
        self._ioc_flagged: set[str] = set()
        self._mitm_flagged: set[str] = set()

    async def run(self) -> None:
        await self.poll_loop(self.ctx.cfg.poll_threats, self._poll)

    async def _poll(self) -> None:
        adb = self.ctx.adb
        assert adb is not None

        a11y = _components_to_pkgs(await adb.shell(
            "settings get secure enabled_accessibility_services", timeout=10))
        notif = _components_to_pkgs(await adb.shell(
            "settings get secure enabled_notification_listeners", timeout=10))
        dp = await adb.shell("dumpsys device_policy", timeout=20)
        admins = set(_COMPONENT.findall(dp))

        cas: set[str] = set()
        for path in _CA_PATHS:
            # `|| true` keeps a missing directory (exit 1 under shell-v2/su)
            # from raising and aborting the whole audit poll
            out = await adb.shell(f"ls -1 {path} 2>/dev/null || true", su=True, timeout=10)
            cas |= {ln.strip() for ln in out.splitlines()
                    if ln.strip() and "No such file" not in ln}

        adb_wifi = (await adb.shell(
            "settings get global adb_wifi_enabled", timeout=10)).strip()

        current = {
            "accessibility": sorted(a11y),
            "notification listener": sorted(notif),
            "device admin": sorted(admins),
        }
        self.ctx.state["godmode"] = current
        self.ctx.state["user_cas"] = sorted(cas)
        self.ctx.state["adb_wifi"] = adb_wifi == "1"

        # packages absent from the third-party inventory are preinstalled;
        # "(system)" keeps stock accessibility services (TalkBack etc.) from
        # tripping the sideload+god-mode combo
        third_party = self.ctx.state.get("apps") or {}
        installers = {p: (d.get("installer") if isinstance(d, dict) else None)
                      for p, d in third_party.items()}

        def installer_of(pkg: str) -> str | None:
            return installers.get(pkg, "(system)") if third_party else "(system)"

        baseline = await asyncio.to_thread(self.ctx.store.get_snapshot, _SNAPSHOT_KEY)
        if baseline is not None:
            for access, pkgs in current.items():
                old = set(baseline.get(access) or [])
                for pkg in set(pkgs) - old:
                    self.ctx.emit(Event(
                        kind="threat.godmode", severity=SEV_WARN,
                        title=f"{pkg} enabled {access}",
                        app=pkg,
                        data={"added": True, "access": access,
                              "installer": installer_of(pkg)},
                    ))
                for pkg in old - set(pkgs):
                    self.ctx.emit(Event(
                        kind="threat.godmode", severity=SEV_NOTICE,
                        title=f"{pkg} no longer holds {access}",
                        app=pkg,
                        data={"added": False, "access": access},
                    ))
            old_cas = set(baseline.get("cas") or [])
            for fp in cas - old_cas:
                self.ctx.emit(Event(
                    kind="threat.ca", severity=SEV_WARN,
                    title="User CA certificate added",
                    detail=fp,
                    data={"added": True, "fingerprint": fp},
                ))
        await asyncio.to_thread(self.ctx.store.put_snapshot, _SNAPSHOT_KEY,
                                {**current, "cas": sorted(cas)})

        if adb_wifi == "1":
            self.ctx.emit(Event(
                kind="threat.adbwifi", severity=SEV_NOTICE,
                title="Wireless debugging is on",
                data={"on": True},
            ))

        # ---- interception trio: user CA + global proxy / custom private DNS ----
        proxy = (await adb.shell("settings get global http_proxy", timeout=10)).strip()
        pdns_mode = (await adb.shell("settings get global private_dns_mode", timeout=10)).strip()
        pdns_host = (await adb.shell("settings get global private_dns_specifier", timeout=10)).strip()
        proxy_set = proxy not in ("", "null", ":0")
        pdns_custom = pdns_mode == "hostname" and pdns_host not in ("", "null")
        self.ctx.state["proxy"] = proxy if proxy_set else None
        self.ctx.state["private_dns"] = pdns_host if pdns_custom else pdns_mode or None
        if cas and (proxy_set or pdns_custom):
            sig = f"{sorted(cas)[0]}|{proxy if proxy_set else pdns_host}"
            if sig not in self._mitm_flagged:
                self._mitm_flagged.add(sig)
                parts = [f"{len(cas)} user CA cert(s)"]
                if proxy_set:
                    parts.append(f"global proxy {proxy}")
                if pdns_custom:
                    parts.append(f"private DNS {pdns_host}")
                self.ctx.emit(Event(
                    kind="threat.mitm", severity=SEV_WARN,
                    title="Interception pattern: " + " + ".join(parts),
                    detail="Someone may be decrypting this device's traffic. "
                           "If you did not set this up yourself, investigate now.",
                    data={"signature": sig, "proxy": proxy if proxy_set else None,
                          "private_dns": pdns_host if pdns_custom else None,
                          "cas": sorted(cas)},
                ))

        # ---- stalkerware indicator matching ----
        if self._iocs:
            installed = set((self.ctx.state.get("apps") or {}).keys())
            for pkg in (installed & self._iocs) - self._ioc_flagged:
                self._ioc_flagged.add(pkg)
                self.ctx.emit(Event(
                    kind="threat.ioc", severity=SEV_WARN,
                    title=f"Stalkerware indicator: {pkg}",
                    app=pkg,
                    data={"source": "stalkerware-pkgs.txt"},
                ))
