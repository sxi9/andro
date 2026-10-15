"""Alert rules engine.

Watches the unified event stream and raises alerts for the patterns that
actually matter on a personal device. The detections encode the common
spyware / stalkerware shapes:

- background mic / camera use, and background sensor use followed by egress
- a new user CA certificate (someone preparing to MITM the owner)
- a new god-mode grant (accessibility, device admin, notification access)
- a sideloaded app holding god-mode access
- traffic to a country never seen before for that app, cleartext egress
- a changed APK signer across an update (repackaged app)
- silently added dangerous permissions, SMS+INTERNET combos
- wireless debugging left enabled (the monitoring path itself is a surface)
- cellular network-type downgrade to 2G (possible fake base station)
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from .events import Event, SEV_CRIT, SEV_NOTICE, SEV_WARN

DANGEROUS_PERMS = {
    "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS", "android.permission.READ_CALL_LOG",
    "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
}

# Allowlist, not denylist: the installer string is attacker-influenced (any app
# can name itself whatever it wants and stalkerware ships via pm/adb installs
# that report arbitrary or missing installers). Anything not provably from a
# trusted store counts as sideloaded. "(system)" marks preinstalled packages.
TRUSTED_INSTALLERS = {"com.android.vending", "com.sec.android.app.samsungapps", "(system)"}


def is_sideloaded(installer: str | None) -> bool:
    return installer not in TRUSTED_INSTALLERS
TWO_G = {"GPRS", "EDGE", "GSM", "CDMA", "1xRTT", "IDEN"}
FAST_G = {"LTE", "LTE_CA", "NR", "NR_SA", "NR_NSA", "HSPAP", "HSPA", "UMTS"}


@dataclass
class Rule:
    id: str
    name: str
    severity: str
    description: str
    enabled: bool = True
    cooldown: float = 600.0  # seconds between repeat fires of the same (rule, key)


@dataclass
class RulesEngine:
    egress_spike_mb_per_min: float = 10.0
    on_alert: Callable[[Event], None] | None = None  # wired by the app

    rules: dict[str, Rule] = field(default_factory=dict)
    _last_fire: dict[tuple[str, str], float] = field(default_factory=dict)
    _seen_country: set[tuple[str, str]] = field(default_factory=set)   # (app, country)
    _recent_bg_sensor: dict[int, float] = field(default_factory=dict)  # uid -> ts
    _last_net_type: str | None = None
    _prev_stats: dict[int, tuple[float, float]] = field(default_factory=dict)  # uid -> (ts, tx_bytes)

    def __post_init__(self) -> None:
        for r in [
            Rule("bg_mic_cam", "Background mic / camera use", SEV_CRIT,
                 "An app used the microphone or camera while not on screen."),
            Rule("bg_location", "Background location access", SEV_WARN,
                 "An app read your location from the background.", cooldown=1800),
            Rule("bg_clipboard", "Background clipboard read", SEV_WARN,
                 "An app read the clipboard while not focused."),
            Rule("sensor_then_egress", "Background recording followed by upload", SEV_CRIT,
                 "The same app used mic/camera in the background and then sent data out within 2 minutes."),
            Rule("new_user_ca", "New user CA certificate", SEV_CRIT,
                 "A certificate authority was added to the user trust store. "
                 "This can let someone decrypt your HTTPS traffic.", cooldown=0),
            Rule("new_godmode", "New god-mode grant", SEV_CRIT,
                 "Accessibility, device-admin or notification access was newly enabled.", cooldown=0),
            Rule("sideload_godmode", "Sideloaded app with god-mode access", SEV_CRIT,
                 "An app installed outside the Play Store holds accessibility or notification access — "
                 "the classic stalkerware shape.", cooldown=0),
            Rule("new_dest_country", "New destination country", SEV_WARN,
                 "An app contacted a country it has never contacted before.", cooldown=3600),
            Rule("cleartext", "Cleartext egress", SEV_WARN,
                 "Unencrypted traffic (port 80/21/23) left the device.", cooldown=1800),
            Rule("tracker_endpoint", "Known tracker endpoint", SEV_NOTICE,
                 "Traffic to a known advertising / analytics endpoint.", cooldown=3600),
            Rule("sideload_install", "App sideloaded", SEV_WARN,
                 "An app was installed from outside the Play Store.", cooldown=0),
            Rule("signer_changed", "APK signer changed on update", SEV_CRIT,
                 "An app's signing certificate changed across an update — possible repackaged app.",
                 cooldown=0),
            Rule("perm_added", "Dangerous permission newly granted", SEV_WARN,
                 "An existing app silently gained a dangerous permission.", cooldown=0),
            Rule("sms_combo", "SMS + internet on a non-messaging app", SEV_WARN,
                 "Can read one-time codes and exfiltrate them.", cooldown=0),
            Rule("egress_spike", "High data egress", SEV_NOTICE,
                 "An app is sending far more data than usual.", cooldown=1800),
            Rule("adb_wifi_on", "Wireless debugging left on", SEV_WARN,
                 "Wireless ADB is an attack surface. Turn it off when you are done monitoring.",
                 cooldown=1800),
            Rule("net_downgrade", "Cellular downgraded to 2G", SEV_WARN,
                 "The connection dropped from LTE/5G to 2G, which disables modern encryption — "
                 "can indicate a fake base station.", cooldown=900),
            Rule("stalkerware_ioc", "Known stalkerware package", SEV_CRIT,
                 "An installed package matches a stalkerware indicator list "
                 "(see data dir stalkerware-pkgs.txt).", cooldown=0),
            Rule("mitm_trio", "Interception pattern: user CA + redirected traffic", SEV_CRIT,
                 "A user CA certificate combined with a global proxy or custom private DNS "
                 "is the classic setup for decrypting the owner's traffic.", cooldown=0),
        ]:
            self.rules[r.id] = r

    # ---- rule state import/export (persisted by the app) ----
    def enabled_map(self) -> dict[str, bool]:
        return {rid: r.enabled for rid, r in self.rules.items()}

    def apply_enabled_map(self, m: dict[str, bool]) -> None:
        for rid, on in (m or {}).items():
            if rid in self.rules:
                self.rules[rid].enabled = bool(on)

    def set_enabled(self, rule_id: str, on: bool) -> bool:
        if rule_id not in self.rules:
            return False
        self.rules[rule_id].enabled = on
        return True

    def seed_seen_countries(self, pairs: list[list[str]] | None) -> None:
        for p in pairs or []:
            if len(p) == 2:
                self._seen_country.add((p[0], p[1]))

    def export_seen_countries(self) -> list[list[str]]:
        return [list(p) for p in self._seen_country]

    # ---- core ----
    def _fire(self, rule_id: str, key: str, title: str, detail: str,
              app: str | None, data: dict) -> Event | None:
        rule = self.rules.get(rule_id)
        if rule is None or not rule.enabled:
            return None
        now = time.time()
        k = (rule_id, key)
        if rule.cooldown and now - self._last_fire.get(k, 0.0) < rule.cooldown:
            return None
        self._last_fire[k] = now
        ev = Event(kind="alert", severity=rule.severity, title=title, detail=detail,
                   app=app, data={"rule": rule_id, **data})
        if self.on_alert:
            self.on_alert(ev)
        return ev

    def handle(self, ev: Event) -> list[Event]:
        """Feed one event; returns any alerts raised (also sent via on_alert)."""
        if ev.kind == "alert":
            return []
        out: list[Event] = []

        def fire(rule_id: str, key: str, title: str, detail: str, data: dict | None = None) -> None:
            a = self._fire(rule_id, key, title, detail, ev.app, data or {})
            if a:
                out.append(a)

        app = ev.app or "?"

        # --- sensors ---
        # a Reject entry means the OS BLOCKED the attempt: nothing was
        # recorded, so it must not raise "was used in the background"
        rejected = bool(ev.data.get("rejected"))
        if ev.kind in ("sensor.mic", "sensor.cam") and ev.data.get("background") \
                and not rejected:
            if ev.uid is not None:
                self._recent_bg_sensor[ev.uid] = ev.ts
            what = "microphone" if ev.kind == "sensor.mic" else "camera"
            fire("bg_mic_cam", f"{app}:{ev.kind}",
                 f"Background {what} use by {app}",
                 f"{app} accessed the {what} while not on screen.",
                 {"op": ev.data.get("op")})
        elif ev.kind == "sensor.loc" and ev.data.get("background") and not rejected:
            fire("bg_location", app, f"Background location access by {app}",
                 f"{app} read device location from the background.")
        elif ev.kind == "sensor.clip" and ev.data.get("background") and not rejected:
            fire("bg_clipboard", app, f"Background clipboard read by {app}",
                 f"{app} read the clipboard while not focused.")

        # --- network ---
        elif ev.kind == "net.conn":
            d = ev.data
            # correlation: background recording then egress on the same uid
            if ev.uid is not None:
                t0 = self._recent_bg_sensor.get(ev.uid)
                if t0 and ev.ts - t0 <= 120:
                    fire("sensor_then_egress", f"{app}",
                         f"{app}: background recording followed by upload",
                         f"{app} used a sensor in the background and connected to "
                         f"{d.get('host') or d.get('ip')} within 2 minutes.", {"ip": d.get("ip")})
            country = d.get("country")
            if country and ev.app:
                if (ev.app, country) not in self._seen_country:
                    known = any(a == ev.app for a, _ in self._seen_country)
                    self._seen_country.add((ev.app, country))
                    if known:  # only alert once a baseline exists for the app
                        fire("new_dest_country", f"{app}:{country}",
                             f"{app} contacted a new country: {country}",
                             f"Destination {d.get('host') or d.get('ip')} ({d.get('org') or 'unknown org'}) "
                             f"in {country} — first time for this app.", {"country": country})
            if d.get("port") in (80, 21, 23) and d.get("transport") != "vpn":
                fire("cleartext", f"{app}:{d.get('ip')}",
                     f"Cleartext traffic from {app}",
                     f"Unencrypted connection to {d.get('host') or d.get('ip')}:{d.get('port')}.")
            if d.get("tracker"):
                fire("tracker_endpoint", f"{app}:{d.get('tracker')}",
                     f"{app} → tracker {d.get('tracker')}",
                     f"Connected to known tracker endpoint {d.get('host') or d.get('ip')}.",
                     {"tracker": d.get("tracker")})

        elif ev.kind == "net.stats":
            now = ev.ts
            for uid_s, st in (ev.data.get("per_uid") or {}).items():
                try:
                    uid = int(uid_s)
                    tx = float(st.get("tx", 0))
                except (TypeError, ValueError):
                    continue
                prev = self._prev_stats.get(uid)
                self._prev_stats[uid] = (now, tx)
                if prev:
                    dt_min = max((now - prev[0]) / 60.0, 1e-6)
                    mb_per_min = max(tx - prev[1], 0) / 1e6 / dt_min
                    if mb_per_min >= self.egress_spike_mb_per_min:
                        fire("egress_spike", str(uid),
                             f"High egress: {st.get('app', uid)}",
                             f"Sending ~{mb_per_min:.1f} MB/min.", {"uid": uid})

        # --- packages ---
        elif ev.kind == "app.install":
            if is_sideloaded(ev.data.get("installer")):
                fire("sideload_install", app, f"Sideloaded app installed: {app}",
                     f"Installer: {ev.data.get('installer') or 'unknown (adb / file manager)'}.",
                     {"installer": ev.data.get("installer")})
        elif ev.kind == "app.update":
            if ev.data.get("signer_changed"):
                fire("signer_changed", app, f"Signer changed: {app}",
                     "The APK signing certificate is different from the previous version.")
        elif ev.kind == "app.perm":
            added = [p for p in (ev.data.get("added") or []) if p in DANGEROUS_PERMS]
            if added:
                fire("perm_added", f"{app}:{','.join(sorted(added))}",
                     f"{app} gained dangerous permissions",
                     "Newly granted: " + ", ".join(sorted(added)), {"added": added})

        # --- threats ---
        elif ev.kind == "threat.godmode":
            if ev.data.get("added"):
                kind = ev.data.get("access", "god-mode")
                fire("new_godmode", f"{app}:{kind}", f"{app} enabled {kind}",
                     f"{app} now holds {kind} access.", {"access": kind})
                if is_sideloaded(ev.data.get("installer")):
                    fire("sideload_godmode", f"{app}:{kind}",
                         f"Sideloaded app with {kind}: {app}",
                         "An app installed outside a trusted store holds god-mode access. "
                         "Investigate immediately.", {"access": kind})
        elif ev.kind == "threat.ca":
            if ev.data.get("added"):
                fire("new_user_ca", str(ev.data.get("fingerprint", "?")),
                     "New user CA certificate installed",
                     f"Subject: {ev.data.get('subject', 'unknown')}. "
                     "Someone may be preparing to intercept your HTTPS traffic.",
                     {"fingerprint": ev.data.get("fingerprint")})
        elif ev.kind == "threat.ioc":
            fire("stalkerware_ioc", app, f"Stalkerware indicator match: {app}",
                 f"Package {app} matches a known stalkerware indicator "
                 f"({ev.data.get('source', 'ioc list')}). Treat with care: removing it can "
                 "notify whoever installed it.", {"source": ev.data.get("source")})
        elif ev.kind == "threat.mitm":
            fire("mitm_trio", str(ev.data.get("signature", "mitm")),
                 "Traffic interception pattern detected",
                 ev.detail or "User CA certificate plus proxy / private DNS redirection.",
                 {"signature": ev.data.get("signature")})
        elif ev.kind == "threat.adbwifi":
            if ev.data.get("on"):
                fire("adb_wifi_on", "global", "Wireless debugging is enabled",
                     "Turn it off when you finish monitoring; it accepts connections over the network.")
        elif ev.kind == "threat.combo":
            if ev.data.get("combo") == "sms_internet":
                fire("sms_combo", app, f"{app} can read SMS and reach the internet",
                     "A non-messaging app with READ/RECEIVE_SMS + INTERNET can exfiltrate one-time codes.")

        # --- radio ---
        elif ev.kind == "radio.cell":
            nt = (ev.data.get("network_type") or "").upper()
            if nt:
                if self._last_net_type in FAST_G and nt in TWO_G:
                    fire("net_downgrade", "global",
                         f"Cellular downgraded: {self._last_net_type} → {nt}",
                         "2G lacks modern encryption and is the classic IMSI-catcher downgrade. "
                         "If you did not move out of coverage, be suspicious.",
                         {"from": self._last_net_type, "to": nt})
                self._last_net_type = nt

        return out
