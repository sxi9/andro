"""Demo mode: a simulated device feeding the real pipeline (bus → rules →
store → WebSocket), so the dashboard runs end-to-end with no phone attached.
Everything it emits is clearly marked demo in /api/status.
"""
from __future__ import annotations

import asyncio
import random

from ..core.events import Event, SEV_INFO, SEV_NOTICE, SEV_WARN
from .base import Collector

APPS = [
    ("com.whatsapp", 10155), ("com.instagram.android", 10203),
    ("com.facebook.katana", 10118), ("com.zhiliaoapp.musically", 10307),
    ("com.android.chrome", 10091), ("com.spotify.music", 10164),
    ("com.google.android.gms", 10012), ("com.wx.weatherpro", 10412),
    ("com.led.qrflash", 10501),
]
DESTS = [
    ("graph.facebook.com", "157.240.221.35", "Meta Platforms", "Ireland", "IE", None),
    ("mtalk.google.com", "142.250.74.206", "Google LLC", "United States", "US", None),
    ("e2.whatsapp.net", "157.240.19.60", "Meta Platforms", "Ireland", "IE", None),
    ("analytics.tiktok.com", "161.117.9.20", "Alibaba (ByteDance)", "Singapore", "SG", None),
    ("wd.a.appsflyer.com", "18.196.4.90", "Amazon AWS", "Germany", "DE", "AppsFlyer"),
    ("sdk.ironsrc.mobi", "34.117.59.81", "Google Cloud", "United States", "US", "ironSource"),
    ("mc.yandex.ru", "77.88.21.11", "Yandex", "Russia", "RU", "Yandex Metrica"),
    ("scontent.cdninstagram.com", "157.240.253.63", "Meta CDN", "United States", "US", None),
]
OPS = [("RECORD_AUDIO", "sensor.mic", "microphone"), ("CAMERA", "sensor.cam", "camera"),
       ("FINE_LOCATION", "sensor.loc", "location"), ("READ_CLIPBOARD", "sensor.clip", "clipboard")]
TAGS = ["ActivityManager", "CameraService", "AppOps", "ConnectivityService",
        "audio_hw", "PackageManager", "WindowManager", "NetworkStack"]


class DemoCollector(Collector):
    name = "demo"

    async def run(self) -> None:
        ctx = self.ctx
        ctx.state["demo"] = True
        ctx.state["transport"] = "wifi"
        ctx.device.update({"connected": True, "model": "Pixel 7 (demo)",
                           "android": "14", "sdk": "34", "root": True,
                           "manufacturer": "Google", "serial": "demo",
                           "wireless": False})
        ctx.state["godmode"] = {
            "accessibility": ["com.led.qrflash"],
            "notification listener": ["com.facebook.katana"],
            "device admin": ["com.wx.weatherpro"],
        }
        ctx.state["apps"] = {
            pkg: {"uid": uid, "installer": "com.android.vending" if pkg != "com.led.qrflash" else None,
                  "version": 100 + i, "version_name": f"1.{i}", "sig": "deadbeef",
                  "system": False,
                  "requested": ["android.permission.INTERNET", "android.permission.CAMERA"],
                  "granted": ["android.permission.INTERNET"]
                  + (["android.permission.RECORD_AUDIO", "android.permission.READ_SMS"]
                     if pkg in ("com.led.qrflash", "com.wx.weatherpro") else []),
                  "last_update": "2026-10-01 10:00:00"}
            for i, (pkg, uid) in enumerate(APPS)
        }
        ctx.state["storage"] = {
            "apps": {pkg: {"app": (12 + i * 3) * 1024 * 1024,
                           "data": (20 + i * 11) * 1024 * 1024,
                           "cache": (3 + i) * 1024 * 1024}
                     for i, (pkg, uid) in enumerate(APPS)},
            "totals": {"data_free": 18 * 1024 ** 3, "cache_free": 2 * 1024 ** 3},
        }
        # a couple of one-shot scripted findings so the alerts tab has substance
        scripted = [
            Event(kind="threat.godmode", severity=SEV_WARN,
                  title="com.led.qrflash enabled accessibility",
                  app="com.led.qrflash",
                  data={"added": True, "access": "accessibility", "installer": None}),
            Event(kind="threat.ca", severity=SEV_WARN, title="User CA certificate added",
                  detail="9a3bf1e2.0", data={"added": True, "fingerprint": "9a3bf1e2.0",
                                             "subject": "CN=DemoProxy Root"}),
            Event(kind="app.install", severity=SEV_NOTICE,
                  title="App installed: com.led.qrflash", app="com.led.qrflash",
                  data={"installer": None}),
        ]
        await asyncio.sleep(1.0)
        for ev in scripted:
            ctx.emit(ev)
            await asyncio.sleep(0.2)

        tick = 0
        while True:
            tick += 1
            self._net_event()
            if tick % 3 == 0:
                self._sensor_event()
            if tick % 5 == 0:
                self._log_event()
            if tick % 12 == 0:
                self._radio_event()
            if tick % 20 == 0:
                self._stats_event(tick)
            ctx.state["connections"] = random.randint(28, 55)
            await asyncio.sleep(random.uniform(1.5, 3.2))

    def _net_event(self) -> None:
        pkg, uid = random.choice(APPS)
        host, ip, org, country, cc, tracker = random.choice(DESTS)
        self.ctx.hostnames.put(ip, host, "dns")
        self.ctx.emit(Event(
            kind="net.conn", severity=SEV_NOTICE if tracker else SEV_INFO,
            title=f"{pkg} → {host}",
            detail=f"{ip}:443 · {org} · {cc}" + (f" · tracker: {tracker}" if tracker else ""),
            app=pkg, uid=uid,
            data={"ip": ip, "port": 443, "proto": "tcp", "host": host, "org": org,
                  "country": country, "country_code": cc, "tracker": tracker,
                  "transport": random.choice(["wifi", "wifi", "cellular"])},
        ))

    def _sensor_event(self) -> None:
        pkg, uid = random.choice(APPS)
        op, kind, label = random.choice(OPS)
        background = random.random() < 0.3
        self.ctx.emit(Event(
            kind=kind,
            severity=SEV_WARN if background and kind in ("sensor.mic", "sensor.cam") else (
                SEV_NOTICE if background else SEV_INFO),
            title=f"{pkg} used {label}",
            detail=("background" if background else "foreground")
                   + f", {random.randint(1, 20)}s",
            app=pkg, uid=uid,
            data={"op": op, "background": background, "source": "appops",
                  "duration": random.randint(1, 20)},
        ))
        if kind == "sensor.cam" and not background:
            self.ctx.state["camera_active"] = [pkg]
        else:
            self.ctx.state["camera_active"] = []

    def _log_event(self) -> None:
        pkg, uid = random.choice(APPS)
        level = random.choice(["I", "I", "I", "W", "E"])
        self.ctx.emit(Event(
            kind="log.line",
            severity={"W": SEV_NOTICE, "E": SEV_WARN}.get(level, SEV_INFO),
            title=random.choice(TAGS),
            detail=random.choice([
                f"Start proc {random.randint(2000, 30000)}:{pkg}/u0a{uid % 1000}",
                f"NetworkRequest from {pkg} type INTERNET",
                "input stream opened sr=48000 src=MIC",
                f"Note op FINE_LOCATION from uid {uid}",
                "avc: denied { read } scontext=u:r:untrusted_app",
            ]),
            app=pkg, uid=uid,
            data={"level": level, "tag": random.choice(TAGS), "pid": random.randint(1000, 30000),
                  "buffer": "sys", "t": ""},
        ))

    def _radio_event(self) -> None:
        nt = random.choice(["LTE", "LTE", "LTE", "NR", "HSPAP"])
        cell = {"ci": random.choice([104231, 104232, 88412]), "tac": 5021}
        self.ctx.state["telephony"] = {"call_state": "idle", "network_type": nt,
                                       "cell": cell, "operator": "DemoCell"}
        self.ctx.emit(Event(
            kind="radio.cell", severity=SEV_INFO,
            title=f"Network type: {nt}",
            detail=f"cell ci={cell['ci']} tac={cell['tac']}",
            data={"network_type": nt, "cell": cell},
        ))

    def _stats_event(self, tick: int) -> None:
        per_uid = {}
        for i, (pkg, uid) in enumerate(APPS):
            base = (i + 1) * 3_000_000 + tick * random.randint(10_000, 600_000)
            per_uid[str(uid)] = {"app": pkg, "rx": base * 3, "tx": base,
                                 "wrx": int(base * 2.1), "wtx": int(base * 0.6),
                                 "mrx": int(base * 0.9), "mtx": int(base * 0.4)}
        self.ctx.state["netstats"] = per_uid
        self.ctx.emit(Event(kind="net.stats", severity=SEV_INFO,
                            title="data usage refreshed", detail=f"{len(per_uid)} apps",
                            data={"per_uid": per_uid}))
