"""Shared hub + per-device context.

A single Hub holds the things shared across every monitored device (config,
the event bus, the SQLite store, GeoIP and tracker databases, the backup
service). Each connected device gets its own DeviceContext with its own adb
client, uid/pid maps, rules engine, hostname cache and live state. Collectors
bind to one DeviceContext, and every Event it emits is stamped with that
device's adb serial.
"""
from __future__ import annotations

import time
from typing import Any

from .adb.client import AdbClient
from .adb.device import DeviceMaps
from .config import Config
from .core.bus import EventBus
from .core.events import Event
from .core.rules import RulesEngine
from .core.store import Store
from .enrich.geoip import GeoIP
from .enrich.hostnames import HostnameCache
from .enrich.trackers import TrackerMatcher


class SnapshotProxy:
    """Namespaces per-device baselines (packages, threats, countries) by serial,
    while delegating events/alerts straight through to the shared store."""

    def __init__(self, store: Store, prefix: str) -> None:
        self._store = store
        self._prefix = prefix

    def get_snapshot(self, key: str) -> Any:
        return self._store.get_snapshot(self._prefix + key)

    def put_snapshot(self, key: str, data: Any) -> None:
        self._store.put_snapshot(self._prefix + key, data)

    def __getattr__(self, name: str):  # add_event, add_alert, events, alerts, ...
        return getattr(self._store, name)


def _new_state() -> dict[str, Any]:
    return {
        "started": time.time(), "transport": None, "connections": 0,
        "camera_active": [], "telephony": {}, "netstats": {}, "godmode": {},
        "capture": False, "apps": {}, "storage": {},
    }


class DeviceContext:
    """One monitored device. Exposes the surface collectors expect (cfg, adb,
    maps, hostnames, geoip, trackers, store, state, device, emit...)."""

    def __init__(self, hub: "Hub", serial: str, *, demo: bool = False) -> None:
        self.hub = hub
        self.serial = serial
        self.demo = demo
        self.adb: AdbClient | None = None
        self.maps: DeviceMaps | None = None
        if not demo:
            self.adb = AdbClient(adb_path=hub.cfg.adb_path, serial=serial,
                                 use_su=hub.cfg.use_su)
            self.maps = DeviceMaps(self.adb)
        self.rules = RulesEngine(egress_spike_mb_per_min=hub.cfg.egress_spike_mb_per_min)
        self.rules.apply_enabled_map(hub.store.get_snapshot("rules_enabled") or {})
        self.rules.seed_seen_countries(self.store.get_snapshot("seen_countries"))
        self.hostnames = HostnameCache()
        self.device: dict[str, Any] = {"serial": serial, "connected": False}
        self.state: dict[str, Any] = _new_state()
        self.tasks: list = []  # asyncio tasks owned by this device

    # shared services
    @property
    def cfg(self) -> Config:
        return self.hub.cfg

    @property
    def bus(self) -> EventBus:
        return self.hub.bus

    @property
    def geoip(self) -> GeoIP:
        return self.hub.geoip

    @property
    def trackers(self) -> TrackerMatcher:
        return self.hub.trackers

    @property
    def store(self) -> SnapshotProxy:
        return SnapshotProxy(self.hub.store, f"{self.serial}:")

    # eventing (stamp the serial)
    def emit(self, ev: Event) -> None:
        ev.device = self.serial
        self.hub.bus.publish(ev)

    def emit_threadsafe(self, ev: Event) -> None:
        ev.device = self.serial
        self.hub.bus.publish_threadsafe(ev)

    def app_for_uid(self, uid: int | None) -> str | None:
        return self.maps.app_for_uid(uid) if self.maps else None

    def summary(self) -> dict[str, Any]:
        d = self.device
        return {
            "serial": self.serial,
            "model": d.get("model") or self.serial,
            "android": d.get("android"), "sdk": d.get("sdk"),
            "root": d.get("root"), "connected": d.get("connected", False),
            "transport": self.state.get("transport") or
            ("wireless" if ":" in self.serial else "usb"),
            "demo": self.demo,
            "open_alerts": len(self.hub.store.alerts(state="open", limit=500,
                                                     device=self.serial)),
            "connections": self.state.get("connections", 0),
            "capture": self.state.get("capture", False),
        }


# Collectors type-hint against this name.
AppContext = DeviceContext


class Hub:
    """Everything shared across devices, plus the live device registry."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.bus = EventBus()
        self.store = Store(cfg.db_path)
        self.geoip = GeoIP(cfg.geoip_db, cfg.asn_db)
        self.trackers = TrackerMatcher(cfg.data_dir / "trackers.txt")
        self.devices: dict[str, DeviceContext] = {}
        self.listing: list[dict] = []   # last `adb devices` incl. not-ready ones
        self.adb = None if cfg.demo else AdbClient(adb_path=cfg.adb_path, use_su=cfg.use_su)
        from .service.backup import BackupService
        self.backup = BackupService(self)

    def ready_devices(self) -> list[DeviceContext]:
        return [d for d in self.devices.values()]

    def default_serial(self) -> str | None:
        for s, d in self.devices.items():
            if d.device.get("connected"):
                return s
        return next(iter(self.devices), None)

    def resolve(self, serial: str | None) -> DeviceContext | None:
        if serial and serial in self.devices:
            return self.devices[serial]
        s = self.default_serial()
        return self.devices.get(s) if s else None
