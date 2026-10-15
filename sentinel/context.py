"""Shared application context handed to every collector and the API."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
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


@dataclass
class AppContext:
    cfg: Config
    bus: EventBus
    store: Store
    rules: RulesEngine
    adb: AdbClient | None
    maps: DeviceMaps | None
    hostnames: HostnameCache
    geoip: GeoIP
    trackers: TrackerMatcher
    device: dict[str, Any] = field(default_factory=dict)
    # live state the REST API serves directly
    state: dict[str, Any] = field(default_factory=lambda: {
        "started": time.time(),
        "transport": None,          # wifi | cellular | vpn | None
        "connections": 0,
        "camera_active": [],
        "telephony": {},
        "netstats": {},             # uid -> {wifi_rx, wifi_tx, mobile_rx, mobile_tx, app}
        "godmode": {},              # access type -> [pkg]
        "capture": False,           # tcpdump hostname capture running
        "demo": False,
    })

    def emit(self, ev: Event) -> None:
        """Publish from inside the event loop."""
        self.bus.publish(ev)

    def emit_threadsafe(self, ev: Event) -> None:
        """Publish from a reader thread."""
        self.bus.publish_threadsafe(ev)

    def app_for_uid(self, uid: int | None) -> str | None:
        if self.maps:
            return self.maps.app_for_uid(uid)
        return None
