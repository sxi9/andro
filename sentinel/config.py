"""Runtime configuration for Android Sentinel."""
from __future__ import annotations

import argparse
import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    # server
    host: str = "127.0.0.1"          # local-only by default; never expose the dashboard publicly
    port: int = 8765

    # device
    adb_path: str = "adb"
    serial: str | None = None        # adb -s <serial>; None = single attached device
    use_su: bool = True              # wrap privileged reads in `su -c`

    # modes
    demo: bool = False               # run with a simulated device (no adb needed)
    demo_devices: int = 2            # how many simulated devices in demo mode

    # polling cadences (seconds)
    poll_sensors: float = 1.5        # appops / camera service
    poll_net: float = 2.0            # /proc/net sockets
    poll_netstats: float = 15.0      # dumpsys netstats (wifi vs cellular byte counts)
    poll_packages: float = 60.0      # package inventory diff
    poll_threats: float = 30.0       # god-mode / CA / adb-wifi audit
    poll_radio: float = 10.0         # telephony registry (call state, cell identity)

    # capture
    tcpdump: bool = True             # stream DNS + TLS SNI via on-device tcpdump (needs root)
    tcpdump_path: str = "tcpdump"    # path of tcpdump binary on the device

    # storage / enrichment
    data_dir: Path = field(default_factory=lambda: Path.home() / ".android-sentinel")
    geoip_db: Path | None = None     # optional GeoLite2-City or -Country .mmdb
    asn_db: Path | None = None       # optional GeoLite2-ASN .mmdb

    # alerting
    egress_spike_mb_per_min: float = 10.0

    @property
    def db_path(self) -> Path:
        return self.data_dir / "sentinel.db"


def parse_args(argv: list[str] | None = None) -> Config:
    p = argparse.ArgumentParser(
        prog="android-sentinel",
        description="Local monitoring dashboard for your own rooted Android device (ADB, USB or wireless).",
    )
    p.add_argument("--host", default=os.environ.get("SENTINEL_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("SENTINEL_PORT", "8765")))
    p.add_argument("--serial", "-s", default=None, help="adb device serial (or host:port for wireless)")
    p.add_argument("--adb", dest="adb_path", default="adb", help="path to the adb binary")
    p.add_argument("--no-su", dest="use_su", action="store_false", help="device shell is not rooted / skip su")
    p.add_argument("--no-tcpdump", dest="tcpdump", action="store_false",
                   help="disable on-device packet capture (hostnames fall back to IP-only)")
    p.add_argument("--demo", action="store_true", help="run with simulated data, no device needed")
    p.add_argument("--demo-devices", type=int, default=2,
                   help="number of simulated devices in demo mode (default 2)")
    p.add_argument("--data-dir", type=Path, default=None)
    p.add_argument("--geoip-db", type=Path, default=None, help="optional GeoLite2 City/Country .mmdb file")
    p.add_argument("--asn-db", type=Path, default=None, help="optional GeoLite2 ASN .mmdb file")
    a = p.parse_args(argv)

    cfg = Config(
        host=a.host, port=a.port, serial=a.serial, adb_path=a.adb_path,
        use_su=a.use_su, tcpdump=a.tcpdump, demo=a.demo, demo_devices=a.demo_devices,
        geoip_db=a.geoip_db, asn_db=a.asn_db,
    )
    if a.data_dir:
        cfg.data_dir = a.data_dir
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    return cfg
