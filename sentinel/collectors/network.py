"""Live connection tracking: /proc/net sockets → UID → package, enriched with
hostname (DNS/SNI cache), GeoIP and tracker matching.

Transport (wifi / cellular / vpn) is read from the default route's interface:
wlan* = wifi, rmnet*/ccmni* = cellular, tun* = vpn. On-device capture sees all
of them identically; this label just tells you which path the bytes took.
"""
from __future__ import annotations

import time

from ..core.events import Event, SEV_INFO, SEV_NOTICE
from ..parsers.procnet import is_private, parse_proc_net
from .base import Collector

_SEEN_TTL = 600.0  # re-announce a (uid, ip, port) at most every 10 min


def transport_for_iface(iface: str | None) -> str | None:
    if not iface:
        return None
    if iface.startswith(("wlan", "eth", "ap")):
        return "wifi"
    if iface.startswith(("rmnet", "ccmni", "v4-rmnet", "clat", "umts", "pdp")):
        return "cellular"
    if iface.startswith(("tun", "ppp", "wg")):
        return "vpn"
    return None


class NetworkCollector(Collector):
    name = "network"

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self._seen: dict[tuple, float] = {}

    async def run(self) -> None:
        await self.poll_loop(self.ctx.cfg.poll_net, self._poll)

    async def _detect_transport(self) -> str | None:
        adb = self.ctx.adb
        assert adb is not None
        try:
            out = await adb.shell("ip route get 8.8.8.8 2>/dev/null | head -1", timeout=8)
            iface = None
            toks = out.split()
            if "dev" in toks:
                iface = toks[toks.index("dev") + 1]
            return transport_for_iface(iface)
        except Exception:
            return None

    async def _poll(self) -> None:
        adb = self.ctx.adb
        assert adb is not None
        now = time.time()

        transport = await self._detect_transport()
        if transport:
            self.ctx.state["transport"] = transport

        tcp_txt = await adb.shell("cat /proc/net/tcp /proc/net/tcp6 2>/dev/null",
                                  su=True, timeout=12)
        udp_txt = await adb.shell("cat /proc/net/udp /proc/net/udp6 2>/dev/null",
                                  su=True, timeout=12)
        socks = parse_proc_net(tcp_txt, "tcp") + parse_proc_net(udp_txt, "udp")
        self.ctx.state["connections"] = len(socks)

        # purge stale dedupe entries
        if len(self._seen) > 20000:
            self._seen = {k: t for k, t in self._seen.items() if now - t < _SEEN_TTL}

        for s in socks:
            if is_private(s.remote_ip):
                continue
            key = (s.uid, s.remote_ip, s.remote_port, s.proto)
            if now - self._seen.get(key, 0.0) < _SEEN_TTL:
                self._seen[key] = now
                continue
            self._seen[key] = now

            app = self.ctx.app_for_uid(s.uid) or f"uid:{s.uid}"
            host = self.ctx.hostnames.get(s.remote_ip)
            geo = self.ctx.geoip.lookup(s.remote_ip) if self.ctx.geoip.enabled else {}
            tracker = self.ctx.trackers.match(host)
            where = host or s.remote_ip
            org = geo.get("org")
            cc = geo.get("country_code")
            sev = SEV_NOTICE if tracker else SEV_INFO
            self.ctx.emit(Event(
                kind="net.conn", severity=sev,
                title=f"{app} → {where}",
                detail=":".join((s.remote_ip, str(s.remote_port)))
                       + (f" · {org}" if org else "")
                       + (f" · {cc}" if cc else "")
                       + (f" · tracker: {tracker}" if tracker else ""),
                app=app if not app.startswith("uid:") else None,
                uid=s.uid,
                data={
                    "ip": s.remote_ip, "port": s.remote_port, "proto": s.proto,
                    "host": host, "org": org, "country": geo.get("country"),
                    "country_code": cc, "city": geo.get("city"),
                    "tracker": tracker, "transport": transport,
                },
            ))
