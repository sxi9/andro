"""On-device tcpdump → host: DNS answers and TLS ClientHello SNI, no decryption.

Runs `tcpdump -w -` on the device via `adb exec-out` and parses the pcap
stream incrementally. The BPF filter keeps volume tiny: DNS (both IP
families) plus IPv4 TLS handshake records only. IPv6 HTTPS flows still get
hostnames from their DNS lookups.

Needs root and a tcpdump binary on the device; degrades to IP-only
monitoring when either is missing.
"""
from __future__ import annotations

import asyncio
import time

from ..core.events import Event, SEV_INFO, SEV_NOTICE
from ..parsers.pcap import PcapStream, extract_sni, parse_dns_answers
from .base import Collector

_FILTER = ("(udp port 53) or "
           "(tcp port 443 and tcp[((tcp[12] & 0xf0) >> 2)] = 0x16)")


class CaptureCollector(Collector):
    name = "capture"

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self._new_domains: dict[str, float] = {}

    async def run(self) -> None:
        cfg = self.ctx.cfg
        adb = self.ctx.adb
        assert adb is not None
        if not cfg.tcpdump:
            return
        # Probe until the capability appears: the server may start before the
        # device is plugged in, so a failed probe backs off and retries rather
        # than disabling hostname capture for the whole session.
        announced = False
        probe_backoff = 5.0
        while True:
            ok_root = await asyncio.to_thread(adb.has_root)
            ok_bin = ok_root and await asyncio.to_thread(adb.has_binary, cfg.tcpdump_path)
            if ok_root and ok_bin:
                break
            self.ctx.state["capture"] = False
            if not announced:
                announced = True
                self.ctx.emit(Event(
                    kind="log.line", severity=SEV_NOTICE, title="hostname capture off",
                    detail="tcpdump or root unavailable on the device — destinations will "
                           "show as IPs until it appears. Push a static tcpdump binary "
                           "to enable hostnames.",
                    data={"level": "W", "tag": "sentinel", "buffer": "sys"},
                ))
            await asyncio.sleep(probe_backoff)
            probe_backoff = min(probe_backoff * 2, 120.0)

        # Keep retrying forever with backoff: a USB unplug or reboot must not
        # permanently disable hostname capture for the rest of the session.
        backoff = 3.0
        while True:
            # snaplen 4096: current Chrome/Android ClientHellos carry a
            # post-quantum key_share (~1.2KB+), overflowing a 1024 snap and
            # losing the SNI; the BPF filter keeps volume tiny regardless
            cmd = (f"{cfg.tcpdump_path} -i any -s 4096 -U -n -w - '{_FILTER}'")
            started = time.time()
            try:
                proc = adb.popen_raw(cmd, su=True)
                self.ctx.state["capture"] = True
                self.log.info("tcpdump hostname capture attached")
                try:
                    await asyncio.to_thread(self._pump, proc)
                finally:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            except Exception as e:
                self.log.warning("tcpdump start failed: %s", e)
            self.ctx.state["capture"] = False
            if time.time() - started > 60:
                backoff = 3.0          # it ran fine for a while; retry quickly
            else:
                backoff = min(backoff * 2, 120.0)
                self.log.info("capture exited fast; retrying in %.0fs", backoff)
            await asyncio.sleep(backoff)

    def _pump(self, proc) -> None:
        stream = PcapStream()
        assert proc.stdout is not None
        while True:
            chunk = proc.stdout.read(4096)
            if not chunk:
                break
            for pkt in stream.feed(chunk):
                if pkt.proto == "udp" and pkt.sport == 53:
                    res = parse_dns_answers(pkt.payload)
                    if res:
                        qname, ips = res
                        for ip in ips:
                            self.ctx.hostnames.put(ip, qname, "dns")
                        self._maybe_announce(qname)
                elif pkt.proto == "tcp" and pkt.dport == 443:
                    sni = extract_sni(pkt.payload)
                    if sni:
                        self.ctx.hostnames.put(pkt.dst, sni, "sni")
                        self._maybe_announce(sni)

    def _maybe_announce(self, name: str) -> None:
        """Emit a low-key event the first time a domain is seen this session."""
        now = time.time()
        if name in self._new_domains:
            return
        if len(self._new_domains) > 5000:
            self._new_domains.clear()
        self._new_domains[name] = now
        tracker = self.ctx.trackers.match(name)
        self.ctx.emit_threadsafe(Event(
            kind="net.dns",
            severity=SEV_NOTICE if tracker else SEV_INFO,
            title=f"domain observed: {name}",
            detail=f"tracker: {tracker}" if tracker else "",
            data={"qname": name, "tracker": tracker},
        ))
