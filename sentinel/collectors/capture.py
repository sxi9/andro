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
        ok_root = await asyncio.to_thread(adb.has_root)
        ok_bin = await asyncio.to_thread(adb.has_binary, cfg.tcpdump_path)
        if not (ok_root and ok_bin):
            self.ctx.state["capture"] = False
            self.ctx.emit(Event(
                kind="log.line", severity=SEV_NOTICE, title="hostname capture off",
                detail="tcpdump or root unavailable on the device — destinations will "
                       "show as IPs. Push a static tcpdump binary to enable hostnames.",
                data={"level": "W", "tag": "sentinel", "buffer": "sys"},
            ))
            return

        failures = 0
        while failures < 4:
            cmd = (f"{cfg.tcpdump_path} -i any -s 1024 -U -n -w - '{_FILTER}'")
            try:
                proc = adb.popen_raw(cmd, su=True)
            except Exception as e:
                self.log.warning("tcpdump start failed: %s", e)
                failures += 1
                await asyncio.sleep(5)
                continue
            self.ctx.state["capture"] = True
            self.log.info("tcpdump hostname capture attached")
            started = time.time()
            try:
                await asyncio.to_thread(self._pump, proc)
            finally:
                try:
                    proc.kill()
                except Exception:
                    pass
            self.ctx.state["capture"] = False
            failures = 0 if time.time() - started > 60 else failures + 1
            await asyncio.sleep(3)
        self.log.warning("tcpdump keeps dying; hostname capture disabled")

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
