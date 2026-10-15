"""Streaming pcap parser for `tcpdump -U -w -` piped over `adb exec-out`.

Extracts exactly two things, both WITHOUT any decryption:
  - DNS answers      → ip  → hostname   (what name resolved to this address)
  - TLS ClientHello  → SNI → hostname   (what name this HTTPS flow is for)

Handles Ethernet, Linux cooked v1 (SLL, what `-i any` produces) and v2 (SLL2),
and raw-IP link types, IPv4 and IPv6. Truncated packets (snaplen) parse as far
as the bytes allow and are then dropped silently.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_A = 12
LINKTYPE_RAW_B = 101
LINKTYPE_SLL = 113
LINKTYPE_SLL2 = 276

_MAGICS = {
    0xA1B2C3D4: ">", 0xD4C3B2A1: "<",   # microsecond pcap
    0xA1B23C4D: ">", 0x4D3CB2A1: "<",   # nanosecond pcap
}


@dataclass
class L4Packet:
    proto: str      # 'tcp' | 'udp'
    src: str
    dst: str
    sport: int
    dport: int
    payload: bytes


def _ip_str(raw: bytes) -> str:
    if len(raw) == 4:
        return ".".join(str(b) for b in raw)
    import ipaddress
    return str(ipaddress.IPv6Address(raw))


class PcapStream:
    """Feed raw bytes as they arrive; collect parsed L4 packets."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self._endian: str | None = None
        self._linktype: int = LINKTYPE_ETHERNET

    def feed(self, data: bytes) -> list[L4Packet]:
        self._buf.extend(data)
        out: list[L4Packet] = []

        if self._endian is None:
            if len(self._buf) < 24:
                return out
            magic = struct.unpack(">I", self._buf[:4])[0]
            endian = _MAGICS.get(magic)
            if endian is None:
                # not a pcap stream; drop a byte to resync (defensive)
                del self._buf[0]
                return out
            self._endian = endian
            self._linktype = struct.unpack(endian + "I", self._buf[20:24])[0]
            del self._buf[:24]

        while True:
            if len(self._buf) < 16:
                break
            _ts, _tus, incl, _orig = struct.unpack(self._endian + "IIII", self._buf[:16])
            if incl > 262144:   # corrupt length: resync by clearing
                self._buf.clear()
                break
            if len(self._buf) < 16 + incl:
                break
            frame = bytes(self._buf[16:16 + incl])
            del self._buf[:16 + incl]
            pkt = self._parse_frame(frame)
            if pkt:
                out.append(pkt)
        return out

    # ---- link layer ----
    def _parse_frame(self, frame: bytes) -> L4Packet | None:
        lt = self._linktype
        if lt == LINKTYPE_ETHERNET:
            if len(frame) < 14:
                return None
            eth = struct.unpack(">H", frame[12:14])[0]
            off = 14
            if eth == 0x8100 and len(frame) >= 18:     # 802.1Q VLAN
                eth = struct.unpack(">H", frame[16:18])[0]
                off = 18
            if eth not in (0x0800, 0x86DD):
                return None
            return self._parse_ip(frame[off:])
        if lt == LINKTYPE_SLL:
            if len(frame) < 16:
                return None
            eth = struct.unpack(">H", frame[14:16])[0]
            if eth not in (0x0800, 0x86DD):
                return None
            return self._parse_ip(frame[16:])
        if lt == LINKTYPE_SLL2:
            if len(frame) < 20:
                return None
            eth = struct.unpack(">H", frame[0:2])[0]
            if eth not in (0x0800, 0x86DD):
                return None
            return self._parse_ip(frame[20:])
        if lt in (LINKTYPE_RAW_A, LINKTYPE_RAW_B):
            return self._parse_ip(frame)
        return None

    # ---- network layer ----
    def _parse_ip(self, b: bytes) -> L4Packet | None:
        if not b:
            return None
        ver = b[0] >> 4
        if ver == 4:
            if len(b) < 20:
                return None
            ihl = (b[0] & 0x0F) * 4
            proto = b[9]
            src, dst = _ip_str(b[12:16]), _ip_str(b[16:20])
            return self._parse_l4(proto, src, dst, b[ihl:])
        if ver == 6:
            if len(b) < 40:
                return None
            nxt = b[6]
            src, dst = _ip_str(b[8:24]), _ip_str(b[24:40])
            off = 40
            # skip common extension headers
            while nxt in (0, 43, 60) and len(b) >= off + 8:
                nxt2 = b[off]
                off += (b[off + 1] + 1) * 8
                nxt = nxt2
            return self._parse_l4(nxt, src, dst, b[off:])
        return None

    # ---- transport layer ----
    @staticmethod
    def _parse_l4(proto: int, src: str, dst: str, b: bytes) -> L4Packet | None:
        if proto == 17:  # UDP
            if len(b) < 8:
                return None
            sp, dp = struct.unpack(">HH", b[:4])
            return L4Packet("udp", src, dst, sp, dp, b[8:])
        if proto == 6:   # TCP
            if len(b) < 20:
                return None
            sp, dp = struct.unpack(">HH", b[:4])
            doff = (b[12] >> 4) * 4
            if doff < 20 or len(b) < doff:
                return None
            return L4Packet("tcp", src, dst, sp, dp, b[doff:])
        return None


# -------------------- DNS --------------------

def _read_name(msg: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    """Read a (possibly compressed) DNS name. Returns (name, new_pos)."""
    if depth > 10:
        return "", pos
    labels: list[str] = []
    jumped = False
    end = pos
    guard = 0
    while guard < 128:
        guard += 1
        if pos >= len(msg):
            break
        ln = msg[pos]
        if ln == 0:
            pos += 1
            break
        if ln & 0xC0 == 0xC0:
            if pos + 1 >= len(msg):
                break
            ptr = ((ln & 0x3F) << 8) | msg[pos + 1]
            if not jumped:
                end = pos + 2
            if ptr >= len(msg):
                break
            pos = ptr
            jumped = True
            depth += 1
            if depth > 10:
                break
            continue
        if pos + 1 + ln > len(msg):
            break
        labels.append(msg[pos + 1:pos + 1 + ln].decode("ascii", "replace"))
        pos += 1 + ln
    if not jumped:
        end = pos
    return ".".join(labels), end


def parse_dns_answers(payload: bytes) -> tuple[str, set[str]] | None:
    """For a DNS *response*, return (query_name, {answer IPs}). None otherwise."""
    if len(payload) < 12:
        return None
    flags, qd, an = struct.unpack(">HHH", payload[2:8])
    if not flags & 0x8000 or an == 0:
        return None
    pos = 12
    qname = ""
    for _ in range(min(qd, 4)):
        qname, pos = _read_name(payload, pos)
        pos += 4
    if not qname or pos > len(payload):
        return None
    ips: set[str] = set()
    for _ in range(min(an, 32)):
        _name, pos = _read_name(payload, pos)
        if pos + 10 > len(payload):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", payload[pos:pos + 10])
        pos += 10
        if pos + rdlen > len(payload):
            break
        if rtype == 1 and rdlen == 4:
            ips.add(_ip_str(payload[pos:pos + 4]))
        elif rtype == 28 and rdlen == 16:
            ips.add(_ip_str(payload[pos:pos + 16]))
        pos += rdlen
    if not ips:
        return None
    return qname.lower(), ips


# -------------------- TLS SNI --------------------

def extract_sni(payload: bytes) -> str | None:
    """Pull the server_name from a TLS ClientHello, if this payload starts one."""
    # TLS record: type(1)=0x16 handshake, version(2), length(2)
    if len(payload) < 9 or payload[0] != 0x16:
        return None
    # handshake header: type(1)=0x01 ClientHello, length(3)
    if payload[5] != 0x01:
        return None
    pos = 9          # skip record hdr(5) + hs type(1) + hs len(3)
    pos += 2 + 32    # client_version + random
    if pos + 1 > len(payload):
        return None
    sid_len = payload[pos]
    pos += 1 + sid_len
    if pos + 2 > len(payload):
        return None
    cs_len = struct.unpack(">H", payload[pos:pos + 2])[0]
    pos += 2 + cs_len
    if pos + 1 > len(payload):
        return None
    comp_len = payload[pos]
    pos += 1 + comp_len
    if pos + 2 > len(payload):
        return None
    ext_total = struct.unpack(">H", payload[pos:pos + 2])[0]
    pos += 2
    end = min(pos + ext_total, len(payload))
    while pos + 4 <= end:
        etype, elen = struct.unpack(">HH", payload[pos:pos + 4])
        pos += 4
        if etype == 0:  # server_name
            if pos + 5 > len(payload):
                return None
            # list length(2), entry type(1)=0 hostname, name length(2)
            name_len = struct.unpack(">H", payload[pos + 3:pos + 5])[0]
            if pos + 5 + name_len > len(payload):
                return None
            try:
                return payload[pos + 5:pos + 5 + name_len].decode("ascii").lower()
            except UnicodeDecodeError:
                return None
        pos += elen
    return None
