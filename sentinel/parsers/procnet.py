"""Parse /proc/net/{tcp,tcp6,udp,udp6}: socket → remote endpoint + owning UID.

Addresses are hex, little-endian per 32-bit group. TCP state 01=ESTABLISHED,
02=SYN_SENT; we keep those (outbound-relevant) plus UDP sockets with a
non-zero remote.
"""
from __future__ import annotations

import ipaddress
import socket
import struct
from dataclasses import dataclass

TCP_KEEP_STATES = {"01", "02"}  # ESTABLISHED, SYN_SENT


@dataclass(frozen=True)
class Sock:
    proto: str         # tcp | udp
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    uid: int
    state: str


def _v4(hexip: str) -> str:
    return socket.inet_ntoa(struct.pack("<I", int(hexip, 16)))


def _v6(hexip: str) -> str:
    # 4 little-endian 32-bit groups
    raw = b"".join(struct.pack("<I", int(hexip[i:i + 8], 16)) for i in range(0, 32, 8))
    addr = ipaddress.IPv6Address(raw)
    if addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return str(addr)


def _addr(tok: str) -> tuple[str, int] | None:
    try:
        hexip, hexport = tok.rsplit(":", 1)
        port = int(hexport, 16)
        if len(hexip) == 8:
            return _v4(hexip), port
        if len(hexip) == 32:
            return _v6(hexip), port
    except (ValueError, OSError):
        pass
    return None


def parse_proc_net(text: str, proto: str) -> list[Sock]:
    """proto: 'tcp' or 'udp' (6-variants use the same layout)."""
    out: list[Sock] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 8 or not parts[0].rstrip(":").isdigit():
            continue
        local = _addr(parts[1])
        remote = _addr(parts[2])
        state = parts[3]
        if local is None or remote is None:
            continue
        try:
            uid = int(parts[7])
        except ValueError:
            continue
        if proto == "tcp" and state not in TCP_KEEP_STATES:
            continue
        if remote[1] == 0 or remote[0] in ("0.0.0.0", "::"):
            continue
        out.append(Sock(proto, local[0], local[1], remote[0], remote[1], uid, state))
    return out


def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
    except ValueError:
        return True
