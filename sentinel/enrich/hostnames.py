"""ip → hostname cache fed by DNS answers and TLS SNI. Local only."""
from __future__ import annotations

import threading
import time


class HostnameCache:
    def __init__(self, ttl: float = 7200.0, cap: int = 20000) -> None:
        self.ttl = ttl
        self.cap = cap
        self._m: dict[str, tuple[str, float, str]] = {}  # ip -> (host, ts, source)
        self._lock = threading.Lock()

    def put(self, ip: str, host: str, source: str = "dns") -> None:
        if not ip or not host:
            return
        with self._lock:
            cur = self._m.get(ip)
            # SNI is flow-specific and beats a generic DNS answer
            if cur and cur[2] == "sni" and source == "dns":
                return
            if len(self._m) >= self.cap:
                # drop the oldest ~10%
                for k in sorted(self._m, key=lambda k: self._m[k][1])[: self.cap // 10]:
                    self._m.pop(k, None)
            self._m[ip] = (host, time.time(), source)

    def get(self, ip: str) -> str | None:
        with self._lock:
            e = self._m.get(ip)
        if not e:
            return None
        if time.time() - e[1] > self.ttl:
            return None
        return e[0]

    def size(self) -> int:
        with self._lock:
            return len(self._m)
