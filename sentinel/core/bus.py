"""Async pub/sub event bus.

Collectors publish Events; the store, the rules engine and every WebSocket
client subscribe. Collectors that read blocking subprocess pipes run in
threads, so publishing is thread-safe.
"""
from __future__ import annotations

import asyncio
import logging
from .events import Event

log = logging.getLogger("sentinel.bus")

_MAX_QUEUE = 2000  # per-subscriber backpressure cap


class EventBus:
    def __init__(self) -> None:
        self._subs: set[asyncio.Queue[Event]] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def attach_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self, *, unbounded: bool = False) -> asyncio.Queue[Event]:
        """Bounded by default (slow WebSocket clients drop oldest). The store/
        rules pump subscribes unbounded so no event is ever lost to backpressure."""
        q: asyncio.Queue[Event] = asyncio.Queue(maxsize=0 if unbounded else _MAX_QUEUE)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[Event]) -> None:
        self._subs.discard(q)

    def publish(self, ev: Event) -> None:
        """Publish from inside the event loop."""
        for q in list(self._subs):
            try:
                q.put_nowait(ev)
            except asyncio.QueueFull:
                # Drop oldest so a stalled consumer can't wedge the bus.
                try:
                    q.get_nowait()
                    q.put_nowait(ev)
                except Exception:
                    pass

    def publish_threadsafe(self, ev: Event) -> None:
        """Publish from a reader thread (logcat / tcpdump pipes)."""
        if self._loop is None or self._loop.is_closed():
            return
        self._loop.call_soon_threadsafe(self.publish, ev)
