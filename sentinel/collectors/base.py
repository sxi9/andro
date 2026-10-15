"""Collector base: a long-running task that feeds the event bus."""
from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable

from ..context import AppContext

log = logging.getLogger("sentinel.collector")


class Collector:
    name = "base"

    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx
        self.log = logging.getLogger(f"sentinel.{self.name}")

    async def run(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    async def poll_loop(self, interval: float, fn: Callable[[], Awaitable[None]]) -> None:
        """Run fn forever on a cadence; a failing cycle logs and keeps going."""
        consecutive = 0
        while True:
            try:
                await fn()
                consecutive = 0
            except asyncio.CancelledError:
                raise
            except Exception as e:
                consecutive += 1
                lvl = logging.WARNING if consecutive <= 3 else logging.DEBUG
                self.log.log(lvl, "%s poll failed (%d): %s", self.name, consecutive, e)
            # back off while the device is unreachable
            await asyncio.sleep(interval if consecutive < 5 else min(interval * 5, 60))
