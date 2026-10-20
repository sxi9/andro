"""Automation watcher: evaluates the device's automation rules on a cadence and
applies the matching performance profile when the context changes. No-ops unless
the owner has enabled automation for the device."""
from __future__ import annotations

import asyncio

from .base import Collector


class AutomationCollector(Collector):
    name = "automation"

    async def run(self) -> None:
        await self.poll_loop(8.0, self._poll)

    async def _poll(self) -> None:
        from ..service import automation
        await asyncio.to_thread(automation.evaluate, self.ctx, True)
