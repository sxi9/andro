"""Per-app storage overview from `dumpsys diskstats` (cheap, no `du` sweep).

Feeds ctx.state["storage"] with per-app code/data/cache sizes and free-space
totals. Deep per-app inspection (where an app stores things, its log files) is
done on demand by the REST layer, not polled, since it walks the filesystem.
"""
from __future__ import annotations

from ..parsers.storage import parse_diskstats
from .base import Collector


class StorageCollector(Collector):
    name = "storage"

    async def run(self) -> None:
        await self.poll_loop(max(self.ctx.cfg.poll_packages, 120.0), self._poll)

    async def _poll(self) -> None:
        adb = self.ctx.adb
        assert adb is not None
        text = await adb.shell("dumpsys diskstats", timeout=45)
        ds = parse_diskstats(text)
        if ds.get("apps") or ds.get("totals"):
            self.ctx.state["storage"] = ds
