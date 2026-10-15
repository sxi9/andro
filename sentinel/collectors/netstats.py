"""Per-app data usage split WiFi vs cellular, from `dumpsys netstats detail`.

Cellular ("mobile") counters are the metered path — the numbers that answer
"what is this app sending over my data plan, and is it doing it in the
background?" The rules engine computes egress-rate spikes from these totals.
"""
from __future__ import annotations

from ..core.events import Event, SEV_INFO
from ..parsers.netstats import parse_netstats_detail
from .base import Collector


class NetstatsCollector(Collector):
    name = "netstats"

    async def run(self) -> None:
        await self.poll_loop(self.ctx.cfg.poll_netstats, self._poll)

    async def _poll(self) -> None:
        adb = self.ctx.adb
        assert adb is not None
        text = await adb.shell("dumpsys netstats detail", timeout=40)
        totals = parse_netstats_detail(text)
        if not totals:
            return
        per_uid: dict[str, dict] = {}
        for uid, t in totals.items():
            app = self.ctx.app_for_uid(uid)
            per_uid[str(uid)] = {
                "app": app or f"uid:{uid}",
                "rx": t["wifi_rx"] + t["mobile_rx"],
                "tx": t["wifi_tx"] + t["mobile_tx"],
                "wrx": t["wifi_rx"], "wtx": t["wifi_tx"],
                "mrx": t["mobile_rx"], "mtx": t["mobile_tx"],
            }
        self.ctx.state["netstats"] = per_uid
        self.ctx.emit(Event(
            kind="net.stats", severity=SEV_INFO,
            title="data usage refreshed",
            detail=f"{len(per_uid)} apps",
            data={"per_uid": per_uid},
        ))
