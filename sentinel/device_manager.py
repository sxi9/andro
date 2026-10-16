"""Watches `adb devices` and supervises one collector set per connected device.

Any number of devices, USB and wireless together, no cap. A device that
appears gets its own DeviceContext and collectors started; one that drops has
its collectors cancelled. Devices that show up but are not ready (unauthorized,
offline, no permissions) are kept in hub.listing so the UI can explain them.
"""
from __future__ import annotations

import asyncio
import logging

from .adb.device import device_info
from .context import DeviceContext, Hub
from .core.events import Event, SEV_NOTICE

log = logging.getLogger("sentinel.devmgr")


def collectors_for(dctx: DeviceContext) -> list:
    from .collectors.capture import CaptureCollector
    from .collectors.logcat import LogcatCollector
    from .collectors.netstats import NetstatsCollector
    from .collectors.network import NetworkCollector
    from .collectors.packages import PackagesCollector
    from .collectors.radio import RadioCollector
    from .collectors.sensors import SensorsCollector
    from .collectors.storage import StorageCollector
    from .collectors.threats import ThreatsCollector
    return [
        LogcatCollector(dctx), SensorsCollector(dctx), NetworkCollector(dctx),
        CaptureCollector(dctx), NetstatsCollector(dctx), PackagesCollector(dctx),
        ThreatsCollector(dctx), RadioCollector(dctx), StorageCollector(dctx),
    ]


class DeviceManager:
    def __init__(self, hub: Hub, poll: float = 5.0) -> None:
        self.hub = hub
        self.poll = poll
        self._tick = 0

    async def run(self) -> None:
        assert self.hub.adb is not None
        while True:
            try:
                await self._reconcile()
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001 - never die; keep watching
                log.debug("reconcile failed: %s", e)
            await asyncio.sleep(self.poll)

    async def _reconcile(self) -> None:
        hub = self.hub
        listing = await asyncio.to_thread(hub.adb.devices)
        hub.listing = listing
        ready = {d["serial"] for d in listing if d["state"] == "device"}

        for serial in ready - set(hub.devices):
            await self._start(serial)
        for serial in list(hub.devices):
            if serial not in ready:
                await self._stop(serial)

        self._tick += 1
        if self._tick % 6 == 0:          # refresh device identity periodically
            for serial, dctx in list(hub.devices.items()):
                try:
                    info = await asyncio.to_thread(device_info, dctx.adb)
                    dctx.device.update(info)
                    dctx.device["serial"] = serial
                except Exception:
                    pass

    async def _start(self, serial: str) -> None:
        hub = self.hub
        dctx = DeviceContext(hub, serial)
        try:
            info = await asyncio.to_thread(device_info, dctx.adb)
            dctx.device.update(info)
        except Exception as e:
            log.warning("could not read %s: %s", serial, e)
        dctx.device["serial"] = serial
        try:
            await asyncio.to_thread(dctx.maps.refresh_uid_map)
        except Exception:
            pass
        hub.devices[serial] = dctx
        for c in collectors_for(dctx):
            dctx.tasks.append(asyncio.create_task(c.run(), name=f"{serial}:{c.name}"))
        dctx.emit(Event(kind="log.line", severity=SEV_NOTICE,
                        title=f"device online: {dctx.device.get('model') or serial}",
                        detail=serial, data={"level": "I", "tag": "sentinel", "buffer": "sys"}))
        log.info("device online: %s (%s) — %d now monitored",
                 serial, dctx.device.get("model"), len(hub.devices))

    async def _stop(self, serial: str) -> None:
        dctx = self.hub.devices.pop(serial, None)
        if not dctx:
            return
        for t in dctx.tasks:
            t.cancel()
        await asyncio.gather(*dctx.tasks, return_exceptions=True)
        log.info("device offline: %s — %d now monitored", serial, len(self.hub.devices))

    async def stop_all(self) -> None:
        for serial in list(self.hub.devices):
            await self._stop(serial)
