"""The one event model every collector feeds and every consumer reads."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

# Severities, mildest to worst.
SEV_INFO = "info"
SEV_NOTICE = "notice"
SEV_WARN = "warn"
SEV_CRIT = "crit"
SEVERITIES = (SEV_INFO, SEV_NOTICE, SEV_WARN, SEV_CRIT)

# Event kinds (dotted namespaces; the UI groups by prefix):
#   net.conn    new outbound connection        data: ip, port, host?, proto, transport, country?, org?, tracker?
#   net.dns     dns answer observed            data: qname, ips
#   net.stats   periodic per-app byte counters data: per_uid: {uid: {rx,tx,mrx,mtx}}
#   sensor.mic / sensor.cam / sensor.loc / sensor.clip
#               sensor access                  data: op, background(bool), duration?, source
#   app.install / app.remove / app.update / app.perm
#               package inventory change       data: installer?, added?, removed?, signer_changed?
#   log.line    attributed logcat line         data: level, tag, buffer, pid
#   radio.call / radio.cell / radio.state
#               telephony layer                data: state?, cell?, network_type?
#   threat.godmode / threat.ca / threat.adbwifi / threat.combo
#               audit finding                  data: varies
#   alert       a rule fired                   data: rule, source_kind


@dataclass
class Event:
    kind: str
    severity: str
    title: str
    detail: str = ""
    app: str | None = None          # owning package, when attributable
    uid: int | None = None
    data: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)
    id: int | None = None           # set by the store
    device: str | None = None       # adb serial of the device this came from

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "ts": self.ts,
            "kind": self.kind,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "app": self.app,
            "uid": self.uid,
            "device": self.device,
            "data": self.data,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), default=str)

    @property
    def group(self) -> str:
        return self.kind.split(".", 1)[0]
