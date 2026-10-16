"""SQLite persistence: events, alerts and named JSON snapshots (baselines).

A single connection guarded by a lock; WAL mode so the web API can read
while collectors write. Everything stays in a local file under
~/.android-sentinel — nothing ever leaves this machine.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from .events import Event

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    kind     TEXT NOT NULL,
    severity TEXT NOT NULL,
    title    TEXT NOT NULL,
    detail   TEXT NOT NULL DEFAULT '',
    app      TEXT,
    uid      INTEGER,
    data     TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);

CREATE TABLE IF NOT EXISTS alerts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    rule     TEXT NOT NULL,
    severity TEXT NOT NULL,
    title    TEXT NOT NULL,
    detail   TEXT NOT NULL DEFAULT '',
    app      TEXT,
    state    TEXT NOT NULL DEFAULT 'open',   -- open | acked | muted
    data     TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS snapshots (
    key  TEXT PRIMARY KEY,
    ts   REAL NOT NULL,
    data TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.executescript(_SCHEMA)
        self._migrate()
        self._db.commit()

    def _migrate(self) -> None:
        """Add columns introduced after the first release (multi-device)."""
        for table in ("events", "alerts"):
            cols = {r[1] for r in self._db.execute(f"PRAGMA table_info({table})").fetchall()}
            if "device" not in cols:
                self._db.execute(f"ALTER TABLE {table} ADD COLUMN device TEXT")
        self._db.execute("CREATE INDEX IF NOT EXISTS idx_events_device ON events(device)")

    # ---- events ----
    def add_event(self, ev: Event) -> Event:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO events(ts,kind,severity,title,detail,app,uid,data,device) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (ev.ts, ev.kind, ev.severity, ev.title, ev.detail, ev.app, ev.uid,
                 json.dumps(ev.data, default=str), ev.device),
            )
            self._db.commit()
            ev.id = cur.lastrowid
        return ev

    def events(self, *, kinds: list[str] | None = None, prefix: str | None = None,
               app: str | None = None, since: float | None = None,
               device: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        q = "SELECT id,ts,kind,severity,title,detail,app,uid,data,device FROM events"
        where, args = [], []
        if kinds:
            where.append("kind IN (%s)" % ",".join("?" * len(kinds)))
            args += kinds
        if prefix:
            where.append("kind LIKE ?")
            args.append(prefix + "%")
        if app:
            where.append("app = ?")
            args.append(app)
        if since is not None:
            where.append("ts >= ?")
            args.append(since)
        if device:
            where.append("device = ?")
            args.append(device)
        if where:
            q += " WHERE " + " AND ".join(where)
        q += " ORDER BY id DESC LIMIT ?"
        args.append(max(1, min(int(limit), 2000)))
        with self._lock:
            rows = self._db.execute(q, args).fetchall()
        return [self._row_to_event(r) for r in rows]

    @staticmethod
    def _row_to_event(r: tuple) -> dict[str, Any]:
        return {
            "id": r[0], "ts": r[1], "kind": r[2], "severity": r[3],
            "title": r[4], "detail": r[5], "app": r[6], "uid": r[7],
            "data": json.loads(r[8] or "{}"), "device": r[9],
        }

    # ---- alerts ----
    def add_alert(self, ev: Event) -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO alerts(ts,rule,severity,title,detail,app,data,device) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (ev.ts, ev.data.get("rule", "?"), ev.severity, ev.title, ev.detail,
                 ev.app, json.dumps(ev.data, default=str), ev.device),
            )
            self._db.commit()
            return int(cur.lastrowid or 0)

    def alerts(self, *, state: str | None = "open", limit: int = 100,
               device: str | None = None) -> list[dict[str, Any]]:
        q = "SELECT id,ts,rule,severity,title,detail,app,state,data,device FROM alerts"
        where, args = [], []
        if state:
            where.append("state = ?")
            args.append(state)
        if device:
            where.append("device = ?")
            args.append(device)
        if where:
            q += " WHERE " + " AND ".join(where)
        q += " ORDER BY id DESC LIMIT ?"
        args.append(max(1, min(int(limit), 1000)))
        with self._lock:
            rows = self._db.execute(q, args).fetchall()
        return [
            {"id": r[0], "ts": r[1], "rule": r[2], "severity": r[3], "title": r[4],
             "detail": r[5], "app": r[6], "state": r[7], "data": json.loads(r[8] or "{}"),
             "device": r[9]}
            for r in rows
        ]

    def set_alert_state(self, alert_id: int, state: str) -> bool:
        if state not in ("open", "acked", "muted"):
            return False
        with self._lock:
            cur = self._db.execute("UPDATE alerts SET state=? WHERE id=?", (state, alert_id))
            self._db.commit()
            return cur.rowcount > 0

    # ---- snapshots (baselines for diffing) ----
    def get_snapshot(self, key: str) -> Any | None:
        with self._lock:
            row = self._db.execute("SELECT data FROM snapshots WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def put_snapshot(self, key: str, data: Any) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO snapshots(key,ts,data) VALUES(?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET ts=excluded.ts, data=excluded.data",
                (key, time.time(), json.dumps(data, default=str)),
            )
            self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()
