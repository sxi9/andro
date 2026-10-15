"""Store round-trips."""
from __future__ import annotations

from pathlib import Path

from sentinel.core.events import Event
from sentinel.core.store import Store


def test_event_roundtrip(tmp_path: Path):
    st = Store(tmp_path / "t.db")
    ev = Event(kind="net.conn", severity="info", title="a → b",
               app="com.a", uid=10001, data={"ip": "1.2.3.4"})
    st.add_event(ev)
    assert ev.id is not None
    rows = st.events(prefix="net")
    assert rows[0]["data"]["ip"] == "1.2.3.4"
    assert st.events(kinds=["sensor.mic"]) == []
    assert st.events(app="com.a")[0]["app"] == "com.a"
    st.close()


def test_alerts_and_state(tmp_path: Path):
    st = Store(tmp_path / "t.db")
    a = Event(kind="alert", severity="crit", title="bad", data={"rule": "bg_mic_cam"})
    aid = st.add_alert(a)
    assert st.alerts(state="open")[0]["rule"] == "bg_mic_cam"
    assert st.set_alert_state(aid, "acked")
    assert st.alerts(state="open") == []
    assert not st.set_alert_state(aid, "bogus")
    st.close()


def test_snapshots(tmp_path: Path):
    st = Store(tmp_path / "t.db")
    assert st.get_snapshot("x") is None
    st.put_snapshot("x", {"a": 1})
    st.put_snapshot("x", {"a": 2})
    assert st.get_snapshot("x") == {"a": 2}
    st.close()
