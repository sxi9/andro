"""Rules engine behavior: the detections and their dedupe/cooldown logic."""
from __future__ import annotations

import time

from sentinel.core.events import Event
from sentinel.core.rules import RulesEngine


def ev(kind: str, app: str | None = None, uid: int | None = None, **data) -> Event:
    return Event(kind=kind, severity="info", title="t", app=app, uid=uid, data=data)


def test_background_mic_alerts_and_cooldown():
    eng = RulesEngine()
    a1 = eng.handle(ev("sensor.mic", app="com.spy", uid=10500, background=True, op="RECORD_AUDIO"))
    assert len(a1) == 1
    assert a1[0].data["rule"] == "bg_mic_cam"
    assert a1[0].severity == "crit"
    # same app again inside the cooldown: no duplicate
    a2 = eng.handle(ev("sensor.mic", app="com.spy", uid=10500, background=True, op="RECORD_AUDIO"))
    assert a2 == []


def test_foreground_mic_no_alert():
    eng = RulesEngine()
    assert eng.handle(ev("sensor.mic", app="com.whatsapp", background=False)) == []


def test_sensor_then_egress_correlation():
    eng = RulesEngine()
    eng.handle(ev("sensor.cam", app="com.spy", uid=10500, background=True, op="CAMERA"))
    alerts = eng.handle(ev("net.conn", app="com.spy", uid=10500,
                           ip="1.2.3.4", port=443, host="evil.example"))
    rules = {a.data["rule"] for a in alerts}
    assert "sensor_then_egress" in rules


def test_new_user_ca():
    eng = RulesEngine()
    alerts = eng.handle(ev("threat.ca", added=True, fingerprint="9a3bf1e2.0"))
    assert len(alerts) == 1 and alerts[0].severity == "crit"


def test_godmode_and_sideload_combo():
    eng = RulesEngine()
    alerts = eng.handle(ev("threat.godmode", app="com.led.qrflash",
                           added=True, access="accessibility", installer=None))
    rules = {a.data["rule"] for a in alerts}
    assert "new_godmode" in rules and "sideload_godmode" in rules


def test_godmode_play_install_no_combo():
    eng = RulesEngine()
    alerts = eng.handle(ev("threat.godmode", app="com.joplin",
                           added=True, access="accessibility",
                           installer="com.android.vending"))
    rules = {a.data["rule"] for a in alerts}
    assert "new_godmode" in rules and "sideload_godmode" not in rules


def test_new_country_needs_baseline_first():
    eng = RulesEngine()
    # first country for the app establishes a baseline silently
    a1 = eng.handle(ev("net.conn", app="com.app", ip="1.1.1.1", country="Germany"))
    assert not any(a.data["rule"] == "new_dest_country" for a in a1)
    a2 = eng.handle(ev("net.conn", app="com.app", ip="7.7.7.7", country="Russia"))
    assert any(a.data["rule"] == "new_dest_country" for a in a2)
    # same country again: silent
    a3 = eng.handle(ev("net.conn", app="com.app", ip="7.7.7.8", country="Russia"))
    assert not any(a.data["rule"] == "new_dest_country" for a in a3)


def test_cleartext_and_tracker():
    eng = RulesEngine()
    a = eng.handle(ev("net.conn", app="com.app", ip="5.5.5.5", port=80, transport="wifi"))
    assert any(x.data["rule"] == "cleartext" for x in a)
    a = eng.handle(ev("net.conn", app="com.app", ip="6.6.6.6", port=443,
                      tracker="AppsFlyer", host="wd.a.appsflyer.com"))
    assert any(x.data["rule"] == "tracker_endpoint" for x in a)


def test_signer_change_and_perm_added():
    eng = RulesEngine()
    a = eng.handle(ev("app.update", app="com.app", signer_changed=True))
    assert any(x.data["rule"] == "signer_changed" for x in a)
    a = eng.handle(ev("app.perm", app="com.app",
                      added=["android.permission.READ_SMS", "android.permission.VIBRATE"]))
    assert any(x.data["rule"] == "perm_added" for x in a)
    # non-dangerous additions do not fire
    a = eng.handle(ev("app.perm", app="com.other", added=["android.permission.VIBRATE"]))
    assert a == []


def test_2g_downgrade():
    eng = RulesEngine()
    assert eng.handle(ev("radio.cell", network_type="LTE")) == []
    a = eng.handle(ev("radio.cell", network_type="GSM"))
    assert any(x.data["rule"] == "net_downgrade" for x in a)
    # going back up is not an alert
    assert eng.handle(ev("radio.cell", network_type="LTE")) == []


def test_egress_spike():
    eng = RulesEngine(egress_spike_mb_per_min=1.0)
    t0 = time.time()
    e1 = ev("net.stats", per_uid={"10500": {"tx": 0, "app": "com.spy"}})
    e1.ts = t0 - 60
    assert eng.handle(e1) == []
    e2 = ev("net.stats", per_uid={"10500": {"tx": 50_000_000, "app": "com.spy"}})
    e2.ts = t0
    a = eng.handle(e2)
    assert any(x.data["rule"] == "egress_spike" for x in a)


def test_rule_toggle():
    eng = RulesEngine()
    eng.set_enabled("bg_mic_cam", False)
    assert eng.handle(ev("sensor.mic", app="com.spy", background=True)) == []
    eng.set_enabled("bg_mic_cam", True)
    assert len(eng.handle(ev("sensor.mic", app="com.spy", background=True))) == 1


def test_enabled_map_roundtrip():
    eng = RulesEngine()
    eng.set_enabled("tracker_endpoint", False)
    m = eng.enabled_map()
    eng2 = RulesEngine()
    eng2.apply_enabled_map(m)
    assert eng2.rules["tracker_endpoint"].enabled is False


def test_stalkerware_ioc():
    eng = RulesEngine()
    a = eng.handle(ev("threat.ioc", app="com.spyphone.agent", source="stalkerware-pkgs.txt"))
    assert len(a) == 1 and a[0].severity == "crit"
    assert a[0].data["rule"] == "stalkerware_ioc"


def test_mitm_trio():
    eng = RulesEngine()
    a = eng.handle(ev("threat.mitm", signature="9a3b|proxy:8080"))
    assert len(a) == 1 and a[0].data["rule"] == "mitm_trio"
