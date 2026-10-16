"""App Manager phase-2 actions against a recording fake adb: exact command
strings, su flags, pushed file contents, batch/one-click rules, events."""
from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel.core.events import Event, SEV_NOTICE, SEV_WARN
from sentinel.service import appmanager
from sentinel.service.appmanager import run_action

PKG = "com.x"
UID = 10234

PM_LIST = (f"package:/data/app/x/base.apk={PKG} installer=null uid:{UID}\n"
           "package:/data/app/y/base.apk=com.y installer=null uid:10235\n")
PS = ("PID UID RSS NAME\n"
      f"4711 {UID} 180000 {PKG}\n"
      f"4712 {UID} 2000 {PKG}:push\n"
      "3000 10235 50000 com.y\n"
      "1 0 1000 init\n")
DUMP = f"""Packages:
  Package [{PKG}] (abc):
    userId={UID}
    versionCode=7 minSdk=21 targetSdk=33
    pkgFlags=[ HAS_CODE ]
    requested permissions:
      android.permission.CAMERA
      android.permission.INTERNET
      android.permission.READ_SMS
      android.permission.ACCESS_FINE_LOCATION
    install permissions:
      android.permission.INTERNET: granted=true
    User 0: ceDataInode=1 installed=true hidden=false suspended=true stopped=false enabled=0
      runtime permissions:
        android.permission.CAMERA: granted=true, flags=[ USER_SET|USER_SENSITIVE_WHEN_GRANTED]
        android.permission.READ_SMS: granted=false
        android.permission.ACCESS_FINE_LOCATION: granted=true, flags=[ USER_SET ]
"""
PREFS = (b"<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n"
         b"<map>\n    <boolean name=\"analytics\" value=\"true\" />\n"
         b"    <string name=\"user\">bob</string>\n    <int name=\"n\" value=\"3\" />\n</map>\n")


class FakeAdb:
    use_su = True

    def __init__(self, responses=None, files=None):
        self.cmds: list[tuple[str, bool]] = []
        self.pushed: list[tuple[str, bytes]] = []
        self.pulled: list[str] = []
        self.responses = responses or {}
        self.files = files or {}

    def shell_sync(self, cmd, su=False, timeout=60):
        self.cmds.append((cmd, su))
        for prefix, out in self.responses.items():
            if cmd.startswith(prefix):
                return out(cmd) if callable(out) else out
        if "echo WROTE" in cmd:
            return "WROTE\n"
        if cmd.startswith("pm list packages"):
            return PM_LIST
        if cmd.startswith("ps -A"):
            return PS
        if cmd.startswith("dumpsys package"):
            return DUMP
        return "Success" if cmd.startswith("pm ") else ""

    def exec_out_bytes(self, cmd, su=False, timeout=60):
        self.cmds.append((cmd, su))
        m = re.match(r"cat (\S+)", cmd)
        return self.files.get(m.group(1), b"") if m else b""

    def push_file(self, local, remote, timeout=600):
        self.pushed.append((remote, Path(local).read_bytes()))
        return True

    def apk_paths(self, pkg):
        return [f"/data/app/~~x/{pkg}-y/base.apk", f"/data/app/~~x/{pkg}-y/split_config.arm64_v8a.apk"]

    # the AdbClient filesystem helpers, shaped like the real commands
    def du_sizes(self, paths, su=True, timeout=0):
        return self.shell_sync("du -sk " + " ".join(paths), su=su)

    def list_dir(self, path, su=True, timeout=0):
        return self.shell_sync(f"ls -la {path}", su=su)

    def find_files(self, root, globs=None, limit=0, su=True, timeout=0):
        return self.shell_sync(f"find {root} -type f", su=su)

    def pull_file(self, remote, local, timeout=600):
        Path(local).write_bytes(b"PK\x03\x04")
        self.pulled.append(remote)
        return True


class Store:
    def __init__(self, snaps=None):
        self.snaps = snaps or {}

    def get_snapshot(self, k):
        return self.snaps.get(k)

    def put_snapshot(self, k, v):
        self.snaps[k] = v


class Ctx:
    def __init__(self, tmp_path=None, snaps=None, **adb_kw):
        self.adb = FakeAdb(**adb_kw)
        self.state = {}
        self.device = {"root": True}
        self.serial = "FAKE123"
        self.store = Store(snaps)
        self.events: list[Event] = []
        self.cfg = SimpleNamespace(data_dir=tmp_path) if tmp_path else None

    def emit_threadsafe(self, ev):
        self.events.append(ev)

    def shell_cmds(self):
        return [c for c, _ in self.adb.cmds]


def _act(c, action, **p):
    return run_action(c, action, {"package": PKG, **p})


# ---------------- freeze / unfreeze / uninstall ----------------

@pytest.mark.parametrize("method,cmd", [
    ("disable", "pm disable-user --user 0 com.x"),
    ("suspend", "pm suspend --user 0 com.x"),
    ("hide", "pm hide --user 0 com.x"),
])
def test_freeze_methods(method, cmd):
    c = Ctx()
    r = _act(c, "freeze", method=method, confirm=True)
    assert r["ok"] and c.shell_cmds() == [cmd]
    assert r["action"] == "freeze" and r["package"] == PKG


def test_freeze_needs_confirm_and_valid_method():
    c = Ctx()
    r = _act(c, "freeze", method="hide")
    assert r["ok"] is False and "confirm" in r["output"] and c.adb.cmds == []
    r = _act(c, "freeze", method="nuke", confirm=True)
    assert r["ok"] is False and "method" in r["output"] and c.adb.cmds == []
    assert c.events == []           # refused input never logs an event


def test_unfreeze_runs_all_three_and_tolerates_failures():
    def pm(cmd):
        if cmd.startswith("pm unhide"):
            raise appmanager.AdbError("adb shell failed (1): not hidden")
        return f"Package com.x new state: {cmd.split()[1]}"
    c = Ctx(responses={"pm ": pm})
    r = _act(c, "unfreeze", user=10)
    assert c.shell_cmds() == ["pm enable --user 10 com.x", "pm unsuspend --user 10 com.x",
                              "pm unhide --user 10 com.x"]
    assert r["ok"] is True and "not hidden" in r["output"] and "enable" in r["output"]


def test_uninstall_keep_data_flag():
    c = Ctx()
    assert _act(c, "uninstall", confirm=True, keep_data=True)["ok"]
    assert _act(c, "uninstall", confirm=True)["ok"]
    assert _act(c, "uninstall", confirm=True, keep_data="false")["ok"]
    assert c.shell_cmds() == ["pm uninstall -k --user 0 com.x", "pm uninstall --user 0 com.x",
                              "pm uninstall --user 0 com.x"]


def test_uninstall_updates_only_for_system_apps():
    c = Ctx()                                       # listing has no -s match for com.x
    c.adb.responses["pm list packages -s"] = ""
    r = _act(c, "uninstall-updates", confirm=True)
    assert r["ok"] is False and "system" in r["output"]
    assert not any(cmd.startswith("pm uninstall") for cmd in c.shell_cmds())
    c = Ctx(responses={"pm list packages -s": f"package:{PKG}\n"})
    r = _act(c, "uninstall-updates", confirm=True)
    assert r["ok"] and c.shell_cmds()[-1] == "pm uninstall com.x"


# ---------------- launching ----------------

def test_launch_and_open_settings():
    c = Ctx()
    assert _act(c, "launch")["ok"]
    assert _act(c, "open-settings")["ok"]
    assert c.shell_cmds() == [
        "monkey -p com.x -c android.intent.category.LAUNCHER 1",
        "am start -a android.settings.APPLICATION_DETAILS_SETTINGS -d package:com.x"]
    c = Ctx(responses={"monkey": "** No activities found to run, monkey aborted."})
    assert _act(c, "launch")["ok"] is False


def test_launch_activity_validation_and_su():
    c = Ctx()
    r = _act(c, "launch-activity", component="com.other/.Main")
    assert r["ok"] is False and "belong" in r["output"] and c.adb.cmds == []
    r = _act(c, "launch-activity", component="com.x/.Main; id")
    assert r["ok"] is False and "invalid component" in r["output"] and c.adb.cmds == []
    r = _act(c, "launch-activity", component="com.x/.Main")
    assert r["ok"] and c.adb.cmds == [("am start -n com.x/com.x.Main", True)]
    r = _act(c, "send-broadcast", component="com.x/com.x.Recv")
    assert c.adb.cmds[-1] == ("am broadcast -n com.x/com.x.Recv", False)


def test_start_service_falls_back_to_old_spelling():
    c = Ctx(responses={"am start-service": "Unknown command: start-service",
                       "am startservice": "Starting service: Intent { cmp=com.x/.Svc }"})
    r = _act(c, "start-service", component="com.x/.Svc")
    assert r["ok"] and c.shell_cmds() == ["am start-service -n com.x/com.x.Svc",
                                          "am startservice -n com.x/com.x.Svc"]


# ---------------- policy toggles ----------------

def test_battery_whitelist_add_remove():
    c = Ctx(responses={"dumpsys deviceidle": "Added: com.x"})
    assert _act(c, "battery", whitelist=True)["ok"]
    assert _act(c, "battery", whitelist=False)["ok"]
    assert c.shell_cmds() == ["dumpsys deviceidle whitelist +com.x", "dumpsys deviceidle whitelist -com.x"]
    r = _act(c, "battery")
    assert r["ok"] is False and "whitelist" in r["output"]


def test_netpolicy_resolves_uid_then_adds_and_removes():
    c = Ctx()
    assert _act(c, "netpolicy", restrict_background=True)["ok"]
    assert _act(c, "netpolicy", restrict_background=False)["ok"]
    cmds = c.shell_cmds()
    assert "pm list packages --user 0 -U com.x" in cmds
    assert cmds[1] == f"cmd netpolicy add restrict-background-blacklist {UID}"
    assert cmds[-1] == f"cmd netpolicy remove restrict-background-blacklist {UID}"


def test_netpolicy_without_uid_fails_cleanly():
    c = Ctx(responses={"pm list packages": ""})
    r = _act(c, "netpolicy", restrict_background=True)
    assert r["ok"] is False and "uid" in r["output"]
    assert not any("netpolicy" in cmd for cmd in c.shell_cmds())


def test_sensors_states():
    c = Ctx()
    for st in ("active", "idle", "reset"):
        assert _act(c, "sensors", state=st)["ok"]
    assert c.shell_cmds() == ["cmd sensorservice set-uid-state com.x active",
                              "cmd sensorservice set-uid-state com.x idle",
                              "cmd sensorservice reset-uid-state com.x"]
    assert _act(c, "sensors", state="off")["ok"] is False


def test_denylist_uses_su_and_detects_absence():
    c = Ctx(responses={"magisk --denylist ls": "com.y|com.y\n"})
    assert _act(c, "denylist", enabled=True)["ok"]
    assert _act(c, "denylist", enabled=False)["ok"]
    assert c.adb.cmds == [("magisk --denylist ls", True), ("magisk --denylist add com.x", True),
                          ("magisk --denylist ls", True), ("magisk --denylist rm com.x", True)]

    def gone(cmd):
        raise appmanager.AdbError("adb shell failed (127): magisk: inaccessible or not found")
    c = Ctx(responses={"magisk": gone})
    r = _act(c, "denylist", enabled=True)
    assert r["ok"] is False and r["output"] == "Magisk denylist not available"
    assert c.shell_cmds() == ["magisk --denylist ls"]


def test_app_links_allowed():
    c = Ctx()
    assert _act(c, "app-links", allowed=False, user=10)["ok"]
    assert _act(c, "app-links", allowed=True)["ok"]
    assert c.shell_cmds() == ["pm set-app-links-allowed --user 10 --package com.x false",
                              "pm set-app-links-allowed --user 0 --package com.x true"]


def test_firewall_both_tables_as_root():
    c = Ctx()
    r = _act(c, "firewall", block=True, confirm=True)
    assert r["ok"] and "reboot" in r["output"]
    su = [(cmd, s) for cmd, s in c.adb.cmds if "tables" in cmd]
    assert su == [(f"iptables -I OUTPUT -m owner --uid-owner {UID} -j REJECT", True),
                  (f"ip6tables -I OUTPUT -m owner --uid-owner {UID} -j REJECT", True)]
    _act(c, "firewall", block=False, confirm=True)
    assert c.adb.cmds[-1] == (f"ip6tables -D OUTPUT -m owner --uid-owner {UID} -j REJECT", True)
    assert _act(c, "firewall", block=True)["ok"] is False      # destructive: confirm


def test_prevent_background_two_ops():
    c = Ctx()
    assert _act(c, "prevent-background", enabled=True)["ok"]
    assert _act(c, "prevent-background", enabled=False)["ok"]
    assert c.shell_cmds() == ["appops set com.x RUN_IN_BACKGROUND ignore",
                              "appops set com.x RUN_ANY_IN_BACKGROUND ignore",
                              "appops set com.x RUN_IN_BACKGROUND allow",
                              "appops set com.x RUN_ANY_IN_BACKGROUND allow"]


def test_appops_deny_dangerous_and_reset():
    c = Ctx()
    assert _act(c, "appops-deny-dangerous", confirm=True)["ok"]
    cmd = c.shell_cmds()[0]
    assert cmd.startswith("appops set com.x COARSE_LOCATION ignore; appops set com.x FINE_LOCATION ignore")
    assert cmd.endswith("appops set com.x SYSTEM_ALERT_WINDOW ignore")
    assert cmd.count("appops set") == 13 and ";" in cmd
    assert _act(c, "appops-reset")["ok"] and c.shell_cmds()[-1] == "appops reset com.x"


def test_deny_dangerous_perms_revokes_only_granted_dangerous():
    c = Ctx()
    r = _act(c, "deny-dangerous-perms", confirm=True)
    revokes = [cmd for cmd in c.shell_cmds() if cmd.startswith("pm revoke")]
    # CAMERA and FINE_LOCATION are granted + dangerous; READ_SMS is not granted,
    # INTERNET is not dangerous
    assert revokes == ["pm revoke --user 0 com.x android.permission.CAMERA",
                       "pm revoke --user 0 com.x android.permission.ACCESS_FINE_LOCATION"]
    assert r["ok"] and "revoked 2" in r["output"]


# ---------------- intent firewall ----------------

MANIFEST = {PKG: {"activities": [{"name": "com.x.AdActivity"}],
                  "services": [{"name": "com.x.TrackSvc"}],
                  "receivers": [{"name": "com.x.BootRecv"}],
                  "providers": [{"name": "com.x.Prov"}]}}


def _pushed_xml(c):
    return [data.decode() for remote, data in c.adb.pushed]


def test_ifw_block_activity_and_service_write_rules():
    c = Ctx(snaps={"manifests": MANIFEST})
    r = _act(c, "ifw-block", component="com.x/.AdActivity", confirm=True)
    assert r["ok"], r
    xml = _pushed_xml(c)[-1]
    assert '<activity block="true" log="false">' in xml
    assert '<component-filter name="com.x/com.x.AdActivity" />' in xml
    assert "<service" not in xml
    # the pushed temp file is copied into place as root, world-readable
    write = [cmd for cmd, su in c.adb.cmds if "cp /data/local/tmp/" in cmd and su][-1]
    assert "/data/system/ifw/com.x.xml" in write and "chmod 644" in write and "rm -f /data/local/tmp/" in write
    assert ("pm disable com.x/com.x.AdActivity", True) in c.adb.cmds
    # a second rule for a service is merged into the existing file
    c.adb.files["/data/system/ifw/com.x.xml"] = xml.encode()
    _act(c, "ifw-block", component="com.x/com.x.TrackSvc", confirm=True)
    xml2 = _pushed_xml(c)[-1]
    assert '<component-filter name="com.x/com.x.AdActivity" />' in xml2
    assert '<service block="true" log="false"><component-filter name="com.x/com.x.TrackSvc" />' in xml2.replace("\n", "")
    assert xml2.count("component-filter") == 2


def test_ifw_unknown_component_gets_all_three_and_unblock_removes_file():
    c = Ctx(snaps={"manifests": MANIFEST})
    _act(c, "ifw-block", component="com.x/com.x.Mystery", confirm=True)
    xml = _pushed_xml(c)[-1]
    for tag in ("activity", "service", "broadcast"):
        assert f'<{tag} block="true" log="false">' in xml
    assert xml.count('name="com.x/com.x.Mystery"') == 3
    c.adb.files["/data/system/ifw/com.x.xml"] = xml.encode()
    before = len(c.adb.pushed)
    r = _act(c, "ifw-unblock", component="com.x/com.x.Mystery", confirm=True)
    assert r["ok"]
    assert len(c.adb.pushed) == before                     # nothing left: file removed
    assert ("rm -f /data/system/ifw/com.x.xml", True) in c.adb.cmds
    assert ("pm enable com.x/com.x.Mystery", True) in c.adb.cmds


def test_ifw_provider_uses_pm_disable_only():
    c = Ctx(snaps={"manifests": MANIFEST})
    r = _act(c, "ifw-block", component="com.x/com.x.Prov", confirm=True)
    assert r["ok"] and c.adb.pushed == []
    assert ("pm disable com.x/com.x.Prov", True) in c.adb.cmds


def test_block_trackers_needs_cached_scan():
    c = Ctx(snaps={"manifests": MANIFEST})
    r = _act(c, "block-trackers", confirm=True)
    assert r["ok"] is False and r["output"] == "scan this app first" and c.adb.cmds == []
    scan = {PKG: {"trackers": [{"name": "T", "components": ["com.x.AdActivity", "com.x.TrackSvc"]},
                               {"name": "U", "components": ["com.x/com.x.BootRecv"]}]}}
    c = Ctx(snaps={"manifests": MANIFEST, "scans": scan})
    r = _act(c, "block-trackers", confirm=True)
    assert r["ok"] and "3 component" in r["output"]
    xml = _pushed_xml(c)[-1]
    assert len(c.adb.pushed) == 1                           # one read-modify-write
    assert '<broadcast block="true" log="false"><component-filter name="com.x/com.x.BootRecv" />' in xml.replace("\n", "")
    assert xml.count("component-filter") == 3
    disabled = [cmd for cmd, su in c.adb.cmds if cmd.startswith("pm disable") and su]
    assert len(disabled) == 3


# ---------------- processes / compile / apk ----------------

def test_kill_checks_pid_owner():
    c = Ctx()
    r = _act(c, "kill", pid=3000)
    assert r["ok"] is False and "belongs to uid 10235" in r["output"]
    assert not any(cmd.startswith("kill") for cmd in c.shell_cmds())
    r = _act(c, "kill", pid=4712)
    assert r["ok"] and c.adb.cmds[-1] == ("kill -9 4712", True)
    assert _act(c, "kill", pid=99999)["ok"] is False
    assert _act(c, "kill", pid="x")["ok"] is False
    assert _act(c, "kill", pid=1)["ok"] is False             # out of range, never runs


def test_compile_modes():
    c = Ctx()
    for mode in ("speed", "speed-profile", "verify", "reset"):
        assert _act(c, "compile", mode=mode)["ok"]
    assert c.shell_cmds() == ["pm compile -m speed -f com.x", "pm compile -m speed-profile -f com.x",
                              "pm compile -m verify -f com.x", "pm compile --reset com.x"]
    assert _act(c, "compile", mode="everything")["ok"] is False


def test_save_apk_pulls_every_split(tmp_path):
    c = Ctx(tmp_path=tmp_path)
    r = _act(c, "save-apk")
    assert r["ok"]
    dest = Path(r["output"])
    assert dest == tmp_path / "apks" / "FAKE123" / PKG
    assert sorted(p.name for p in dest.iterdir()) == ["0_base.apk", "1_split_config.arm64_v8a.apk"]
    assert c.adb.pulled == c.adb.apk_paths(PKG)


# ---------------- shared_prefs ----------------

def test_prefs_set_rewrites_xml_and_fixes_ownership():
    c = Ctx(files={"/data/data/com.x/shared_prefs/com.x_preferences.xml": PREFS})
    r = _act(c, "prefs-set", file="com.x_preferences.xml", key="analytics", type="boolean",
             value=False, confirm=True)
    assert r["ok"] and r["output"] == "set"
    remote, data = c.adb.pushed[-1]
    assert remote.startswith("/data/local/tmp/sentinel-")
    xml = data.decode()
    assert xml.startswith("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>")
    assert '<boolean name="analytics" value="false" />' in xml
    assert xml.count('name="analytics"') == 1
    assert '<string name="user">bob</string>' in xml and '<int name="n" value="3" />' in xml
    write = [cmd for cmd, su in c.adb.cmds if "cp /data/local/tmp/" in cmd and su][-1]
    assert "/data/data/com.x/shared_prefs/com.x_preferences.xml" in write
    assert f"chown {UID}:{UID}" in write and "chmod 660" in write and "restorecon" in write
    assert c.events[-1].kind == "app.action" and c.events[-1].data["params"]["value"] is False


def test_prefs_set_new_key_and_set_type_and_delete():
    files = {"/data/data/com.x/shared_prefs/p.xml": PREFS}
    c = Ctx(files=files)
    r = _act(c, "prefs-set", file="p.xml", key="tags", type="set", value=["a", "b"], confirm=True)
    assert r["ok"]
    xml = c.adb.pushed[-1][1].decode()
    assert '<set name="tags"><string>a</string><string>b</string></set>' in xml
    r = _act(c, "prefs-delete", file="p.xml", key="user", confirm=True)
    assert r["ok"] and r["output"] == "deleted"
    assert 'name="user"' not in c.adb.pushed[-1][1].decode()
    assert _act(c, "prefs-delete", file="p.xml", key="nope", confirm=True)["ok"] is False
    for bad in ({"file": "../p.xml", "key": "a"}, {"file": "p.xml", "key": "a b"},
                {"file": "p.txt", "key": "a"}, {"file": "p.xml", "key": "a", "type": "blob"}):
        r = _act(c, "prefs-set", **{"type": "string", "value": "v", "confirm": True, **bad})
        assert r["ok"] is False
    r = _act(c, "prefs-set", file="p.xml", key="big", type="string", value="x" * 4001, confirm=True)
    assert r["ok"] is False and "long" in r["output"]


# ---------------- events ----------------

def test_every_executed_action_emits_app_action_event():
    c = Ctx(responses={"am force-stop": "",
                       "pm grant": "java.lang.SecurityException: Permission not requested"})
    _act(c, "force-stop", device="FAKE123", confirm=True)
    ev = c.events[-1]
    assert isinstance(ev, Event) and ev.kind == "app.action" and ev.severity == SEV_NOTICE
    assert ev.title == "force-stop: com.x" and ev.app == PKG
    assert ev.data["action"] == "force-stop" and ev.data["ok"] is True and ev.data["user"] == 0
    assert "device" not in ev.data["params"] and "confirm" not in ev.data["params"]
    _act(c, "grant", permission="android.permission.CAMERA")
    ev = c.events[-1]
    assert ev.severity == SEV_WARN and ev.data["ok"] is False
    assert ev.data["params"] == {"permission": "android.permission.CAMERA"}
    assert ev.data["output"].startswith("java.lang.SecurityException")
    _act(c, "grant", permission="bad perm")                      # refused: no event
    assert len(c.events) == 2


# ---------------- batch / one-click ----------------

def test_batch_validation():
    c = Ctx()
    with pytest.raises(appmanager.AdbError, match="max 500"):
        appmanager.batch(c, "force-stop", [f"com.p{i}" for i in range(501)])
    with pytest.raises(appmanager.AdbError, match="not allowed"):
        appmanager.batch(c, "grant", [PKG])
    with pytest.raises(appmanager.AdbError, match="invalid package"):
        appmanager.batch(c, "force-stop", ["com.ok", "bad;rm"])
    with pytest.raises(appmanager.AdbError, match="confirm"):
        appmanager.batch(c, "freeze", [PKG], 0, False, {"method": "hide"})
    with pytest.raises(appmanager.AdbError, match="non-empty"):
        appmanager.batch(c, "force-stop", [])
    assert c.adb.cmds == []


def test_batch_runs_sequentially_with_options():
    def pm(cmd):
        return "Failure [not installed]" if "com.bad" in cmd else "Success"
    c = Ctx(responses={"pm ": pm})
    res = appmanager.batch(c, "freeze", ["com.a", "com.bad", "com.c"], 10, True,
                           {"method": "suspend", "device": "ignored"})
    assert c.shell_cmds() == ["pm suspend --user 10 com.a", "pm suspend --user 10 com.bad",
                              "pm suspend --user 10 com.c"]
    assert res["ok_count"] == 2 and res["fail_count"] == 1
    assert [r["package"] for r in res["results"]] == ["com.a", "com.bad", "com.c"]
    assert res["results"][1]["ok"] is False and "Failure" in res["results"][1]["output"]
    assert len(c.events) == 3


FULL = ("package:/s/android.apk=android uid:1000\n"
        "package:/s/sysui.apk=com.android.systemui uid:10013\n"
        "package:/s/settings.apk=com.android.settings uid:1000\n"
        "package:/s/phone.apk=com.android.phone uid:1001\n"
        "package:/s/shell.apk=com.android.shell uid:2000\n"
        "package:/s/launcher.apk=com.android.launcher3 uid:10020\n"
        "package:/s/gms.apk=com.google.android.gms uid:10012\n"
        "package:/d/a.apk=com.a uid:10101\n"
        "package:/d/b.apk=com.b uid:10102\n"
        "package:/s/radio.apk=com.android.radio uid:1001\n")


def _oneclick_ctx():
    def pm_list(cmd):
        if "-3" in cmd.split():
            return "package:/d/a.apk=com.a uid:10101\npackage:/d/b.apk=com.b uid:10102\n"
        return FULL

    def role(cmd):
        return "com.android.launcher3\n" if cmd.endswith("android.app.role.HOME") else "\n"
    return Ctx(responses={"pm list packages": pm_list, "cmd role get-role-holders": role,
                          "pm query-activities": "", "pm resolve-activity": ""})


def test_oneclick_package_set_rules():
    c = _oneclick_ctx()
    assert appmanager.oneclick_packages(c, "user") == ["com.a", "com.b"]
    # all: uid >= 10000 only, minus the core system set and the launcher
    assert appmanager.oneclick_packages(c, "all") == ["com.a", "com.b", "com.google.android.gms"]


def test_oneclick_runs_batch_and_trim_caches():
    c = _oneclick_ctx()
    res = appmanager.oneclick(c, "deny-bg-all", False, "all")
    assert res["ok_count"] == 3 and res["fail_count"] == 0 and "3 all app(s)" in res["note"]
    bg = [cmd for cmd in c.shell_cmds() if cmd.startswith("appops set")]
    assert bg == [f"appops set {p} {op} ignore" for p in ("com.a", "com.b", "com.google.android.gms")
                  for op in ("RUN_IN_BACKGROUND", "RUN_ANY_IN_BACKGROUND")]
    with pytest.raises(appmanager.AdbError, match="confirm"):
        appmanager.oneclick(c, "deny-dangerous-ops-all", False, "user")
    with pytest.raises(appmanager.AdbError, match="unknown op"):
        appmanager.oneclick(c, "firewall-all-user-apps", True, "user")
    c = _oneclick_ctx()
    res = appmanager.oneclick(c, "trim-caches", False, "user")
    assert c.shell_cmds() == ["pm trim-caches 999G"] and res["ok_count"] == 1
    assert c.events[-1].data["action"] == "trim-caches"


def test_oneclick_block_trackers_skips_unscanned():
    c = _oneclick_ctx()
    c.store.snaps["scans"] = {"com.a": {"trackers": [{"name": "T", "components": ["com.a.Svc"]}]},
                              "com.b": {"trackers": []}}
    c.store.snaps["manifests"] = {"com.a": {"services": [{"name": "com.a.Svc"}]}}
    res = appmanager.oneclick(c, "block-trackers-all", True, "user")
    assert [r["package"] for r in res["results"]] == ["com.a"]
    assert "1 skipped" in res["note"] and res["ok_count"] == 1
    assert '<component-filter name="com.a/com.a.Svc" />' in c.adb.pushed[-1][1].decode()
    assert c.adb.pushed[-1][1].decode().count("<service") == 1


# ---------------- detail / controls / history ----------------

def test_app_detail_new_fields():
    c = Ctx(responses={"pm list users": "Users:\n\tUserInfo{0:Owner:c13} running\n",
                       "dumpsys appops": ""})
    c.state["netstats"] = {str(UID): {"wrx": 10, "wtx": 20, "mrx": 30, "mtx": 40}}
    d = appmanager.app_detail(c, PKG)
    assert d["uid"] == UID and d["shared_user"] is None
    assert d["state"] == {"installed": True, "hidden": False, "suspended": True, "stopped": False,
                          "enabled_state": 0, "frozen": "suspended", "user": 0}
    assert d["perm_flags"]["android.permission.CAMERA"] == ["USER_SET", "USER_SENSITIVE_WHEN_GRANTED"]
    assert d["data_usage"] == {"wifi_rx": 10, "wifi_tx": 20, "mobile_rx": 30, "mobile_tx": 40}
    assert d["running"] == {"pids": [4711, 4712], "rss_kb": 182000}
    assert d["links"]["play"].endswith("id=com.x") and "exodus" in d["links"]


def test_controls_parsing():
    def sh(cmd):
        return {
            "dumpsys deviceidle whitelist": "system-excidle,com.google.android.gms,10012\nuser,com.x,10234\n",
            "cmd netpolicy list restrict-background-blacklist": "Restrict background blacklist uids: 10234 10300\n",
            "cmd netpolicy get restrict-background": "Restrict background status: enabled\n",
            "cmd sensorservice get-uid-state com.x": "com.x is idle\n",
            "magisk --denylist ls": "com.x|com.x\ncom.y|com.y:bg\n",
            "pm get-app-links --user 0 com.x": (
                "  com.x:\n    ID: 1\n    Signatures: [AA]\n    Domain verification state:\n"
                "      x.com: verified\n      m.x.com: none\n    User 0:\n"
                "      Verification link handling allowed: false\n      Selection state:\n"
                "        Enabled:\n          alt.x.com\n"),
            "iptables -S OUTPUT": "-P OUTPUT ACCEPT\n-A OUTPUT -m owner --uid-owner 10234 -j REJECT --reject-with icmp-port-unreachable\n",
            "cmd overlay list --user 0": "android\n[x] com.theme.a\ncom.x\n[x] com.x.ov1\n[ ] com.x.ov2\ncom.z\n[x] com.z.ov\n",
            "abx2xml /data/system/users/0/settings_ssaid.xml -": (
                '<settings version="-1">\n  <setting id="2" name="10234" value="abc123" package="com.x" '
                'defaultValue="abc123" defaultSysSet="false" tag="null" />\n</settings>\n'),
            "ls /data/misc/keystore/user_0": "10234_USRPKEY_k1\n10234_USRCERT_k1\n10300_USRPKEY_z\n",
        }.get(cmd, "")
    c = Ctx(responses={"": sh})
    c.adb.responses = {"pm list packages": PM_LIST, "": sh}
    r = appmanager.controls(c, PKG)
    assert r["errors"] == {}
    assert r["battery_whitelisted"] is True and r["net_restricted_background"] is True
    assert r["data_saver"] is True and r["sensors"] == "idle"
    assert r["denylist"] is True and r["denylist_available"] is True
    assert r["app_links"] == [{"domain": "x.com", "state": "verified"}, {"domain": "m.x.com", "state": "none"},
                              {"domain": "alt.x.com", "state": "user-enabled"}]
    assert r["app_links_allowed"] is False and r["firewall_blocked"] is True
    assert r["overlays"] == [{"name": "com.x.ov1", "enabled": True}, {"name": "com.x.ov2", "enabled": False}]
    assert r["ssaid"] == "abc123" and r["keystore_files"] == 2
    # the root-only probes ran with su
    assert ("magisk --denylist ls", True) in c.adb.cmds and ("iptables -S OUTPUT", True) in c.adb.cmds


def test_controls_survive_failures():
    def boom(cmd):
        raise appmanager.AdbError("nope")
    c = Ctx(responses={"pm list packages": PM_LIST, "": boom})
    r = appmanager.controls(c, "com.x")
    assert r["battery_whitelisted"] is None and r["denylist_available"] is False
    assert set(r["errors"]) >= {"battery_whitelisted", "denylist", "firewall_blocked", "ssaid"}


def test_export_rows_and_render():
    apps = [{"package": "com.a", "label": "A", "system": False, "enabled": True, "installed": True,
             "installer": None, "uid": 10001, "data_size": 5, "apk_size": 7}]
    rows = appmanager.export_rows(apps, {"com.a": {"version_name": "1.2"}})
    csv, media, ext = appmanager.render_export(rows, "csv")
    assert csv.splitlines()[0] == "label,package,version,system,enabled,installed,installer,uid,data_size,apk_size"
    assert csv.splitlines()[1] == "A,com.a,1.2,False,True,True,,10001,5,7" and ext == "csv"
    md = appmanager.render_export(rows, "md")[0]
    assert md.startswith("| label | package |") and "| A | com.a | 1.2 |" in md
    js = appmanager.render_export(rows, "json")[0]
    assert '"count": 1' in js


def test_history_reads_app_action_events():
    class S(Store):
        def events(self, **kw):
            assert kw["kinds"] == ["app.action"] and kw["device"] == "FAKE123"
            return [{"ts": 1.0, "title": "freeze: com.x", "app": "com.x", "detail": "d",
                     "data": {"action": "freeze", "ok": True, "user": 0, "output": "o",
                              "params": {"method": "hide"}}}]
    c = Ctx()
    c.store = S()
    h = appmanager.history(c, 50)
    assert h["events"] == [{"ts": 1.0, "action": "freeze", "package": "com.x", "ok": True,
                            "output": "o", "user": 0, "params": {"method": "hide"}}]


# ---------------- appdata: storage / prefs / sqlite / processes ----------------

from sentinel.service import appdata  # noqa: E402


def test_storage_shape_and_backups(tmp_path):
    class Backup:
        def list_backups(self, serial=None):
            return [{"name": "com.x_1", "path": "/b/com.x_1", "bytes": 5, "package": PKG,
                     "serial": serial, "captured": "1", "components": ["apk"]},
                    {"name": "com.y_1", "path": "/b/com.y_1", "bytes": 5, "package": "com.y",
                     "serial": serial, "captured": "1", "components": ["apk"]}]

    def sh(cmd):
        if cmd.startswith("du -sk"):
            return "100\t/data/data/com.x\n20\t/data/data/com.x/cache\n5\t/data/data/com.x/code_cache\n"
        if cmd.startswith("ls -la"):
            return "drwxrwx--x  2 u0_a155 u0_a155 4096 2026-10-15 18:40 cache\n"
        if cmd.startswith("find"):
            return "/data/data/com.x/files/app.log\n"
        return ""
    c = Ctx(responses={"": sh})
    c.hub = SimpleNamespace(backup=Backup())
    s = appdata.storage(c, PKG)
    assert s["data_dir"] == "/data/data/com.x" and s["obb_dir"] == "/sdcard/Android/obb/com.x"
    assert s["de_dir"] == "/data/user_de/0/com.x" and s["media_dir"] == "/sdcard/Android/media/com.x"
    assert s["cache_bytes"] == 25 * 1024 and s["data_bytes"] == 100 * 1024
    assert s["apk_paths"] == c.adb.apk_paths(PKG) and [x["path"] for x in s["splits"]] == s["apk_paths"]
    assert s["entries"][0]["name"] == "cache" and s["log_files"] == ["/data/data/com.x/files/app.log"]
    assert [b["name"] for b in s["backups"]] == ["com.x_1"]
    assert set(s["backups"][0]) == {"name", "path", "bytes", "captured", "components"}


def test_prefs_list_and_read():
    files = {"/data/data/com.x/shared_prefs/a.xml": PREFS,
             "/data/data/com.x/shared_prefs/b.xml": b"<map/>"}
    c = Ctx(files=files, responses={"ls -la": (
        "-rw-rw---- 1 u0_a155 u0_a155 300 2026-10-15 18:40 a.xml\n"
        "-rw-rw---- 1 u0_a155 u0_a155 40 2026-10-15 18:40 b.xml\n"
        "-rw-rw---- 1 u0_a155 u0_a155 40 2026-10-15 18:40 notes.txt\n")})
    assert appdata.prefs_list(c, PKG) == {"files": [{"name": "a.xml", "size": 300, "entries": 3},
                                                    {"name": "b.xml", "size": 40, "entries": 0}]}
    r = appdata.prefs_read(c, PKG, "a.xml")
    assert r["entries"] == [{"key": "analytics", "type": "boolean", "value": True},
                            {"key": "user", "type": "string", "value": "bob"},
                            {"key": "n", "type": "int", "value": 3}]
    assert ("cat /data/data/com.x/shared_prefs/a.xml", True) in c.adb.cmds
    with pytest.raises(appmanager.AdbError):
        appdata.prefs_read(c, PKG, "missing.xml")
    with pytest.raises(appmanager.AdbError):
        appdata.prefs_read(c, PKG, "../a.xml")


def test_db_list_and_read_wal_copy(tmp_path):
    import sqlite3
    src = tmp_path / "app.db"
    con = sqlite3.connect(src)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("create table msgs(id integer primary key, body text, blob blob)")
    con.executemany("insert into msgs(body, blob) values(?, ?)", [(f"m{i}", b"\x00\x01") for i in range(5)])
    con.commit()                                    # rows live in the -wal until a checkpoint
    files = {"/data/data/com.x/databases/app.db": src.read_bytes(),
             "/data/data/com.x/databases/app.db-wal": (tmp_path / "app.db-wal").read_bytes(),
             "/data/data/com.x/databases/notes": b"not a database"}
    c = Ctx(files=files, responses={"ls -la": (
        "-rw-rw---- 1 u0_a155 u0_a155 12288 2026-10-15 18:40 app.db\n"
        "-rw-rw---- 1 u0_a155 u0_a155 12392 2026-10-15 18:40 app.db-wal\n"
        "-rw-rw---- 1 u0_a155 u0_a155 32768 2026-10-15 18:40 app.db-shm\n"
        "-rw-rw---- 1 u0_a155 u0_a155 100 2026-10-15 18:40 app.db-journal\n"
        "-rw-rw---- 1 u0_a155 u0_a155 14 2026-10-15 18:40 notes\n"
        "-rw-rw---- 1 u0_a155 u0_a155 14 2026-10-15 18:40 photo.jpg\n")})
    assert appdata.db_list(c, PKG) == {"files": [{"name": "app.db", "size": 12288}, {"name": "notes", "size": 14}]}
    r = appdata.db_read(c, PKG, "app.db")
    assert r["tables"] == [{"name": "msgs", "rows": 5}] and r["table"] is None and r["rows"] == []
    r = appdata.db_read(c, PKG, "app.db", "msgs", 2)
    assert r["columns"] == ["id", "body", "blob"] and r["truncated"] is True
    assert r["rows"] == [[1, "m0", "<blob 2 B>"], [2, "m1", "<blob 2 B>"]]
    with pytest.raises(appmanager.AdbError, match="no such table"):
        appdata.db_read(c, PKG, "app.db", "sqlite_master")
    with pytest.raises(appmanager.AdbError, match="not a SQLite"):
        appdata.db_read(c, PKG, "notes")
    with pytest.raises(appmanager.AdbError):
        appdata.db_read(c, PKG, "app.db", "msgs; drop")
    con.close()
    # every pull went through exec-out cat as root, nothing was executed on the device
    pulls = [(cmd, su) for cmd, su in c.adb.cmds if cmd.startswith("cat ")]
    assert pulls and all(cmd.startswith("cat /data/data/com.x/databases/") and su for cmd, su in pulls)
    assert ("cat /data/data/com.x/databases/app.db-wal", True) in pulls


def test_processes_and_meminfo():
    ps = ("PID   PPID  UID    RSS   S    TIME      NAME\n"
          "4711  680   10155  180000 S   00:04:12  com.whatsapp\n"
          "4790  680   1010155 2000  S   00:00:01  com.whatsapp:push\n"
          "1     0     0      1000  S   01:00:00  init second\n")
    mem = "MemTotal:        7900000 kB\nMemFree: 100 kB\nMemAvailable:    2600000 kB\nSwapTotal: 2000000 kB\nSwapFree: 1200000 kB\n"
    c = Ctx(responses={"ps -A": ps, "cat /proc/meminfo": mem})
    c.maps = SimpleNamespace(all_packages=lambda: {10155: "com.whatsapp"})
    r = appdata.processes(c)
    assert ("ps -A -o PID,PPID,UID,RSS,STAT,TIME,NAME", False) in c.adb.cmds
    assert r["mem"] == {"total_kb": 7900000, "avail_kb": 2600000, "swap_total_kb": 2000000,
                        "swap_free_kb": 1200000}
    by = {p["pid"]: p for p in r["processes"]}
    assert by[4711]["package"] == "com.whatsapp" and by[4711]["rss_kb"] == 180000
    assert by[4790]["package"] == "com.whatsapp" and by[4790]["name"] == "com.whatsapp:push"
    assert by[1]["package"] is None and by[1]["name"] == "init second" and by[1]["cputime"] == "01:00:00"
    assert [p["pid"] for p in r["processes"]] == [4711, 4790, 1]      # by rss, descending


def test_package_uid_fallbacks():
    c = Ctx(responses={"pm list packages": ""})
    assert appdata.package_uid(c, PKG) is None
    c.maps = SimpleNamespace(all_packages=lambda: {10155: PKG})
    assert appdata.package_uid(c, PKG) == 10155 and appdata.package_uid(c, PKG, 10) == 1010155
    c = Ctx()
    assert appdata.package_uid(c, PKG, 10) == UID
    assert c.shell_cmds()[0] == "pm list packages --user 10 -U com.x"


def test_write_device_file_validation():
    c = Ctx()
    for bad in ("relative/path", "/data/../etc", "/data/x y"):
        with pytest.raises(appmanager.AdbError):
            appdata.write_device_file(c, bad, b"x")
    with pytest.raises(appmanager.AdbError):
        appdata.write_device_file(c, "/data/ok", b"x", owner="root:root")
    assert c.adb.pushed == []
    c = Ctx(responses={"(cp": "cp: permission denied"})
    with pytest.raises(appmanager.AdbError, match="write failed"):
        appdata.write_device_file(c, "/data/ok", b"x")
    # the parent is only created on request (system dirs), never for app dirs
    c = Ctx()
    appdata.write_device_file(c, "/data/system/ifw/x.xml", b"x", mkdir=True)
    assert "mkdir -p /data/system/ifw && cp" in c.shell_cmds()[-1]
    appdata.write_device_file(c, "/data/data/com.x/shared_prefs/p.xml", b"x", owner="1:1")
    assert "mkdir" not in c.shell_cmds()[-1] and "chown 1:1" in c.shell_cmds()[-1]


# ---------------- installer ----------------

import zipfile  # noqa: E402

from sentinel.service import installer  # noqa: E402


def _bundle(path, members):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)


def test_extract_apks_is_zip_slip_safe(tmp_path):
    b = tmp_path / "x.xapk"
    _bundle(b, [("base.apk", b"B"), ("splits/split_a.apk", b"S"), ("../../evil.apk", b"E"),
                ("manifest.json", b"{}"), ("Android/obb/x.obb", b"O"), ("dir/", b""),
                ("split_a.apk", b"S2")])
    out = tmp_path / "out"
    out.mkdir()
    files = installer.extract_apks(b, out)
    names = [f.name for f in files]
    assert names[0] == "base.apk" and len(names) == 4
    assert {"base.apk", "split_a.apk", "evil.apk"} < set(names)
    assert any(re.fullmatch(r"\d+_split_a\.apk", n) for n in names)   # duplicate kept, renamed
    assert all(f.parent == out for f in files)
    assert not (tmp_path.parent / "evil.apk").exists() and not (tmp_path / "evil.apk").exists()


def test_install_upload_flags_and_cleanup(tmp_path):
    class A:
        def __init__(self):
            self.calls = []

        def install(self, files, flags, timeout=0):
            self.calls.append((files, flags))
            return True, "Success"
    up = tmp_path / "uploads" / "u1"
    up.mkdir(parents=True)
    b = up / "app.apks"
    _bundle(b, [("base.apk", b"B"), ("split_config.arm64_v8a.apk", b"S")])
    c = SimpleNamespace(adb=A())
    r = installer.install_upload(c, b, {"user": 10, "replace": True, "downgrade": True,
                                        "grant_all": True, "allow_test": True,
                                        "installer": "com.android.vending"})
    assert r == {"ok": True, "output": "Success", "files": ["base.apk", "split_config.arm64_v8a.apk"]}
    files, flags = c.adb.calls[0]
    assert flags == ["-r", "-d", "-g", "-t", "--user", "10", "-i", "com.android.vending"]
    assert [f.rsplit("/", 1)[1] for f in files] == ["base.apk", "split_config.arm64_v8a.apk"]
    assert not up.exists()                                  # upload dir removed afterwards
    up.mkdir()
    one = up / "x.apk"
    one.write_bytes(b"PK")
    r = installer.install_upload(c, one, {"replace": False, "installer": "bad;rm"})
    assert r["ok"] is False and "installer" in r["output"] and not up.exists()
    up.mkdir()
    (up / "x.exe").write_bytes(b"MZ")
    assert installer.install_upload(c, up / "x.exe", {})["ok"] is False


def test_adb_install_builds_command(monkeypatch):
    import subprocess
    from sentinel.adb.client import AdbClient
    calls = []

    class P:
        returncode, stdout, stderr = 0, "Success\n", ""
    monkeypatch.setattr(subprocess, "run", lambda args, **kw: calls.append(args) or P())
    adb = AdbClient(adb_path="adb", serial="S1")
    assert adb.install(["/a/base.apk"], ["-r"]) == (True, "Success")
    assert calls[-1] == ["adb", "-s", "S1", "install", "-r", "/a/base.apk"]
    adb.install(["/a/base.apk", "/a/s.apk"], ["-r", "--user", "0"])
    assert calls[-1] == ["adb", "-s", "S1", "install-multiple", "-r", "--user", "0", "/a/base.apk", "/a/s.apk"]
    assert adb.install([], [])[0] is False
    assert adb.push_file("/l", "/data/local/tmp/x") is True
    assert calls[-1] == ["adb", "-s", "S1", "push", "/l", "/data/local/tmp/x"]


def test_restore_job_flow(tmp_path):
    import json
    from sentinel.service.backup import BackupService
    hub = SimpleNamespace(cfg=SimpleNamespace(data_dir=tmp_path))
    hub.backup = BackupService(hub)
    d = hub.backup.root / "FAKE123" / "com.x_20261001-100000"
    (d / "apk").mkdir(parents=True)
    (d / "apk" / "1_split.apk").write_bytes(b"S")
    (d / "apk" / "0_base.apk").write_bytes(b"B")
    (d / "data.tar").write_bytes(b"T" * 100)
    (d / "manifest.json").write_text(json.dumps({"package": PKG, "serial": "FAKE123"}))

    class A(FakeAdb):
        def __init__(self):
            super().__init__()
            self.installs = []

        def install(self, files, flags, timeout=0):
            self.installs.append((files, flags))
            if len(self.installs) == 1:
                return False, "Failure [INSTALL_FAILED_TEST_ONLY]"
            return True, "Success"

        def shell_sync(self, cmd, su=False, timeout=60):
            self.cmds.append((cmd, su))
            if cmd.startswith("pm list packages"):
                return PM_LIST
            return "RESTORED\n" if "tar -xf" in cmd else ""
    c = Ctx()
    c.adb = A()
    c.hub = hub
    with pytest.raises(appmanager.AdbError):
        installer.new_restore_job(hub, c, "../etc", True, True)
    with pytest.raises(appmanager.AdbError):
        installer.new_restore_job(hub, c, "com.x_nope", True, True)
    job = installer.new_restore_job(hub, c, "com.x_20261001-100000", True, True)
    assert job["type"] == "restore" and job["pkg"] == PKG and hub.backup.jobs[job["id"]] is job
    installer.run_restore(hub, c, job)
    assert job["state"] == "done", job
    files, flags = c.adb.installs[0]
    assert [f.rsplit("/", 1)[1] for f in files] == ["0_base.apk", "1_split.apk"] and flags == ["-r"]
    assert c.adb.installs[1][1] == ["-r", "-t"]              # retried for a test-only build
    remote, data = c.adb.pushed[0]
    assert remote.startswith("/data/local/tmp/sentinel-") and remote.endswith(".tar") and data == b"T" * 100
    su_cmds = [cmd for cmd, su in c.adb.cmds if su]
    assert any(f"tar -xf {remote} -C /data/data && chown -R {UID}:{UID} /data/data/com.x "
               "&& restorecon -R /data/data/com.x" in cmd for cmd in su_cmds)
    assert ("am force-stop com.x", False) in c.adb.cmds and (f"rm -f {remote}", False) in c.adb.cmds
    assert not any("pm clear" in cmd for cmd, _ in c.adb.cmds)
    kinds = [e.title for e in c.events]
    assert kinds == ["Restore started: com.x", "Restore complete: com.x"]
    assert all(e.kind == "app.backup" for e in c.events)
