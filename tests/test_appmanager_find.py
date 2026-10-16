"""find_package / handlers / multi-user list_apps against a canned adb.

The fake device has two users (0 "rexintone", 10 "Work profile"); Chrome is
uninstalled for user 0 (only visible with -u) but installed for user 10.
"""
from __future__ import annotations

import re

import pytest

from sentinel.service import appmanager

WEBAPK = "org.chromium.webapk.ae2b93f705916af0e_v2"
CHROME = "com.android.chrome"

_USERS = ("Users:\n\tUserInfo{0:rexintone:c13} running\n"
          "\tUserInfo{10:Work profile:1030} running\n")

# per user: (installed, uninstalled-for-user i.e. only listed with -u)
_PKGS = {
    0: (["com.a", WEBAPK], [CHROME]),
    10: (["com.a", CHROME], []),
}

_LS = ("/system/app:\nBluetooth\nStk\n\n"
       "/product/app:\nChrome\nWebViewGoogle\n\n"
       "/product/priv-app:\nVelvet\n")

_LS_DATA = ("/data/app/~~abc==/org.cromite.cromite-xyz==/\n"
            "/data/app/~~def==/com.a-123==/\n")

_QA_BROWSER = ("3 activities found:\n"
               "  priority=0 preferredOrder=0 match=0x500000 specificIndex=-1 isDefault=true\n"
               "  org.cromite.cromite/org.chromium.chrome.browser.ChromeTabbedActivity\n"
               "  priority=0 preferredOrder=0 match=0x500000 specificIndex=-1 isDefault=true\n"
               "  org.cromite.cromite/.IntentDispatcher\n"
               "  priority=0 preferredOrder=0 match=0x500000 specificIndex=-1 isDefault=false\n"
               "  org.mozilla.firefox/.App\n")
_QA_HOME = ("1 activities found:\n"
            "  priority=1 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=true\n"
            "  com.android.launcher3/.Launcher\n")
_QA_DIAL = ("1 activities found:\n"
            "  priority=0 preferredOrder=0 match=0x300000 specificIndex=-1 isDefault=true\n"
            "  com.google.android.dialer/.DialtactsActivity\n")

_USER_ARG = re.compile(r"--user (\d+)")


class FakeAdb:
    def __init__(self, browser_role: str = "org.cromite.cromite\n",
                 resolve: str = "No activity found\n"):
        self.cmds: list[tuple[str, bool]] = []
        self.browser_role = browser_role
        self.resolve = resolve

    def shell_sync(self, cmd, su=False, timeout=60):
        self.cmds.append((cmd, su))
        toks = cmd.split()
        if cmd.startswith("pm list users"):
            return _USERS
        if cmd.startswith("pm list packages"):
            m = _USER_ARG.search(cmd)
            user = int(m.group(1)) if m else 0
            if "-s" in toks:
                return f"package:/product/app/Chrome/Chrome.apk={CHROME}\n"
            if "-d" in toks:
                return ""
            inst, gone = _PKGS[user]
            pkgs = inst + (gone if "-u" in toks else [])
            return "".join(f"package:/p/{p}.apk={p} installer=null uid:10001\n" for p in pkgs)
        if cmd.startswith("cmd role get-role-holders"):
            if cmd.endswith("android.app.role.BROWSER"):
                return self.browser_role
            if cmd.endswith("android.app.role.HOME"):
                return "com.android.launcher3\n"
            return "\n"
        if cmd.startswith("pm query-activities"):
            if "android.intent.category.BROWSABLE" in cmd:
                return _QA_BROWSER
            if "android.intent.category.HOME" in cmd:
                return _QA_HOME
            if "android.intent.action.DIAL" in cmd:
                return _QA_DIAL
            if "android.intent.action.SENDTO" in cmd:
                return "No activities found\n"
            return ""
        if cmd.startswith("pm resolve-activity"):
            return self.resolve
        if cmd.startswith("ls -1 /system/app"):
            return _LS
        if cmd.startswith("ls -d /data/app/"):
            return _LS_DATA if su else ""
        if cmd.startswith("dumpsys package"):
            return "Packages:\n  Package [com.android.chrome] (1):\n    versionCode=1 minSdk=24 targetSdk=34\n"
        if cmd.startswith("dumpsys appops"):
            return ""
        if cmd.startswith("pm path"):
            return "package:/product/app/Chrome/Chrome.apk\n"
        raise AssertionError(f"unexpected command: {cmd}")

    def apk_paths(self, pkg):
        return ["/product/app/Chrome/Chrome.apk"]


class Store:
    def __init__(self, snaps=None):
        self.snaps = snaps or {}

    def get_snapshot(self, k):
        return self.snaps.get(k)

    def put_snapshot(self, k, v):
        self.snaps[k] = v


class Ctx:
    def __init__(self, root: bool = False, snaps=None, **adb_kw):
        self.adb = FakeAdb(**adb_kw)
        self.state = {"device": {"root": root}}
        self.store = Store(snaps)


def _user_args_are_ints(adb: FakeAdb) -> None:
    for cmd, _su in adb.cmds:
        if "--user" in cmd:
            assert re.search(r"--user \d+(\s|$)", cmd), cmd


def test_find_chrome_across_users():
    c = Ctx()
    res = appmanager.find_package(c, "chr")
    assert "error" not in res
    assert [u["id"] for u in res["users"]] == [0, 10]
    assert res["users"][0]["name"] == "rexintone"
    assert res["scanned"] == 3
    by = {m["package"]: m for m in res["matches"]}
    assert set(by) == {CHROME, WEBAPK}
    # uninstalled for the owner (seen only with -u) but live in the work profile
    assert by[CHROME]["users"] == [{"id": 0, "installed": False}, {"id": 10, "installed": True}]
    assert by[CHROME]["label"] == "Chrome" and by[CHROME]["system"] is True
    assert by[WEBAPK]["users"] == [{"id": 0, "installed": True}, {"id": 10, "installed": False}]
    assert by[WEBAPK]["system"] is False
    # APK folder scan: only basenames containing the query
    assert res["apk_dirs"] == ["/product/app/Chrome"]
    # browsers from query-activities, deduped per package, default from the role
    assert [b["package"] for b in res["browsers"]] == ["org.cromite.cromite", "org.mozilla.firefox"]
    assert res["browsers"][0]["default"] is True and res["browsers"][1]["default"] is False
    assert res["browsers"][0]["component"] == \
        "org.cromite.cromite/org.chromium.chrome.browser.ChromeTabbedActivity"
    # every per-user listing used -u for the "exists at all" set
    assert any("--user 10" in cmd and "-u" in cmd.split() for cmd, _ in c.adb.cmds)
    # no su command without root
    assert not any(su for _, su in c.adb.cmds)
    _user_args_are_ints(c.adb)


def test_find_matches_label_case_insensitive():
    c = Ctx()
    res = appmanager.find_package(c, "CHROME")
    assert [m["package"] for m in res["matches"]] == [CHROME]
    assert res["query"] == "CHROME"


@pytest.mark.parametrize("bad", ["chr;ls", "chr$(id)", "a|b", "", "   ", "x" * 65, "ch\nrome"])
def test_find_rejects_bad_query_without_touching_adb(bad):
    c = Ctx()
    res = appmanager.find_package(c, bad)
    assert res["error"] == "invalid query"
    assert res["matches"] == [] and res["apk_dirs"] == [] and res["browsers"] == []
    assert c.adb.cmds == []


def test_find_root_scans_data_app_with_su():
    c = Ctx(root=True)
    res = appmanager.find_package(c, "cromite")
    assert "/data/app/~~abc==/org.cromite.cromite-xyz==" in res["apk_dirs"]
    assert "/data/app/~~def==/com.a-123==" not in res["apk_dirs"]
    su_cmds = [cmd for cmd, su in c.adb.cmds if su]
    assert su_cmds == ["ls -d /data/app/*/*/ 2>/dev/null"]
    # the root flag is also honoured on a real DeviceContext (dctx.device)
    c2 = Ctx()
    c2.device = {"root": True}
    assert "/data/app/~~abc==/org.cromite.cromite-xyz==" in appmanager.find_package(c2, "cromite")["apk_dirs"]


def test_handlers_roles_and_query_activities():
    c = Ctx()
    res = appmanager.handlers(c, 0)
    assert res["user"] == 0
    assert res["roles"] == {"browser": ["org.cromite.cromite"], "home": ["com.android.launcher3"],
                            "sms": [], "dialer": [], "assistant": []}
    h = res["handlers"]
    assert set(h) == {"browser", "launcher", "sms", "dialer", "camera"}
    assert [x["package"] for x in h["browser"]] == ["org.cromite.cromite", "org.mozilla.firefox"]
    assert h["browser"][1] == {"package": "org.mozilla.firefox", "label": "Firefox",
                               "component": "org.mozilla.firefox/.App"}
    assert h["launcher"] == [{"package": "com.android.launcher3", "label": "Launcher3",
                              "component": "com.android.launcher3/.Launcher"}]
    assert [x["package"] for x in h["dialer"]] == ["com.google.android.dialer"]
    assert h["sms"] == [] and h["camera"] == []
    assert res["default_browser"] == "org.cromite.cromite"
    # role comes first, so no resolve-activity fallback was needed
    assert not any(cmd.startswith("pm resolve-activity") for cmd, _ in c.adb.cmds)
    # the five role lookups and five intent queries are all user-scoped
    assert sum(1 for cmd, _ in c.adb.cmds if cmd.startswith("cmd role get-role-holders --user 0 ")) == 5
    assert sum(1 for cmd, _ in c.adb.cmds if cmd.startswith("pm query-activities --brief --user 0 ")) == 5
    _user_args_are_ints(c.adb)
    res10 = appmanager.handlers(c, 10)
    assert res10["user"] == 10
    assert all("--user 10" in cmd for cmd, _ in c.adb.cmds[10:] if "--user" in cmd)


def test_handlers_rejects_bad_user():
    c = Ctx()
    for bad in (-1, 1000, "x", None):
        res = appmanager.handlers(c, bad)
        assert res["error"] == "invalid user id"
        assert res["roles"]["browser"] == [] and res["default_browser"] is None
    assert c.adb.cmds == []


def test_handlers_default_browser_fallback():
    # no role holder + the system resolver => no default
    c = Ctx(browser_role="\n",
            resolve=("priority=0 preferredOrder=0 match=0x500000 specificIndex=-1 isDefault=true\n"
                     "android/com.android.internal.app.ResolverActivity\n"))
    res = appmanager.handlers(c, 0)
    assert res["roles"]["browser"] == [] and res["default_browser"] is None
    assert any(cmd.startswith("pm resolve-activity --brief --user 0 ") for cmd, _ in c.adb.cmds)
    # no role service (error text) + a concrete resolution => that package
    c = Ctx(browser_role="cmd: Can't find service: role\n",
            resolve=("priority=0 preferredOrder=0 match=0x500000 specificIndex=-1 isDefault=true\n"
                     "org.mozilla.firefox/.App\n"))
    res = appmanager.handlers(c, 0)
    assert res["roles"]["browser"] == [] and res["default_browser"] == "org.mozilla.firefox"


def test_list_apps_all_users_unions_with_users_installed():
    meta = {WEBAPK: {"host_browser": "org.cromite.cromite", "start_url": "https://example.org/"}}
    c = Ctx(snaps={"apk_meta": meta})
    res = appmanager.list_apps(c, "all", user="all")
    assert res["user"] == "all" and "error" not in res
    assert [u["id"] for u in res["users"]] == [0, 10]
    by = {a["package"]: a for a in res["apps"]}
    assert set(by) == {"com.a", CHROME, WEBAPK}
    assert by["com.a"]["users_installed"] == [0, 10]
    assert by[CHROME]["users_installed"] == [10] and by[CHROME]["installed"] is True
    assert by[WEBAPK]["users_installed"] == [0]
    assert by[WEBAPK]["meta"] == meta[WEBAPK] and "meta" not in by[CHROME]
    assert res["uninstalled"] == 0 and res["count"] == 3
    assert all(a["enabled"] for a in res["apps"])
    # both users were listed, with and without -u
    assert any("--user 0" in cmd and "-u" in cmd.split() for cmd, _ in c.adb.cmds)
    assert any("--user 10" in cmd and "-u" not in cmd.split() for cmd, _ in c.adb.cmds)
    _user_args_are_ints(c.adb)


def test_list_apps_single_user_users_installed():
    c = Ctx()
    res = appmanager.list_apps(c, "all", user=0)
    by = {a["package"]: a for a in res["apps"]}
    assert res["user"] == 0
    assert by[CHROME]["installed"] is False and by[CHROME]["users_installed"] == []
    assert by["com.a"]["users_installed"] == [0]
    assert res["uninstalled"] == 1
    # omitted user keeps pm's owner default (no --user) and reports user 0
    start = len(c.adb.cmds)
    res = appmanager.list_apps(c, "all")
    assert res["user"] == 0
    assert {a["package"]: a["users_installed"] for a in res["apps"]} == \
        {"com.a": [0], WEBAPK: [0], CHROME: []}
    assert not any("--user" in cmd for cmd, _ in c.adb.cmds[start:])
    _user_args_are_ints(c.adb)
    # uninstalled-only view across users: chrome is installed somewhere, so none
    assert appmanager.list_apps(c, "uninstalled", user="all")["apps"] == []
    assert [a["package"] for a in appmanager.list_apps(c, "uninstalled", user=0)["apps"]] == [CHROME]


def test_app_detail_users_installed_and_meta():
    meta = {CHROME: {"host_browser": "org.cromite.cromite", "start_url": "https://x/", "scope": "https://x/"}}
    c = Ctx(snaps={"apk_meta": meta})
    res = appmanager.app_detail(c, CHROME)
    assert res["users_installed"] == [10]
    assert res["meta"] == meta[CHROME]
    assert res["detail"]["version"] == 1
    assert "meta" not in appmanager.app_detail(c, "com.a")
    assert appmanager.app_detail(c, "com.a")["users_installed"] == [0, 10]
    _user_args_are_ints(c.adb)


def test_ls_paths_parser():
    assert appmanager._ls_paths(_LS) == [
        "/system/app/Bluetooth", "/system/app/Stk", "/product/app/Chrome",
        "/product/app/WebViewGoogle", "/product/priv-app/Velvet"]
    assert appmanager._ls_paths("") == []
    # entries before any header (single-dir ls) are ignored rather than mis-pathed
    assert appmanager._ls_paths("Chrome\nStk\n") == []
