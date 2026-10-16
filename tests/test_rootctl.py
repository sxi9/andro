"""Root / su probing against canned shells."""
from __future__ import annotations

from sentinel.adb.client import AdbError
from sentinel.service import rootctl


class FakeAdb:
    def __init__(self, answers: dict, use_su: bool = True):
        self.answers = answers
        self.use_su = use_su
        self.cmds: list[tuple[str, bool, float]] = []

    def shell_sync(self, cmd, su=False, timeout=20):
        self.cmds.append((cmd, su, timeout))
        a = self.answers.get(cmd)
        if a is None:
            raise AdbError(f"adb shell failed (127): {cmd.split()[0]}: not found")
        if isinstance(a, Exception):
            raise a
        return a


class Store:
    def __init__(self):
        self.snaps = {}

    def get_snapshot(self, k):
        return self.snaps.get(k)

    def put_snapshot(self, k, v):
        self.snaps[k] = v


class Ctx:
    def __init__(self, answers, use_su=True):
        self.adb = FakeAdb(answers, use_su)
        self.device = {"serial": "X", "root": False}
        self.store = Store()


def test_status_magisk():
    c = Ctx({"id": "uid=2000(shell) gid=2000(shell)", "su -c id": "uid=0(root) gid=0(root)",
             "command -v su || which su": "/debug_ramdisk/su", "su -v": "27.0:MAGISK",
             "magisk -v": "27.0:MAGISK:R", "getenforce": "Enforcing"})
    s = rootctl.root_status(c)
    assert s["root"] is True and s["adbd_root"] is False
    assert s["su_path"] == "/debug_ramdisk/su"
    assert s["manager"] == {"name": "Magisk", "version": "27.0:MAGISK:R"}
    assert s["selinux"] == "Enforcing" and s["use_su"] is True and "error" not in s
    assert c.device["root"] is True
    assert all(t <= 8 for _, _, t in c.adb.cmds)


def test_status_kernelsu_and_apatch():
    c = Ctx({"id": "uid=2000(shell)", "su -c id": "uid=0(root)", "su -v": "1.0.3:KernelSU",
             "getenforce": "Permissive"})
    s = rootctl.root_status(c)
    assert s["manager"] == {"name": "KernelSU", "version": "1.0.3:KernelSU"}
    assert s["selinux"] == "Permissive" and s["su_path"] is None
    c = Ctx({"id": "uid=2000(shell)", "su -c id": "uid=0(root)", "su -v": "10.7.0:APatch"})
    assert rootctl.root_status(c)["manager"]["name"] == "APatch"
    # no `su -v` answer: the provider daemons under /data/adb name the manager
    c = Ctx({"id": "uid=2000(shell)", "su -c id": "uid=0(root)",
             "ls /data/adb/ksud /data/adb/apd /data/adb/magisk 2>/dev/null": "/data/adb/ksud"})
    assert rootctl.root_status(c)["manager"] == {"name": "KernelSU", "version": None}


def test_status_without_root():
    c = Ctx({"id": "uid=2000(shell) gid=2000(shell)", "getenforce": "Enforcing"}, use_su=False)
    s = rootctl.root_status(c)
    assert s == {"root": False, "su_path": None, "manager": {"name": None, "version": None},
                 "adbd_root": False, "selinux": "Enforcing", "use_su": False}
    assert c.device["root"] is False


def test_status_adbd_root():
    c = Ctx({"id": "uid=0(root) gid=0(root) context=u:r:su:s0", "su -c id": "uid=0(root)",
             "getenforce": "Permissive"})
    s = rootctl.root_status(c)
    assert s["adbd_root"] is True and s["root"] is True
    assert s["manager"]["name"] == "unknown"            # su works but nothing names it


def test_request_root():
    c = Ctx({"su -c id": "uid=0(root) gid=0(root)"})
    r = rootctl.request_root(c)
    assert r == {"ok": True, "root": True, "output": "uid=0(root) gid=0(root)"}
    assert c.adb.cmds == [("su -c id", False, 45)] and c.device["root"] is True
    c = Ctx({"su -c id": "Permission denied"})
    r = rootctl.request_root(c)
    assert r["ok"] is False and r["root"] is False and r["output"] == "Permission denied"
    c = Ctx({})
    r = rootctl.request_root(c)
    assert r["ok"] is False and "not found" in r["output"]


def test_set_use_su_persists():
    c = Ctx({})
    assert rootctl.set_use_su(c, False) == {"ok": True, "use_su": False}
    assert c.adb.use_su is False and c.store.snaps["use_su"] is False
    assert rootctl.set_use_su(c, 1) == {"ok": True, "use_su": True}
    assert c.adb.use_su is True and c.store.snaps["use_su"] is True


def test_adb_root_unroot_never_raise(monkeypatch):
    import subprocess
    from sentinel.adb.client import AdbClient
    calls = []

    class P:
        def __init__(self, rc, out, err=""):
            self.returncode, self.stdout, self.stderr = rc, out, err

    def fake_run(args, **kw):
        calls.append(args)
        if args[-1] == "root":
            return P(1, "adbd cannot run as root in production builds\n")
        return P(0, "restarting adbd as non root\n")
    monkeypatch.setattr(subprocess, "run", fake_run)
    adb = AdbClient(adb_path="adb", serial="S1")
    ok, out = adb.root()
    assert ok is False and "production" in out and calls[-1] == ["adb", "-s", "S1", "root"]
    ok, out = adb.unroot()
    assert ok is True and calls[-1] == ["adb", "-s", "S1", "unroot"]

    def boom(args, **kw):
        raise FileNotFoundError("adb")
    monkeypatch.setattr(subprocess, "run", boom)
    ok, out = adb.root()
    assert ok is False and "not found" in out


def test_context_applies_persisted_use_su(tmp_path):
    from sentinel.config import Config
    from sentinel.context import DeviceContext, Hub
    hub = Hub(Config(data_dir=tmp_path, demo=False, use_su=True))
    hub.store.put_snapshot("S1:use_su", False)
    try:
        assert DeviceContext(hub, "S1").adb.use_su is False
        assert DeviceContext(hub, "S2").adb.use_su is True
    finally:
        hub.store.close()
