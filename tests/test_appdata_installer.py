"""appdata writes and installer restore / bundle handling against a recording
fake adb, plus the staged-write shell chain run for real on a local tmp dir."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel.adb.client import AdbError
from sentinel.service import appdata, installer

PKG = "com.x"
UID = 10234
PM_LIST = (f"package:/data/app/x/base.apk={PKG} installer=null uid:{UID}\n"
           "package:/data/app/y/base.apk=com.y installer=null uid:10235\n")
PREFS = (b"<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n"
         b"<map>\n    <string name=\"user\">bob</string>\n</map>\n")


class FakeAdb:
    use_su = True

    def __init__(self, responses=None, files=None):
        self.cmds: list[tuple[str, bool]] = []
        self.pushed: list[tuple[str, bytes]] = []
        self.responses = responses or {}
        self.files = files or {}

    def shell_sync(self, cmd, su=False, timeout=60):
        self.cmds.append((cmd, su))
        for prefix, out in self.responses.items():
            if cmd.startswith(prefix):
                return out(cmd) if callable(out) else out
        if "echo WROTE" in cmd:
            return "WROTE\n"
        if cmd.startswith("pm list packages --user 10"):
            return PM_LIST.replace(f"uid:{UID}", f"uid:{UID + 1000000}")
        if cmd.startswith("pm list packages"):
            return PM_LIST
        return ""

    def exec_out_bytes(self, cmd, su=False, timeout=60):
        self.cmds.append((cmd, su))
        m = re.match(r"cat (\S+)", cmd)
        return self.files.get(m.group(1), b"") if m else b""

    def push_file(self, local, remote, timeout=600):
        self.pushed.append((remote, Path(local).read_bytes()))
        return True

    def list_dir(self, path, su=True, timeout=0):
        return self.shell_sync(f"ls -la {path}", su=su)


class Ctx:
    def __init__(self, **adb_kw):
        self.adb = FakeAdb(**adb_kw)
        self.state = {}
        self.device = {"root": True}
        self.serial = "FAKE123"
        self.events = []

    def emit_threadsafe(self, ev):
        self.events.append(ev)

    def su_cmds(self):
        return [c for c, su in self.adb.cmds if su]


# ---------------- #2: writes never follow an app-planted symlink ----------------

def test_write_device_file_stages_and_renames():
    c = Ctx()
    appdata.write_device_file(c, "/data/data/com.x/shared_prefs/p.xml", b"x", mode="660",
                              owner="1:1")
    cmd = c.su_cmds()[-1]
    m = re.fullmatch(
        r"\(test -d /data/data/com\.x/shared_prefs && test ! -L /data/data/com\.x/shared_prefs"
        r" && cp (/data/local/tmp/sentinel-[0-9a-f]{32}) (/data/data/com\.x/shared_prefs/\.sentinel-[0-9a-f]{32}\.tmp)"
        r" && chmod 660 \2 && chown 1:1 \2 && restorecon \2"
        r" && test ! -L /data/data/com\.x/shared_prefs/p\.xml"
        r" && \( test ! -e /data/data/com\.x/shared_prefs/p\.xml \|\| test -f /data/data/com\.x/shared_prefs/p\.xml \)"
        r" && mv -f \2 /data/data/com\.x/shared_prefs/p\.xml && echo WROTE\); rm -f \1 \2", cmd)
    assert m, cmd
    assert "chown 1:1 /data/data/com.x/shared_prefs/p.xml" not in cmd   # never chown the target path
    # system dirs are created on request and need no parent check
    appdata.write_device_file(c, "/data/system/ifw/x.xml", b"x", mkdir=True, restorecon=False)
    cmd = c.su_cmds()[-1]
    assert cmd.startswith("(mkdir -p /data/system/ifw && cp /data/local/tmp/sentinel-")
    assert "test ! -L /data/system/ifw/x.xml" in cmd and "mv -f /data/system/ifw/.sentinel-" in cmd
    assert "restorecon" not in cmd and "chown" not in cmd
    # a refused chain (no WROTE) is an error that names the cause
    c = Ctx(responses={"(test -d": ""})
    with pytest.raises(AdbError, match="write failed: target is not a regular file"):
        appdata.write_device_file(c, "/data/data/com.x/shared_prefs/p.xml", b"x")


class LocalShellAdb:
    """Runs the root chain with the local /bin/sh: /data/local/tmp becomes a
    tmp dir so the staged copy + rename really happen on disk."""
    use_su = False

    def __init__(self, staging: Path):
        self.staging = staging
        self.cmds: list[str] = []

    def push_file(self, local, remote, timeout=600):
        shutil.copyfile(local, self.staging / Path(remote).name)
        return True

    def shell_sync(self, cmd, su=False, timeout=60):
        cmd = cmd.replace("/data/local/tmp/", f"{self.staging}/")
        self.cmds.append(cmd)
        p = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True, timeout=20)
        return p.stdout


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX sh")
def test_write_device_file_real_shell_refuses_symlinks(tmp_path):
    if not re.fullmatch(r"[A-Za-z0-9_./\-]+", str(tmp_path)):
        pytest.skip("tmp path has characters the remote-path rule rejects")
    staging = tmp_path / "staging"
    staging.mkdir()
    prefs = tmp_path / "shared_prefs"
    prefs.mkdir()
    c = SimpleNamespace(adb=LocalShellAdb(staging))
    kw = dict(mode="600", restorecon=False)
    # a regular file is replaced, a missing one created, nothing else is left behind
    (prefs / "a.xml").write_bytes(b"old")
    appdata.write_device_file(c, f"{prefs}/a.xml", b"new", **kw)
    appdata.write_device_file(c, f"{prefs}/b.xml", b"fresh", **kw)
    assert (prefs / "a.xml").read_bytes() == b"new" and (prefs / "b.xml").read_bytes() == b"fresh"
    assert sorted(p.name for p in prefs.iterdir()) == ["a.xml", "b.xml"]
    assert list(staging.iterdir()) == []
    # a symlink at the target is refused and its target untouched
    victim = tmp_path / "victim.sh"
    victim.write_bytes(b"keep")
    (prefs / "evil.xml").symlink_to(victim)
    with pytest.raises(AdbError, match="write failed"):
        appdata.write_device_file(c, f"{prefs}/evil.xml", b"owned", **kw)
    assert victim.read_bytes() == b"keep" and (prefs / "evil.xml").is_symlink()
    assert sorted(p.name for p in prefs.iterdir()) == ["a.xml", "b.xml", "evil.xml"]
    assert list(staging.iterdir()) == []
    # a symlinked parent directory is refused before anything is copied
    other = tmp_path / "elsewhere"
    other.mkdir()
    link_dir = tmp_path / "linked_prefs"
    link_dir.symlink_to(other)
    with pytest.raises(AdbError, match="write failed"):
        appdata.write_device_file(c, f"{link_dir}/c.xml", b"x", **kw)
    assert list(other.iterdir()) == [] and list(staging.iterdir()) == []
    # a directory at the target is refused too
    (prefs / "d.xml").mkdir()
    with pytest.raises(AdbError, match="write failed"):
        appdata.write_device_file(c, f"{prefs}/d.xml", b"x", **kw)
    assert (prefs / "d.xml").is_dir()


# ---------------- #40: an empty read never rewrites a real file ----------------

def _set(c, **kw):
    return appdata.prefs_set(c, PKG, "p.xml", "k", "string", "v", **kw)


def test_prefs_set_refuses_when_read_failed():
    # cat printed nothing but the file is there and non-empty: a failed read
    c = Ctx(responses={"if test -e": "NONEMPTY\n"})
    with pytest.raises(AdbError, match="could not read the prefs file"):
        _set(c)
    assert c.adb.pushed == [] and not any("mv -f" in cmd for cmd in c.su_cmds())
    assert any(cmd.startswith("if test -e /data/data/com.x/shared_prefs/p.xml; then test -s")
               for cmd in c.su_cmds())
    # the probe itself answered nothing usable (no root / odd shell): refuse too
    c = Ctx()
    with pytest.raises(AdbError, match="could not read the prefs file"):
        _set(c)
    assert c.adb.pushed == []
    c = Ctx(responses={"if test -e": lambda cmd: (_ for _ in ()).throw(AdbError("adb shell failed (1)"))})
    with pytest.raises(AdbError):
        _set(c)
    assert c.adb.pushed == []


def test_prefs_set_creates_absent_or_empty_file():
    for mark in ("ABSENT\n", "EMPTY\n"):
        c = Ctx(responses={"if test -e": mark})
        assert _set(c) == "set"
        xml = c.adb.pushed[-1][1].decode()
        assert xml.endswith('<map><string name="k">v</string></map>\n')
        assert f"chown {UID}:{UID}" in c.su_cmds()[-1]


def test_prefs_set_existing_file_needs_no_probe():
    c = Ctx(files={"/data/data/com.x/shared_prefs/p.xml": PREFS})
    assert _set(c) == "set"
    assert not any(cmd.startswith("if test -e") for cmd, _ in c.adb.cmds)
    xml = c.adb.pushed[-1][1].decode()
    assert '<string name="user">bob</string>' in xml and '<string name="k">v</string>' in xml


# ---------------- #42: the selected user's copy, with that user's uid ----------------

def test_prefs_paths_and_uid_follow_the_user():
    files = {"/data/user/10/com.x/shared_prefs/p.xml": PREFS}
    c = Ctx(files=files)
    assert _set(c, user=10) == "set"
    assert ("cat /data/user/10/com.x/shared_prefs/p.xml", True) in c.adb.cmds
    assert ("pm list packages --user 10 -U com.x", False) in c.adb.cmds
    cmd = c.su_cmds()[-1]
    assert "mv -f /data/user/10/com.x/shared_prefs/.sentinel-" in cmd
    assert cmd.rstrip().count("/data/data/") == 0
    assert f"chown {UID + 1000000}:{UID + 1000000}" in cmd
    # the uid is normalised into the user's range even when only user 0's answers
    c = Ctx(files=files, responses={"pm list packages --user 10": "", "pm list packages": PM_LIST})
    assert _set(c, user=10) == "set"
    assert f"chown {UID + 1000000}:{UID + 1000000}" in c.su_cmds()[-1]
    # user 0 keeps the canonical /data/data path
    c = Ctx(files={"/data/data/com.x/shared_prefs/p.xml": PREFS})
    assert appdata.prefs_delete(c, PKG, "p.xml", "user", user=0) == "deleted"
    assert "mv -f /data/data/com.x/shared_prefs/.sentinel-" in c.su_cmds()[-1]
    assert f"chown {UID}:{UID}" in c.su_cmds()[-1]
    # reads and listings take the same keyword
    c = Ctx(files=files, responses={"ls -la": "total 1\n-rw-rw---- 1 u0_a234 u0_a234 300 2026-10-15 10:00 p.xml\n"})
    assert appdata.prefs_read(c, PKG, "p.xml", user=10)["entries"] == [
        {"key": "user", "type": "string", "value": "bob"}]
    assert appdata.prefs_list(c, PKG, user=10)["files"] == [{"name": "p.xml", "size": 300, "entries": 1}]
    assert ("ls -la /data/user/10/com.x/shared_prefs", True) in c.adb.cmds
    for bad in (-1, 1000, "x"):
        with pytest.raises(AdbError, match="invalid user id"):
            appdata.prefs_read(c, PKG, "p.xml", user=bad)
        with pytest.raises(AdbError, match="invalid user id"):
            _set(c, user=bad)


# ---------------- #11 / #34 / #35: restore replaces the data, fixes ownership always ----------------

def _backup(tmp_path, manifest_extra=None):
    from sentinel.service.backup import BackupService
    hub = SimpleNamespace(cfg=SimpleNamespace(data_dir=tmp_path))
    hub.backup = BackupService(hub)
    d = hub.backup.root / "FAKE123" / "com.x_20261001-100000"
    d.mkdir(parents=True)
    (d / "data.tar").write_bytes(b"T" * 100)
    (d / "manifest.json").write_text(json.dumps({"package": PKG, "serial": "FAKE123",
                                                 **(manifest_extra or {})}))
    return hub


def test_restore_chain_clears_fixes_ownership_and_reports_tar_errors(tmp_path):
    hub = _backup(tmp_path)
    c = Ctx(responses={"find /data/data/com.x": "RESTORED\n"})
    c.hub = hub
    job = installer.new_restore_job(hub, c, "com.x_20261001-100000", False, True)
    installer.run_restore(hub, c, job)
    assert job["state"] == "done", job
    remote = c.adb.pushed[0][0]
    cmd = [cmd for cmd in c.su_cmds() if "tar -xf" in cmd][0]
    assert cmd == (
        "find /data/data/com.x -mindepth 1 -maxdepth 1 ! -name lib -exec rm -rf {} + 2>/dev/null; "
        f"tar -xf {remote} -C /data/data 2>&1; rc=$?; "
        f"chown -R {UID}:{UID} /data/data/com.x; "
        f"chown -R {UID}:{UID + 10000} /data/data/com.x/cache /data/data/com.x/code_cache 2>/dev/null; "
        "chmod 02771 /data/data/com.x/cache /data/data/com.x/code_cache 2>/dev/null; "
        "restorecon -RD /data/data/com.x; "
        'test "$rc" = 0 && echo RESTORED')
    assert ("am force-stop com.x", False) in c.adb.cmds and (f"rm -f {remote}", False) in c.adb.cmds
    assert not any("pm clear" in cmd for cmd, _ in c.adb.cmds)
    # tar failed: the same single command already ran chown/restorecon, and the
    # job reports tar's own message
    hub = _backup(tmp_path / "b2")
    c = Ctx(responses={"find /data/data/com.x": "tar: short read\n"})
    c.hub = hub
    job = installer.new_restore_job(hub, c, "com.x_20261001-100000", False, True)
    installer.run_restore(hub, c, job)
    assert job["state"] == "error" and job["error"] == "data restore failed: tar: short read"
    assert (f"rm -f {c.adb.pushed[0][0]}", False) in c.adb.cmds
    assert c.events[-1].title == "Restore failed: com.x"
    # no stdout at all (su missing): still an error, not a crash
    def boom(cmd):
        raise AdbError("adb shell failed (1): su: not found")
    hub = _backup(tmp_path / "b3")
    c = Ctx(responses={"find /data/data/com.x": boom})
    c.hub = hub
    job = installer.new_restore_job(hub, c, "com.x_20261001-100000", False, True)
    installer.run_restore(hub, c, job)
    assert job["state"] == "error" and "su: not found" in job["error"]


def test_restore_cache_gid_only_for_app_ids(tmp_path):
    hub = _backup(tmp_path)
    c = Ctx(responses={"find /data/data/com.x": "RESTORED\n",
                       "pm list packages": PM_LIST.replace(f"uid:{UID}", "uid:1000")})
    c.hub = hub
    job = installer.new_restore_job(hub, c, "com.x_20261001-100000", False, True)
    installer.run_restore(hub, c, job)
    assert job["state"] == "done", job
    cmd = [cmd for cmd in c.su_cmds() if "tar -xf" in cmd][0]
    assert "chown -R 1000:1000 /data/data/com.x; chown -R 1000:1000 /data/data/com.x/cache" in cmd


def test_restore_refuses_truncated_data_tar(tmp_path):
    hub = _backup(tmp_path, {"data_complete": False, "components": ["apk", "data"]})
    c = Ctx()
    c.hub = hub
    with pytest.raises(AdbError, match="incomplete"):
        installer.new_restore_job(hub, c, "com.x_20261001-100000", True, True)
    assert hub.backup.jobs == {}
    job = installer.new_restore_job(hub, c, "com.x_20261001-100000", True, False)   # APK only is fine
    assert job["data"] is False
    hub = _backup(tmp_path / "ok", {"data_complete": True})
    assert installer.new_restore_job(hub, c, "com.x_20261001-100000", True, True)["data"] is True
    (hub.backup.root / "FAKE123" / "com.x_20261001-100000" / "manifest.json").write_text("[1]")
    with pytest.raises(AdbError, match="no valid package"):
        installer.new_restore_job(hub, c, "com.x_20261001-100000", True, True)


# ---------------- #19: a bundle zipfile cannot read answers ok:false ----------------

def _patched_bundle(path: Path, *, flags: int | None = None, method: int | None = None,
                    corrupt: bool = False) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED if corrupt else zipfile.ZIP_STORED) as zf:
        zf.writestr("base.apk", b"A" * 4000)
    raw = bytearray(path.read_bytes())
    lh, ch = raw.find(b"PK\x03\x04"), raw.find(b"PK\x01\x02")
    assert lh == 0 and ch > 0
    if flags is not None:                     # general-purpose bit 0 = encrypted
        raw[lh + 6:lh + 8] = flags.to_bytes(2, "little")
        raw[ch + 8:ch + 10] = flags.to_bytes(2, "little")
    if method is not None:                    # 9 = Deflate64, which zipfile cannot inflate
        raw[lh + 8:lh + 10] = method.to_bytes(2, "little")
        raw[ch + 10:ch + 12] = method.to_bytes(2, "little")
    if corrupt:                               # reserved deflate block type -> zlib.error
        start = 30 + len("base.apk")
        raw[start] = 0x06
    path.write_bytes(bytes(raw))
    assert zipfile.is_zipfile(path)
    return path


@pytest.mark.parametrize("kw,what", [
    ({"flags": 1}, "encrypted"),
    ({"method": 9}, "compression method"),
    ({"corrupt": True}, "decompress"),
])
def test_install_upload_unreadable_bundle_is_a_plain_refusal(tmp_path, kw, what):
    class A:
        def __init__(self):
            self.calls = []

        def install(self, files, flags, timeout=0):
            self.calls.append(files)
            return True, "Success"
    up = tmp_path / "uploads" / "u1"
    up.mkdir(parents=True)
    bundle = _patched_bundle(up / "app.apks", **kw)
    c = SimpleNamespace(adb=A())
    r = installer.install_upload(c, bundle, {})
    assert r["ok"] is False and r["output"].startswith("could not unpack the bundle: ")
    assert what.lower() in r["output"].lower(), r
    assert c.adb.calls == [] and not up.exists()
