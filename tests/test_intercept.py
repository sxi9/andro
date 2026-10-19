"""SSL-interception service (CA trust store + proxy wiring) against a recording
fake adb: exact command strings, su flags, the pushed PEM, the version-aware
APEX overlay, the per-app nat chain, events, and input validation."""
from __future__ import annotations

import datetime
import re
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sentinel.core.events import SEV_NOTICE, SEV_WARN
from sentinel.service import intercept

PKG = "com.x"
UID = 10234
PM_LIST = (f"package:/data/app/x/base.apk={PKG} installer=null uid:{UID}\n"
           "package:/data/app/y/base.apk=com.y installer=null uid:10235\n")


def _make_ca(*, is_ca: bool = True) -> bytes:
    """A self-signed cert PEM, with or without the CA basic-constraint."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Sentinel Proxy CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sentinel"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(name).issuer_name(name)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now)
               .not_valid_after(now + datetime.timedelta(days=3650)))
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True)
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM)


CA_PEM = _make_ca()


class FakeAdb:
    """Records every (cmd, su); the install script's trailing `ls` is answered
    with the cert path so install_ca sees the overlay as having taken hold."""
    use_su = True

    def __init__(self):
        self.cmds: list[tuple[str, bool]] = []
        self.pushed: list[tuple[str, bytes]] = []
        self._http_proxy = "null"  # tracks `settings put/get global http_proxy`

    def shell_sync(self, cmd, su=False, timeout=60):
        self.cmds.append((cmd, su))
        if cmd.startswith("pm list packages"):
            return PM_LIST
        if cmd.startswith("settings put global http_proxy "):
            self._http_proxy = cmd.split("http_proxy ", 1)[1].strip()
            return ""
        if cmd == "settings get global http_proxy":
            return self._http_proxy + "\n"
        if "mount -t tmpfs" in cmd or "mount -o rw,remount" in cmd:
            # the success probe `ls <store>/<hash>` at the tail of the script
            m = re.search(r"ls '?(/\S*?/([0-9a-f]{8}\.0))'?$", cmd)
            return (m.group(1) if m else "") + "\n"
        if cmd.startswith("ls ") and ".0" in cmd:
            return cmd.split("ls ", 1)[1].strip().strip("'") + "\n"
        return ""

    def push_file(self, local, remote, timeout=600):
        self.pushed.append((remote, Path(local).read_bytes()))
        return True


class Store:
    def __init__(self):
        self.snaps: dict = {}

    def get_snapshot(self, k):
        return self.snaps.get(k)

    def put_snapshot(self, k, v):
        self.snaps[k] = v


class Ctx:
    def __init__(self, *, sdk=34, root=True):
        self.adb = FakeAdb()
        self.device = {"root": root, "sdk": str(sdk), "android": "14"}
        self.serial = "FAKE123"
        self.store = Store()
        self.events: list = []

    def emit_threadsafe(self, ev):
        self.events.append(ev)

    def cmds(self):
        return [c for c, _ in self.adb.cmds]


# ---------------- inspect_ca (pure, no device) ----------------

def test_inspect_ca_fields_and_hash_format():
    info = intercept.inspect_ca(CA_PEM)
    assert info["is_ca"] is True
    assert re.fullmatch(r"[0-9a-f]{8}\.0", info["hash_name"])  # openssl subject_hash_old
    assert re.fullmatch(r"[0-9a-f]{64}", info["sha256"])
    assert re.fullmatch(r"[0-9a-f]{40}", info["sha1"])
    assert "Sentinel Proxy CA" in info["subject"]
    assert info["not_after"] > info["not_before"]


def test_inspect_ca_non_ca_cert():
    info = intercept.inspect_ca(_make_ca(is_ca=False))
    assert info["is_ca"] is False  # BasicConstraints absent -> default False


def test_inspect_ca_raises_on_non_cert():
    with pytest.raises(ValueError):
        intercept.inspect_ca(b"-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n")
    with pytest.raises(ValueError):
        intercept.inspect_ca(b"this is not a certificate at all")


def test_store_for_version_split():
    assert intercept._store_for(34) == "apex"
    assert intercept._store_for(35) == "apex"
    assert intercept._store_for(33) == "system"
    assert intercept._store_for(None) == "system"


# ---------------- install_ca (APEX overlay, SDK 34) ----------------

def test_install_ca_apex_overlay_and_event():
    c = Ctx(sdk=34)
    hash_name = intercept.inspect_ca(CA_PEM)["hash_name"]
    res = intercept.install_ca(c, CA_PEM)
    assert res["ok"] is True
    assert res["ca"]["installed"] is True
    assert res["ca"]["store"] == "apex"
    assert res["ca"]["hash_name"] == hash_name
    assert re.fullmatch(r"[0-9a-f]{64}", res["ca"]["sha256"])

    # the plain PEM was pushed to the shell-writable staging area
    assert len(c.adb.pushed) == 1
    remote, data = c.adb.pushed[0]
    assert remote.startswith("/data/local/tmp/sentinel-ca-") and remote.endswith(".pem")
    assert data == CA_PEM

    # the overlay script ran as root and did the version-aware APEX dance
    script, su = next((cmd, s) for cmd, s in c.adb.cmds if "mount -t tmpfs" in cmd)
    assert su is True
    assert hash_name in script
    assert "mount -t tmpfs tmpfs /system/etc/security/cacerts" in script
    assert "mount -o bind" in script and "/apex/com.android.conscrypt/cacerts" in script
    assert "chcon u:object_r:system_security_cacerts_file:s0" in script
    assert "chmod 644" in script and "chown 0:0" in script

    # audit event: notice, kind intercept.action, records the apex store
    ev = next(e for e in c.events if e.kind == "intercept.action")
    assert ev.severity == SEV_NOTICE
    assert ev.data["action"] == "ca.install" and ev.data["ok"] is True
    assert ev.data["store"] == "apex"

    # the install is remembered, and ca_status confirms it via `ls`
    assert c.store.snaps["intercept_ca"]["hash_name"] == hash_name
    st = intercept.ca_status(c)
    assert st["installed"] is True and st["store"] == "apex"


def test_install_ca_system_store_for_old_android():
    c = Ctx(sdk=29)
    res = intercept.install_ca(c, CA_PEM)
    assert res["ok"] is True and res["ca"]["store"] == "system"
    script = next(cmd for cmd in c.cmds() if "mount -o rw,remount" in cmd)
    assert "/system/etc/security/cacerts" in script
    assert "mount -o ro,remount" in script  # restored read-only
    assert "chcon u:object_r:system_security_cacerts_file:s0" in script


def test_install_ca_rejects_non_cert_without_touching_device():
    c = Ctx()
    res = intercept.install_ca(c, b"garbage, not a PEM")
    assert res["ok"] is False and res["ca"]["installed"] is False
    assert c.adb.cmds == [] and c.adb.pushed == []


def test_revert_ca_unmounts_both_and_clears_snapshot():
    c = Ctx(sdk=34)
    intercept.install_ca(c, CA_PEM)
    c.events.clear()
    res = intercept.revert_ca(c)
    assert res["ok"] is True
    cmd = next(cmd for cmd, su in c.adb.cmds if cmd.startswith("umount") or "umount" in cmd)
    assert "umount /system/etc/security/cacerts" in cmd
    assert "umount /apex/com.android.conscrypt/cacerts" in cmd
    assert c.store.snaps["intercept_ca"] == {}
    ev = next(e for e in c.events if e.kind == "intercept.action")
    assert ev.data["action"] == "ca.revert"


# ---------------- set_proxy ----------------

def test_proxy_global_builds_settings_command():
    c = Ctx()
    res = intercept.set_proxy(c, "global", host="127.0.0.1", port=8080)
    assert res["ok"] is True
    assert res["proxy"] == {"mode": "global", "host": "127.0.0.1", "port": 8080,
                            "package": None, "uid": None}
    assert c.cmds() == ["settings put global http_proxy 127.0.0.1:8080"]
    assert c.store.snaps["intercept_proxy"]["mode"] == "global"
    ev = next(e for e in c.events if e.kind == "intercept.action")
    assert ev.data["action"] == "proxy.global" and ev.data["port"] == 8080


def test_proxy_per_app_resolves_uid_and_builds_chain():
    c = Ctx()
    res = intercept.set_proxy(c, "per-app", host="10.0.0.2", port=8083, package=PKG)
    assert res["ok"] is True
    assert res["proxy"]["uid"] == UID and res["proxy"]["package"] == PKG

    script = next(cmd for cmd, su in c.adb.cmds if "SENTINEL_PROXY" in cmd and su)
    for ipt in ("iptables", "ip6tables"):
        assert f"{ipt} -t nat -N SENTINEL_PROXY" in script
        assert f"{ipt} -t nat -A SENTINEL_PROXY -p tcp --dport 443 -j DNAT --to-destination 10.0.0.2:8083" in script
        assert f"{ipt} -t nat -A SENTINEL_PROXY -p tcp --dport 80 -j DNAT --to-destination 10.0.0.2:8083" in script
        assert f"{ipt} -t nat -D OUTPUT -m owner --uid-owner {UID} -j SENTINEL_PROXY" in script
        assert f"{ipt} -t nat -A OUTPUT -m owner --uid-owner {UID} -j SENTINEL_PROXY" in script
    ev = next(e for e in c.events if e.kind == "intercept.action")
    assert ev.data["action"] == "proxy.per-app" and ev.data["package"] == PKG


def test_proxy_per_app_unresolvable_uid_warns():
    c = Ctx()
    res = intercept.set_proxy(c, "per-app", host="10.0.0.2", port=8083, package="com.absent")
    assert res["ok"] is False and "uid" in res["output"]
    # no nat chain was built
    assert not any("SENTINEL_PROXY" in cmd for cmd in c.cmds())
    ev = next(e for e in c.events if e.kind == "intercept.action")
    assert ev.severity == SEV_WARN and ev.data["ok"] is False


def test_proxy_off_clears_setting_and_flushes_chain():
    c = Ctx()
    intercept.set_proxy(c, "per-app", host="10.0.0.2", port=8083, package=PKG)
    c.adb.cmds.clear()
    c.events.clear()
    res = intercept.set_proxy(c, "off")
    assert res["ok"] is True and res["proxy"]["mode"] == "off"
    cmds = c.cmds()
    assert "settings put global http_proxy :0" in cmds
    off = next(cmd for cmd, su in c.adb.cmds if "-F SENTINEL_PROXY" in cmd and su)
    for ipt in ("iptables", "ip6tables"):
        assert f"{ipt} -t nat -F SENTINEL_PROXY" in off
        assert f"{ipt} -t nat -X SENTINEL_PROXY" in off
        # the OUTPUT jump for the previously-set uid is removed
        assert f"{ipt} -t nat -D OUTPUT -m owner --uid-owner {UID} -j SENTINEL_PROXY" in off


def test_set_proxy_rejects_host_with_trailing_newline():
    c = Ctx()
    # \Z (not $) refuses a trailing newline that the device shell would split on
    res = intercept.set_proxy(c, "global", host="127.0.0.1\n", port=8080)
    assert res["ok"] is False and "invalid" in res["output"].lower()
    assert c.adb.cmds == []   # nothing reached the device
    assert c.events == []     # a refused input logs no event


def test_set_proxy_rejects_bad_port_and_mode():
    c = Ctx()
    assert intercept.set_proxy(c, "global", host="h", port=99999)["ok"] is False
    assert intercept.set_proxy(c, "global", host="h", port="nope")["ok"] is False
    assert intercept.set_proxy(c, "sideways")["ok"] is False
    assert c.adb.cmds == []


# ---------------- assembled status ----------------

def test_status_assembles_device_and_blocks():
    c = Ctx(sdk=34, root=True)
    st = intercept.status(c)
    assert st["root"] is True and st["sdk"] == 34 and st["android"] == "14"
    assert st["ca"]["installed"] is False and st["proxy"]["mode"] == "off"
    assert st["errors"] == {}

    intercept.install_ca(c, CA_PEM)
    intercept.set_proxy(c, "global", host="1.2.3.4", port=9090)
    st = intercept.status(c)
    assert st["ca"]["installed"] is True
    assert st["proxy"]["mode"] == "global" and st["proxy"]["port"] == 9090
