"""Engagement gate, request monitor, cert module, mitm bridge and Frida service."""
from __future__ import annotations

import datetime
import io
import zipfile
from collections import deque

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sentinel.service import certmodule, engagement, frida_svc, mitm, reqmon


def _ca_pem() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Sentinel Test CA")])
    now = datetime.datetime(2024, 1, 1)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


class _Store:
    def __init__(self): self.d = {}
    def get_snapshot(self, k): return self.d.get(k)
    def put_snapshot(self, k, v): self.d[k] = v


class _Hub:
    def __init__(self, data_dir=None):
        self.store = _Store()
        if data_dir is not None:
            class _Cfg: pass
            self.cfg = _Cfg()
            self.cfg.data_dir = data_dir
        self._mitm = {"proc": None, "port": None}
    def resolve(self, s): return None


def test_builtin_ca_generate_and_confdir(tmp_path):
    from sentinel.service import ca
    h = _Hub(data_dir=tmp_path)
    assert ca.exists(h) is False
    info = ca.generate(h)
    assert info["exists"] and info["is_ca"] and info["hash_name"].endswith(".0")
    # reused unless forced
    assert ca.generate(h)["sha256"] == info["sha256"]
    assert ca.generate(h, force=True)["sha256"] != info["sha256"]
    pem = ca.cert_pem(h)
    assert b"BEGIN CERTIFICATE" in pem
    conf = ca.mitm_confdir(h)
    combined = (tmp_path / "ca" / "mitm" / "mitmproxy-ca.pem").read_bytes()
    assert b"PRIVATE KEY" in combined and b"BEGIN CERTIFICATE" in combined
    assert conf.endswith("mitm")


def test_replay_validates_without_network():
    from sentinel.service import reqmon
    h = _Hub(data_dir=None)
    assert reqmon.replay(h, {"url": "ftp://x", "method": "GET"})["ok"] is False
    assert reqmon.replay(h, {"url": "http://x", "method": "BREW"})["ok"] is False
    assert reqmon.replay(h, {"url": "nota-url"})["ok"] is False


class _Dctx:
    def __init__(self):
        self.state = {}
        self.store = _Store()
        self.events = []
        self.adb = object()
    def emit_threadsafe(self, ev): self.events.append(ev)


# ---------------- engagement ----------------

def test_engagement_scope_allows_and_refuses():
    h = _Hub()
    engagement.require_scope(h, pkg="com.x")  # no engagement -> no-op
    engagement.create(h, {"name": "bb", "scope_packages": ["com.target", "com.foo.*"],
                          "scope_hosts": ["api.target.com", "*.target.com", "10.0.0.0/24"],
                          "deny": ["evil.target.com"]})
    engagement.require_scope(h, pkg="com.target")
    engagement.require_scope(h, pkg="com.foo.bar")
    engagement.require_scope(h, host="sub.target.com")
    engagement.require_scope(h, host="10.0.0.9")
    for bad in (dict(pkg="com.other"), dict(host="nope.com"), dict(host="evil.target.com")):
        with pytest.raises(engagement.ScopeError):
            engagement.require_scope(h, **bad)
    engagement.set_mode(h, "observe")
    with pytest.raises(engagement.ScopeError):
        engagement.require_scope(h, pkg="com.target")  # observe blocks active work
    engagement.set_mode(h, "active")
    engagement.require_scope(h, pkg="com.target")


def test_engagement_create_validation_and_close():
    h = _Hub()
    with pytest.raises(ValueError):
        engagement.create(h, {"name": ""})
    e = engagement.create(h, {"name": "x"})
    assert engagement.current(h)["id"] == e["id"]
    engagement.close(h, e["id"])
    assert engagement.current(h) is None


# ---------------- request monitor ----------------

def test_reqmon_filters_endpoints_and_export():
    c = _Dctx()
    reqmon.add_flow(c, {"package": "com.t", "method": "get", "host": "api.t.com",
                        "path": "/v1/login", "scheme": "https", "status": 200,
                        "req_headers": {"Authorization": "Bearer x"}})
    reqmon.add_flow(c, {"package": "com.t", "method": "POST", "host": "log.t.com",
                        "path": "/c", "scheme": "http", "status": 404})
    reqmon.add_flow(c, {"package": "com.t", "host": "api.t.com", "path": "/v1/me",
                        "scheme": "https", "status": 200})
    assert len(reqmon.list_flows(c, filters={"scheme": "http"})) == 1
    assert len(reqmon.list_flows(c, filters={"has_auth": True})) == 1
    assert len(reqmon.list_flows(c, filters={"host": "api.t", "path": r"/v1/\w+"})) == 2
    assert len(reqmon.list_flows(c, filters={"status_class": "2xx"})) == 2
    eps = reqmon.endpoints(c, "com.t")
    assert len(eps) == 3 and eps[0]["count"] >= 1
    name, data = reqmon.export(c, "com.t", "har")
    import json
    assert name.endswith(".har") and len(json.loads(data)["log"]["entries"]) == 3
    with pytest.raises(ValueError):
        reqmon.export(c, "com.t", "bogus")


def test_reqmon_watch_fires_alert():
    c = _Dctx()
    reqmon.add_watch(c, "any-auth", {"has_auth": True})
    reqmon.add_flow(c, {"package": "com.t", "host": "a.com", "path": "/x",
                        "scheme": "https", "status": 200,
                        "req_headers": {"Cookie": "s=1"}})
    assert any(e.kind == "alert" and "any-auth" in e.title for e in c.events)
    # a non-matching flow does not alert
    before = len(c.events)
    reqmon.add_flow(c, {"package": "com.t", "host": "b.com", "path": "/y",
                        "scheme": "https", "status": 200})
    assert len(c.events) == before


# ---------------- cert module ----------------

def test_certmodule_builds_flashable_zip():
    pem = _ca_pem()
    name, data = certmodule.build_module(pem)
    z = zipfile.ZipFile(io.BytesIO(data))
    names = z.namelist()
    assert name == "sentinel-ca-module.zip"
    assert "module.prop" in names and "service.sh" in names
    cert = next(n for n in names if n.startswith("system/etc/security/cacerts/"))
    assert cert.endswith(".0") and z.read(cert) == pem
    svc = z.read("service.sh").decode()
    assert "mount -o bind" in svc and "@@HASH@@" not in svc
    with pytest.raises(ValueError):
        certmodule.build_module(b"not a certificate")


# ---------------- mitm ----------------

def test_mitm_degrades_without_mitmdump(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _n: None)
    h = _Hub()
    st = mitm.status(h)
    assert st["installed"] is False and st["running"] is False
    r = mitm.start(h, 8080, "regular", 8765)
    assert r["ok"] is False and "mitmproxy" in r["output"]


# ---------------- frida ----------------

def test_frida_presets_and_validation():
    ids = [p["id"] for p in frida_svc.presets()]
    assert "flutter" in ids and "all" in ids and "okhttp" in ids
    st = frida_svc.status(_FakeFridaDctx())
    assert st["server_running"] is False
    # unpin validates before needing frida; bad input never reaches the device
    assert frida_svc.unpin(_FakeFridaDctx(), "com.x;rm", "all", "spawn")["ok"] is False
    assert frida_svc.unpin(_FakeFridaDctx(), "com.x", "nope", "spawn")["ok"] is False
    assert frida_svc.unpin(_FakeFridaDctx(), "com.x", "all", "fly")["ok"] is False


class _FakeAdb:
    def __init__(self): self.cmds = []
    def shell_sync(self, cmd, su=False, timeout=60):
        self.cmds.append((cmd, su))
        return ""  # pgrep/getprop empty -> server not running
    def push_file(self, local, remote, timeout=600): return True


class _FakeFridaDctx:
    def __init__(self): self.adb = _FakeAdb()


def test_frida_server_commands(tmp_path):
    c = _FakeFridaDctx()
    frida_svc.start_server(c)
    assert any("frida-server" in cmd and su for cmd, su in c.adb.cmds)
    frida_svc.stop_server(c)
    assert any("pkill -f frida-server" in cmd for cmd, _ in c.adb.cmds)
    # push validates the local file exists
    assert frida_svc.push_server(c, "/no/such/file")["ok"] is False
    f = tmp_path / "frida-server"
    f.write_bytes(b"\x7fELF")
    assert frida_svc.push_server(c, str(f))["ok"] is True
