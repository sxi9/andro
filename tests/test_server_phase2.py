"""Phase-2 routes over the demo hub: every GET answers with the contract keys,
every POST action is refused in demo mode, uploads and CSRF behave."""
from __future__ import annotations

import errno
import io
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import types
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentinel.config import Config
from sentinel.server import app as app_mod
from sentinel.server.app import create_app
from sentinel.service.installer import MAX_UPLOAD

PKG = "com.whatsapp"
REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    cfg = Config(demo=True, demo_devices=1, data_dir=tmp_path_factory.mktemp("data"))
    # the TrustedHost middleware only answers to the loopback names
    with TestClient(create_app(cfg), base_url="http://127.0.0.1") as c:
        yield c


def test_foreign_host_header_rejected(client):
    assert client.get("/api/root", headers={"Host": "evil.example"}).status_code == 400


def _ok(client, url):
    r = client.get(url)
    assert r.status_code == 200, (url, r.text)
    return r.json()


def test_root_status(client):
    d = _ok(client, "/api/root")
    assert set(d) >= {"root", "su_path", "manager", "adbd_root", "selinux", "use_su"}
    assert set(d["manager"]) == {"name", "version"} and d["demo"] is True


def test_detail_has_new_fields(client):
    d = _ok(client, f"/api/appmanager/app/{PKG}")
    for k in ("state", "perm_flags", "uid", "shared_user", "process", "data_usage", "running", "links"):
        assert k in d, k
    assert set(d["state"]) == {"installed", "hidden", "suspended", "stopped", "enabled_state", "frozen", "user"}
    assert set(d["links"]) == {"play", "fdroid", "exodus"} and PKG in d["links"]["play"]
    assert set(d["running"]) == {"pids", "rss_kb"}
    assert set(d["data_usage"]) == {"wifi_rx", "wifi_tx", "mobile_rx", "mobile_tx"}


def test_controls(client):
    d = _ok(client, f"/api/appmanager/app/{PKG}/controls")
    for k in ("battery_whitelisted", "net_restricted_background", "data_saver", "sensors", "denylist",
              "denylist_available", "app_links", "app_links_allowed", "firewall_blocked", "overlays",
              "ssaid", "keystore_files", "errors"):
        assert k in d, k
    assert d["app_links"] and set(d["app_links"][0]) == {"domain", "state"}
    assert set(d["overlays"][0]) == {"name", "enabled"}


def test_storage_both_routes(client):
    for url in (f"/api/appmanager/app/{PKG}/storage", f"/api/storage/app/{PKG}"):
        d = _ok(client, url)
        for k in ("data_dir", "external_dir", "sizes", "entries", "log_files", "subdirs", "obb_dir",
                  "media_dir", "de_dir", "cache_bytes", "data_bytes", "app_bytes", "apk_paths",
                  "splits", "backups"):
            assert k in d, (url, k)
        assert set(d["splits"][0]) == {"path", "size"}
        assert set(d["backups"][0]) == {"name", "path", "bytes", "captured", "components"}


def test_manifest_and_scan(client):
    m = _ok(client, f"/api/appmanager/app/{PKG}/manifest")
    for k in ("package", "version_name", "version_code", "min_sdk", "target_sdk", "main_activity",
              "activities", "services", "receivers", "providers", "uses_permissions",
              "declared_permissions", "features", "native_libs", "dex_files", "meta_data",
              "splits", "signatures", "manifest_xml", "apk_path", "apk_size", "cached"):
        assert k in m, k
    a = m["activities"][0]
    assert set(a) >= {"name", "exported", "permission", "enabled", "intent_filters", "tracker"}
    assert set(m["signatures"][0]) >= {"scheme", "subject", "sha256", "not_after"}
    assert set(m["providers"][0]) >= {"name", "exported", "authorities", "grant_uri_permissions"}
    s = _ok(client, f"/api/appmanager/app/{PKG}/scan?refresh=1")
    for k in ("package", "trackers", "libraries", "native_libs", "dex_files", "classes_scanned",
              "apk_size", "scanned_at", "cached"):
        assert k in s, k
    assert len(s["trackers"]) == 2
    # same shape the real scanner emits, so the UI renders both alike
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00", s["scanned_at"])  # same shape as the real scan
    assert s["scanned_ts"] > 0
    assert set(s["trackers"][0]) == {"name", "category", "website", "signatures_matched", "classes", "components"}
    assert set(s["libraries"][0]) == {"name", "website", "classes"}


def test_prefs_and_db(client):
    p = _ok(client, f"/api/appmanager/app/{PKG}/prefs")
    assert p["files"] and set(p["files"][0]) == {"name", "size", "entries"}
    f = _ok(client, f"/api/appmanager/app/{PKG}/prefs/{p['files'][0]['name']}")
    assert f["file"] == p["files"][0]["name"] and len(f["entries"]) == 3
    assert {e["type"] for e in f["entries"]} <= {"string", "int", "long", "float", "boolean", "set"}
    assert client.get(f"/api/appmanager/app/{PKG}/prefs/..%2Fetc.xml").status_code in (400, 404)
    assert client.get(f"/api/appmanager/app/{PKG}/prefs/notes.txt").status_code == 400
    d = _ok(client, f"/api/appmanager/app/{PKG}/db")
    assert d["files"] and set(d["files"][0]) == {"name", "size"}
    t = _ok(client, f"/api/appmanager/app/{PKG}/db/app.db")
    assert set(t) >= {"file", "tables", "table", "columns", "rows", "truncated"}
    assert t["table"] is None and t["rows"] == []
    t = _ok(client, f"/api/appmanager/app/{PKG}/db/app.db?table=messages&limit=2")
    assert t["table"] == "messages" and len(t["rows"]) == 2 and t["columns"]
    assert client.get(f"/api/appmanager/app/{PKG}/db/app.db?table=bad-name").status_code == 400
    assert client.get(f"/api/appmanager/app/{PKG}/db/app.db?limit=0").status_code == 400
    assert client.get(f"/api/appmanager/app/{PKG}/db/a%20b").status_code == 400


def test_running_history_oneclick(client):
    r = _ok(client, "/api/appmanager/running")
    assert len(r["processes"]) == 5
    assert set(r["processes"][0]) == {"pid", "ppid", "uid", "package", "name", "rss_kb", "state", "cputime"}
    assert set(r["mem"]) == {"total_kb", "avail_kb", "swap_total_kb", "swap_free_kb"}
    h = _ok(client, "/api/appmanager/history?limit=10")
    assert len(h["events"]) == 3
    assert set(h["events"][0]) >= {"ts", "action", "package", "ok", "output", "user"}
    o = _ok(client, "/api/appmanager/oneclick")
    ids = [op["id"] for op in o["ops"]]
    assert ids == ["block-trackers-all", "deny-bg-all", "deny-dangerous-ops-all", "trim-caches",
                   "clear-cache-all", "backup-all", "compile-all"]
    assert set(o["ops"][0]) == {"id", "title", "description", "needs_root", "destructive"}


def test_export_formats(client):
    r = client.get("/api/appmanager/export?format=csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert r.headers["content-disposition"].startswith('attachment; filename="apps-demo-')
    lines = r.text.splitlines()
    assert lines[0] == "label,package,version,system,enabled,installed,installer,uid,data_size,apk_size"
    assert any(ln.startswith("WhatsApp,com.whatsapp,") for ln in lines)
    r = client.get("/api/appmanager/export?format=json&which=user")
    assert r.status_code == 200 and all(not a["system"] for a in r.json()["apps"])
    r = client.get("/api/appmanager/export?format=md")
    assert r.status_code == 200 and r.text.startswith("| label | package |")
    assert client.get("/api/appmanager/export?format=xlsx").status_code == 400
    assert client.get("/api/appmanager/export?user=abc").status_code == 400


def test_invalid_package_rejected(client):
    for url in ("/api/appmanager/app/{p}", "/api/appmanager/app/{p}/controls",
                "/api/appmanager/app/{p}/storage", "/api/appmanager/app/{p}/manifest",
                "/api/appmanager/app/{p}/scan", "/api/appmanager/app/{p}/prefs",
                "/api/appmanager/app/{p}/db", "/api/storage/app/{p}"):
        r = client.get(url.format(p="com.x;id"))
        assert r.status_code == 400 and r.json()["error"] == "invalid package name", url


@pytest.mark.parametrize("url,body", [
    ("/api/appmanager/action", {"action": "launch", "package": PKG}),
    ("/api/appmanager/batch", {"action": "force-stop", "packages": [PKG]}),
    ("/api/appmanager/oneclick", {"op": "trim-caches"}),
    ("/api/restore", {"name": "x", "confirm": True}),
    ("/api/root/request", {}),
    ("/api/root/use", {"enabled": True}),
    ("/api/adb/root", {}),
    ("/api/adb/unroot", {}),
])
def test_post_actions_refused_in_demo(client, url, body):
    r = client.post(url, json=body)
    assert r.status_code == 400
    assert r.json() == {"ok": False, "output": "needs a real device (not demo mode)"}


def test_install_upload(client):
    r = client.post("/api/appmanager/install", data={"options": "{}"})
    assert 400 <= r.status_code < 500                      # no file part
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("base.apk", b"PK")
    r = client.post("/api/appmanager/install",
                    files={"file": ("app.xapk", buf.getvalue(), "application/octet-stream")},
                    data={"options": json.dumps({"replace": True})})
    assert r.status_code == 400
    assert r.json() == {"ok": False, "output": "needs a real device (not demo mode)"}
    r = client.post("/api/appmanager/install",
                    files={"file": ("x.apk", b"PK", "application/octet-stream")},
                    data={"options": "not json"})
    assert r.status_code == 400 and r.json()["ok"] is False


def test_csrf_guard_blocks_cross_origin_posts(client):
    r = client.post("/api/appmanager/action", json={"action": "launch", "package": PKG},
                    headers={"Origin": "http://evil.example"})
    assert r.status_code == 403 and r.json() == {"error": "cross-origin request blocked"}
    # same-origin = the authority the browser is talking to (its Host), so a
    # port-forwarded or proxied dashboard keeps working
    for origin, host in (("http://127.0.0.1", "127.0.0.1"), ("http://localhost", "localhost"),
                         ("http://127.0.0.1:8765", "127.0.0.1:8765"), ("http://localhost:9000", "localhost:9000")):
        r = client.post("/api/root/request", json={}, headers={"Origin": origin, "Host": host})
        assert r.status_code == 400, origin                 # same-origin passes to the demo refusal
    assert client.get("/api/root", headers={"Origin": "http://evil.example"}).status_code == 200


@pytest.mark.parametrize("origin", [
    "http://localhost:3000",        # another local port: a dev server's page is cross-origin
    "http://127.0.0.1:8765",        # the request's Host is 127.0.0.1 (port 80): another port
    "https://127.0.0.1:8765",       # scheme differs
    "http://localhost.evil.example:8765",
    "http://127.0.0.1:x",
    "null",
])
def test_csrf_guard_is_port_and_scheme_aware(client, origin):
    # a multipart form POST needs no preflight, so the guard must compare the
    # whole origin against the request's own authority, not just the hostname
    r = client.post("/api/appmanager/install",
                    files={"file": ("x.apk", b"PK", "application/octet-stream")},
                    data={"options": "{}"}, headers={"Origin": origin})
    assert r.status_code == 403 and r.json() == {"error": "cross-origin request blocked"}


@pytest.mark.parametrize("url,body", [
    ("/api/appmanager/action", {"action": "launch", "package": PKG}),
    ("/api/appmanager/batch", {"action": "force-stop", "packages": [PKG]}),
    ("/api/appmanager/oneclick", {"op": "trim-caches"}),
    ("/api/restore", {"name": "x", "confirm": True}),
    ("/api/root/request", {}),
    ("/api/root/use", {"enabled": True}),
    ("/api/adb/root", {}),
    ("/api/adb/unroot", {}),
    ("/api/appmanager/resolve-labels", {}),
])
@pytest.mark.parametrize("device", [["x"], {"a": 1}, 5, None])
def test_non_string_device_falls_back_to_default(client, url, body, device):
    # a list/dict `device` used to reach Hub.resolve's `in` test -> TypeError -> 500
    r = client.post(url, json={**body, "device": device})
    assert r.status_code == 400 and r.json()["ok"] is False
    assert "needs a real device" in r.text


def test_install_non_string_device_falls_back(client):
    r = client.post("/api/appmanager/install",
                    files={"file": ("x.apk", b"PK", "application/octet-stream")},
                    data={"options": json.dumps({"device": ["x"]})})
    assert r.status_code == 400
    assert r.json() == {"ok": False, "output": "needs a real device (not demo mode)"}


def test_install_rejects_oversized_content_length_before_parsing(client):
    # the multipart parser spools the whole body to the temp dir before the
    # handler can count bytes, so an oversized Content-Length is refused up front
    kw = dict(files={"file": ("x.apk", b"PK", "application/octet-stream")}, data={"options": "{}"})
    r = client.post("/api/appmanager/install", headers={"Content-Length": str(MAX_UPLOAD + 2 * 1024 * 1024)}, **kw)
    assert r.status_code == 413 and r.json() == {"ok": False, "output": "file exceeds 400 MB"}
    # just within the allowance for form overhead: passes through to the handler
    r = client.post("/api/appmanager/install", headers={"Content-Length": str(MAX_UPLOAD + 1024 * 1024)}, **kw)
    assert r.status_code == 400 and r.json() == {"ok": False, "output": "needs a real device (not demo mode)"}
    # other routes are not subject to the cap
    r = client.post("/api/root/request", json={}, headers={"Content-Length": str(MAX_UPLOAD * 2)})
    assert r.status_code == 400 and "needs a real device" in r.text


def _fake_dctx():
    # looks like a real device to the routes: adb set, state dict for locks
    return types.SimpleNamespace(adb=object(), state={}, serial="FAKE123")


def test_install_write_failure_is_reported_and_cleaned(client, monkeypatch, tmp_path):
    hub = client.app.state.hub
    dctx = _fake_dctx()
    monkeypatch.setattr(hub, "resolve", lambda serial: dctx)
    uploads = hub.cfg.data_dir / "uploads"
    kw = dict(files={"file": ("a.apk", b"PK\x03\x04", "application/octet-stream")}, data={"options": "{}"})

    def full(*a, **k):
        raise OSError(errno.ENOSPC, "No space left on device")
    # the handler's `open` resolves through the module globals first
    monkeypatch.setattr(app_mod, "open", full, raising=False)
    r = client.post("/api/appmanager/install", **kw)
    assert r.status_code == 507
    assert r.json() == {"ok": False, "output": "cannot save upload: No space left on device"}
    assert not uploads.exists() or list(uploads.iterdir()) == []   # no orphaned uploads/<uuid>

    # unwritable data_dir: mkdir fails (uploads is a file) before open, still a clean 4xx
    shutil.rmtree(uploads, ignore_errors=True)
    uploads.write_bytes(b"")
    try:
        r = client.post("/api/appmanager/install", **kw)
        assert r.status_code == 400 and r.json()["ok"] is False
        assert r.json()["output"].startswith("cannot save upload: ")
    finally:
        uploads.unlink()


def test_bulk_lock_refuses_concurrent_batch(client, monkeypatch):
    from sentinel.service import appmanager
    hub = client.app.state.hub
    dctx = _fake_dctx()
    monkeypatch.setattr(hub, "resolve", lambda serial: dctx)
    started, release = threading.Event(), threading.Event()
    calls: list[tuple] = []

    def slow_batch(d, action, pkgs, user, confirm, options):
        calls.append((action, tuple(pkgs)))
        started.set()
        release.wait(5)
        return {"ok": True, "action": action, "results": []}
    monkeypatch.setattr(appmanager, "batch", slow_batch)
    monkeypatch.setattr(appmanager, "oneclick", lambda d, op, confirm, scope: {"ok": True, "op": op})

    body = {"action": "force-stop", "packages": [PKG], "confirm": True}
    busy = {"ok": False, "output": "a batch is already running on this device"}
    first: dict = {}
    t = threading.Thread(target=lambda: first.setdefault("r", client.post("/api/appmanager/batch", json=body)))
    t.start()
    assert started.wait(5)
    try:
        # while the first pass runs on its thread, a second batch and a one-click op are refused
        r = client.post("/api/appmanager/batch", json=body)
        assert r.status_code == 409 and r.json() == busy
        r = client.post("/api/appmanager/oneclick", json={"op": "compile-all", "confirm": True})
        assert r.status_code == 409 and r.json() == busy
    finally:
        release.set()
        t.join(5)
    assert first["r"].status_code == 200 and first["r"].json()["ok"] is True
    assert calls == [("force-stop", (PKG,))]
    # the lock is released when the pass ends, so the next one runs
    assert not dctx.state["bulk_lock"].locked()
    r = client.post("/api/appmanager/oneclick", json={"op": "compile-all", "confirm": True})
    assert r.status_code == 200 and r.json() == {"ok": True, "op": "compile-all"}
    assert not dctx.state["bulk_lock"].locked()


def test_main_starts_without_optional_packages(monkeypatch, capsys, tmp_path):
    import uvicorn
    import sentinel.__main__ as m
    for mod in ("pyaxmlparser", "multipart", "python_multipart"):
        monkeypatch.setitem(sys.modules, mod, None)      # find_spec() -> None, like an uninstalled package
    assert m._missing_deps(m._REQUIRED) == []
    assert m._missing_deps(m._OPTIONAL) == ["multipart", "pyaxmlparser"]
    runs: list = []
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: runs.append(k))
    monkeypatch.setattr(app_mod, "create_app", lambda cfg: "app")
    assert m.main(["--demo", "--data-dir", str(tmp_path)]) == 0
    assert runs and runs[0]["port"] == 8765
    err = capsys.readouterr().err
    assert "Optional Python packages missing" in err
    assert "python-multipart (Install APK is off)" in err
    assert "pyaxmlparser (Resolve names is off)" in err
    # a hard requirement still stops the start
    monkeypatch.setitem(sys.modules, "fastapi", None)
    assert m.main(["--demo", "--data-dir", str(tmp_path)]) == 2
    assert "Missing Python packages: fastapi" in capsys.readouterr().err


@pytest.mark.skipif(not shutil.which("bash") or os.name == "nt", reason="needs bash")
@pytest.mark.parametrize("where", ["home", "xdg"])
def test_run_sh_finds_the_installers_venv(tmp_path, where):
    # install.sh creates ~/.local/share/android-sentinel/.venv when the checkout
    # path has a ':'; run.sh must look there whatever XDG_DATA_HOME says
    chk = tmp_path / "chk"
    chk.mkdir()
    shutil.copy(REPO / "run.sh", chk / "run.sh")
    (chk / "requirements.txt").write_text("fastapi\n")
    home, xdg = tmp_path / "home", tmp_path / "custom-xdg"
    venv_bin = (home / ".local/share" if where == "home" else xdg) / "android-sentinel/.venv/bin"
    venv_bin.mkdir(parents=True)
    py = venv_bin / "python"
    py.write_text("#!/bin/sh\necho \"fake-python $*\"\n")
    py.chmod(0o755)
    (venv_bin / "python.reqs-stamp").touch()               # stamp newer than requirements -> no pip step
    env = {**os.environ, "HOME": str(home), "XDG_DATA_HOME": str(xdg)}
    r = subprocess.run(["bash", str(chk / "run.sh"), "--demo"], env=env,
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "fake-python -m sentinel --demo"


def test_backup_jobs_route_lists_type(client):
    assert client.get("/api/backup/jobs").json() == []


# ---------- SSL interception: CA trust + proxy wiring (Phase: step 1) ----------
# These exercise the app.py routes only. The device-side work and PEM parsing
# live in sentinel.service.intercept (a sibling module); the two offline inspect
# cases importorskip it so the suite stays green until that module lands, then
# run in full against it.

_CA_SUBJECT_CN = "Sentinel Test Proxy CA"
_INSPECT_KEYS = {"ok", "subject", "issuer", "sha256", "sha1", "hash_name",
                 "not_before", "not_after", "is_ca"}


def _self_signed_ca_pem() -> str:
    """A real self-signed CA PEM, built inline so the inspect route has
    something cryptography can actually parse (no fixture file on disk)."""
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _CA_SUBJECT_CN),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sentinel")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_intercept_status_demo_shape(client):
    # the frontend binds to exactly this shape; keep it in lockstep
    d = _ok(client, "/api/intercept/status")
    assert d == {"demo": True, "root": True, "sdk": 34, "android": "14",
                 "ca": {"installed": False, "subject": None, "sha256": None,
                        "hash_name": None, "store": "apex", "not_after": None},
                 "proxy": {"mode": "off", "host": None, "port": None,
                           "package": None, "uid": None},
                 "errors": {}}


def test_intercept_ca_inspect_offline(client):
    pytest.importorskip("sentinel.service.intercept")   # written by a sibling agent
    r = client.post("/api/intercept/ca/inspect", json={"pem": _self_signed_ca_pem()})
    assert r.status_code == 200, r.text
    d = r.json()
    assert _INSPECT_KEYS <= set(d), d
    assert d["ok"] is True
    assert d["is_ca"] is True
    assert d["hash_name"].endswith(".0")        # openssl subject_hash_old -> "<hash>.0"
    assert _CA_SUBJECT_CN in (d["subject"] or "")
    assert d["sha256"] and d["not_after"]       # present, format left to the service


def test_intercept_ca_inspect_rejects_non_cert(client):
    pytest.importorskip("sentinel.service.intercept")
    r = client.post("/api/intercept/ca/inspect", json={"pem": "not a cert"})
    assert r.status_code == 400 and r.json()["ok"] is False
    # a missing PEM is refused by the route itself, before the service
    r = client.post("/api/intercept/ca/inspect", json={})
    assert r.status_code == 400 and r.json()["ok"] is False


def test_intercept_ca_install_refused_in_demo(client):
    # confirm given + a valid PEM, so the route clears confirm and PEM checks
    # and lands on the demo gate (never importing the service)
    r = client.post("/api/intercept/ca",
                    json={"pem": _self_signed_ca_pem(), "confirm": True})
    assert r.status_code == 400
    assert r.json() == {"ok": False, "output": "needs a real device (not demo mode)"}


def test_intercept_active_calls_need_confirm(client):
    # the confirm gate comes first, so an un-confirmed active call always says so
    for url, body in (("/api/intercept/ca", {"pem": "x"}),
                      ("/api/intercept/ca/revert", {}),
                      ("/api/intercept/proxy",
                       {"mode": "global", "host": "127.0.0.1", "port": 8080})):
        r = client.post(url, json=body)
        assert r.status_code == 400, url
        d = r.json()
        assert d["ok"] is False and "confirm" in d["output"], url


def test_intercept_proxy_validation(client):
    # mode / host / port / package validated at the boundary (confirm set so the
    # request reaches validation rather than being stopped at the confirm gate)
    bad = [
        {"mode": "sideways", "confirm": True},                            # unknown mode
        {"mode": "global", "host": "bad;host", "port": 8080, "confirm": True},
        {"mode": "global", "host": "10.0.0.1", "port": 0, "confirm": True},
        {"mode": "global", "host": "10.0.0.1", "port": 99999, "confirm": True},
        {"mode": "global", "host": "10.0.0.1", "port": "eighty", "confirm": True},
        {"mode": "global", "host": "10.0.0.1", "confirm": True},          # missing port
        {"mode": "per-app", "host": "10.0.0.1", "port": 8080,
         "package": "com.x;rm", "confirm": True},                         # bad package
    ]
    for body in bad:
        r = client.post("/api/intercept/proxy", json=body)
        assert r.status_code == 400 and r.json()["ok"] is False, body
    # well-formed requests pass validation and then hit the demo gate
    for body in ({"mode": "off", "confirm": True},
                 {"mode": "global", "host": "127.0.0.1", "port": 8080, "confirm": True},
                 {"mode": "per-app", "host": "10.0.0.1", "port": 8080,
                  "package": PKG, "confirm": True}):
        r = client.post("/api/intercept/proxy", json=body)
        assert r.status_code == 400
        assert r.json() == {"ok": False, "output": "needs a real device (not demo mode)"}, body


def test_intercept_csrf_guard_blocks_cross_origin(client):
    for url, body in (("/api/intercept/ca", {"pem": "x", "confirm": True}),
                      ("/api/intercept/ca/revert", {"confirm": True}),
                      ("/api/intercept/proxy", {"mode": "off", "confirm": True}),
                      ("/api/intercept/ca/inspect", {"pem": "x"})):
        r = client.post(url, json=body, headers={"Origin": "http://evil.example"})
        assert r.status_code == 403 and r.json() == {"error": "cross-origin request blocked"}, url
    # the read endpoint stays reachable: GET is not guarded
    assert client.get("/api/intercept/status",
                      headers={"Origin": "http://evil.example"}).status_code == 200
