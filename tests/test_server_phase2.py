"""Phase-2 routes over the demo hub: every GET answers with the contract keys,
every POST action is refused in demo mode, uploads and CSRF behave."""
from __future__ import annotations

import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from sentinel.config import Config
from sentinel.server.app import create_app

PKG = "com.whatsapp"


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
    r = client.post("/api/root/request", json={}, headers={"Origin": "http://127.0.0.1:8765"})
    assert r.status_code == 400                             # same-origin passes to the demo refusal
    assert client.get("/api/root", headers={"Origin": "http://evil.example"}).status_code == 200


def test_backup_jobs_route_lists_type(client):
    assert client.get("/api/backup/jobs").json() == []
