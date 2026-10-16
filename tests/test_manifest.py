"""APK inspection over a ranged reader: manifest, signatures, dex scan,
signature tables and the prefix matcher."""
from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from sentinel.enrich import manifest, signatures
from sentinel.enrich.manifest import (component_kinds, dex_class_names, inspect_apk, is_dangerous,
                                      parse_manifest, scan_app)
from sentinel.enrich.signatures import LIBRARIES, TRACKERS, match_prefixes, tracker_for_class

SAMPLE_APK = Path("/tmp/claude-0/-home-user-andro/9f21e297-6624-5b9e-afc1-ff4f09c54e08/"
                  "scratchpad/apk-test/fdroid-sample.apk")
PKG = "org.fdroid.fdroid"
APK_PATH = "/data/app/~~abc==/org.fdroid.fdroid-xyz==/base.apk"

needs_apk = pytest.mark.skipif(not SAMPLE_APK.exists(), reason="sample APK not downloaded")


# ---------------- signature tables + matcher ----------------
def test_tables_are_well_formed():
    assert len(TRACKERS) >= 110
    assert len(LIBRARIES) >= 40
    names = [t["name"] for t in TRACKERS]
    assert len(names) == len(set(names))
    for t in TRACKERS:
        assert t["category"] in signatures.CATEGORIES, t["name"]
        assert t["website"].startswith("http")
        assert t["signatures"], t["name"]
        for sig in t["signatures"]:
            assert sig == sig.strip() and " " not in sig and not sig.endswith(".")
    for lib in LIBRARIES:
        assert lib["signatures"] and lib["website"].startswith("http")


def test_match_prefixes():
    got = match_prefixes([
        "com.appsflyer.AppsFlyerLib", "com.appsflyer.internal.Foo$Bar",
        "com.appsflyerx.Nope",                 # prefix must end at a dot
        "io.sentry.Sentry", "okhttp3.OkHttpClient",
        "com.google.android.gms.ads.doubleclick.PublisherAdView",
        "com.example.app.MainActivity",
    ])
    assert got["AppsFlyer"] == {"signatures_matched": {"com.appsflyer"}, "classes": 2}
    assert got["Sentry"]["classes"] == 1
    # nested prefixes: the AdMob and the Ad Manager entries both see the class
    assert got["Google AdMob"]["classes"] == 1
    assert got["Google Ad Manager (DoubleClick)"]["signatures_matched"] == {
        "com.google.android.gms.ads.doubleclick"}
    assert "OkHttp" not in got                   # libraries are a separate table
    assert match_prefixes(["okhttp3.OkHttpClient", "retrofit2.Retrofit$Builder"], LIBRARIES) == {
        "OkHttp": {"signatures_matched": {"okhttp3"}, "classes": 1},
        "Retrofit": {"signatures_matched": {"retrofit2"}, "classes": 1},
    }
    assert match_prefixes([]) == {}
    # a class matching two prefixes of ONE entry still counts once
    got = match_prefixes(["com.unity3d.services.analytics.Foo"])
    assert got["Unity Ads"]["classes"] == 1 and got["Unity Analytics"]["classes"] == 1


def test_tracker_for_class_prefers_longest_prefix():
    assert tracker_for_class("com.google.android.gms.ads.doubleclick.X") == "Google Ad Manager (DoubleClick)"
    assert tracker_for_class("com.google.android.gms.ads.AdView") == "Google AdMob"
    assert tracker_for_class("com.onesignal.NotificationOpenedReceiver") == "OneSignal"
    assert tracker_for_class("org.fdroid.fdroid.views.main.MainActivity") is None
    assert tracker_for_class("") is None


def test_is_dangerous():
    assert is_dangerous("android.permission.CAMERA")
    assert is_dangerous("com.android.voicemail.permission.ADD_VOICEMAIL")
    assert not is_dangerous("android.permission.INTERNET")
    assert not is_dangerous("com.example.permission.CAMERA")


# ---------------- dex parser (synthetic) ----------------
def _mini_dex(strings: list[bytes]) -> bytes:
    """Header + string_ids + type_ids (every string is a type) + string data."""
    hdr = bytearray(0x70)
    hdr[:8] = b"dex\n035\0"
    n = len(strings)
    sid_off, tid_off = 0x70, 0x70 + 4 * n
    data_off = tid_off + 4 * n
    struct.pack_into("<IIII", hdr, 0x38, n, sid_off, n, tid_off)
    data = bytearray()
    offs = []
    for s in strings:
        offs.append(data_off + len(data))
        data += bytes([len(s)]) + s + b"\0"      # uleb128 length (< 128) + MUTF-8 + NUL
    sids = b"".join(struct.pack("<I", o) for o in offs)
    tids = b"".join(struct.pack("<I", i) for i in range(n))
    return bytes(hdr) + sids + tids + bytes(data)


def test_dex_class_names_synthetic():
    dex = _mini_dex([b"Lcom/appsflyer/AppsFlyerLib;", b"I", b"Lorg/example/Main$1;", b"[B"])
    assert dex_class_names(dex) == ["com.appsflyer.AppsFlyerLib", "org.example.Main$1"]
    with pytest.raises(ValueError):
        dex_class_names(b"PK\x03\x04" + b"\0" * 200)
    # a truncated table does not blow up
    assert dex_class_names(dex[:0x7c]) == []


# ---------------- manifest parsing (static XML) ----------------
_XML = b"""<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app" android:versionCode="7" android:versionName="1.2">
  <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.CAMERA" android:maxSdkVersion="28"/>
  <permission android:name="com.example.app.permission.C2D" android:protectionLevel="0x00000012"/>
  <uses-feature android:name="android.hardware.camera"/>
  <uses-feature android:glEsVersion="0x00020000" android:required="true"/>
  <application android:name=".App" android:debuggable="true" android:allowBackup="false">
    <meta-data android:name="com.google.android.gms.ads.APPLICATION_ID" android:value="ca-app-pub-1"/>
    <meta-data android:name="fcm_icon" android:resource="@7F0800F2"/>
    <activity android:name=".Main" android:launchMode="2">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
    <activity android:name="Plain"/>
    <activity-alias android:name=".Alias" android:targetActivity=".Main" android:exported="true"/>
    <activity android:name="com.google.android.gms.ads.AdActivity" android:exported="false"/>
    <service android:name="com.onesignal.SyncService" android:permission="android.permission.BIND_JOB_SERVICE"
             android:enabled="false" android:process=":remote"/>
    <receiver android:name=".Boot">
      <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED"/>
        <data android:scheme="https" android:host="example.com" android:port="443" android:pathPrefix="/x"
              android:mimeType="text/plain"/>
      </intent-filter>
    </receiver>
    <provider android:name=".Files" android:authorities="com.example.app.files;com.example.app.more"
              android:grantUriPermissions="true"/>
    <uses-library android:name="org.apache.http.legacy" android:required="false"/>
  </application>
</manifest>"""


def test_parse_manifest_static():
    etree = pytest.importorskip("lxml.etree")
    m = parse_manifest(etree.fromstring(_XML), "com.example.app")
    assert m["package"] == "com.example.app" and m["version_code"] == 7 and m["version_name"] == "1.2"
    assert (m["min_sdk"], m["target_sdk"], m["max_sdk"]) == (21, 30, None)
    assert m["debuggable"] is True and m["allow_backup"] is False and m["test_only"] is False
    assert m["uses_cleartext_traffic"] is False        # targetSdk 28+ default
    assert m["application_class"] == "com.example.app.App"
    assert m["main_activity"] == "com.example.app.Main"
    acts = {a["name"]: a for a in m["activities"]}
    assert set(acts) == {"com.example.app.Main", "com.example.app.Plain", "com.example.app.Alias",
                         "com.google.android.gms.ads.AdActivity"}
    main = acts["com.example.app.Main"]
    assert main["exported"] is True                    # implicit via intent-filter, targetSdk < 31
    assert main["launch_mode"] == "singleTask"
    assert main["intent_filters"] == [{"actions": ["android.intent.action.MAIN"],
                                       "categories": ["android.intent.category.LAUNCHER"], "data": []}]
    assert acts["com.example.app.Plain"]["exported"] is False and acts["com.example.app.Plain"]["tracker"] is None
    assert acts["com.example.app.Alias"]["alias"] is True
    assert acts["com.example.app.Alias"]["target_activity"] == "com.example.app.Main"
    assert acts["com.google.android.gms.ads.AdActivity"]["tracker"] == "Google AdMob"
    svc = m["services"][0]
    assert svc["name"] == "com.onesignal.SyncService" and svc["tracker"] == "OneSignal"
    assert svc["permission"] == "android.permission.BIND_JOB_SERVICE"
    assert svc["enabled"] is False and svc["process"] == ":remote" and svc["launch_mode"] is None
    rcv = m["receivers"][0]
    assert rcv["intent_filters"][0]["data"] == [{"scheme": "https", "host": "example.com:443",
                                                 "path": "/x", "mime": "text/plain"}]
    prov = m["providers"][0]
    assert prov["authorities"] == ["com.example.app.files", "com.example.app.more"]
    assert prov["grant_uri_permissions"] is True and prov["exported"] is False
    assert m["uses_permissions"] == [
        {"name": "android.permission.INTERNET", "max_sdk": None, "dangerous": False},
        {"name": "android.permission.CAMERA", "max_sdk": 28, "dangerous": True}]
    assert m["declared_permissions"] == [{"name": "com.example.app.permission.C2D",
                                          "protection_level": "signature|privileged"}]
    assert m["features"] == [{"name": "android.hardware.camera", "required": True},
                             {"name": "android.hardware.opengles.version=0x00020000", "required": True}]
    assert m["libraries"] == [{"name": "org.apache.http.legacy", "required": False}]
    assert m["meta_data"] == {"com.google.android.gms.ads.APPLICATION_ID": "ca-app-pub-1",
                              "fcm_icon": "@7F0800F2"}
    assert component_kinds(m) == {
        "com.example.app.Main": "activity", "com.example.app.Plain": "activity",
        "com.example.app.Alias": "activity", "com.google.android.gms.ads.AdActivity": "activity",
        "com.onesignal.SyncService": "service", "com.example.app.Boot": "receiver",
        "com.example.app.Files": "provider"}
    assert component_kinds(None) == {}


# ---------------- real APK through a fake device ----------------
class _Store:
    """Snapshot store that round-trips JSON like the real one."""

    def __init__(self) -> None:
        self.snapshots: dict[str, object] = {}

    def get_snapshot(self, key):
        return self.snapshots.get(key)

    def put_snapshot(self, key, data):
        self.snapshots[key] = json.loads(json.dumps(data, default=str))


class _Adb:
    def __init__(self, paths: list[str]) -> None:
        self.paths = paths
        self.cmds: list[str] = []

    def apk_paths(self, pkg):
        return list(self.paths)

    def shell_sync(self, cmd, *, su=False, timeout=20):
        self.cmds.append(cmd)
        if cmd.startswith("stat -c %s "):
            return "\n".join("4242" for _ in cmd.split(" ")[3:]) + "\n"
        return ""


class _Ctx:
    def __init__(self, paths: list[str]) -> None:
        self.adb = _Adb(paths)
        self.store = _Store()


@pytest.fixture
def local_reader(monkeypatch):
    """Serve the sample APK's bytes through manifest._adb_range_reader and
    record every byte-range read (the reader itself is also consulted for the
    size on a cache hit, so only reads prove the APK was re-parsed)."""
    data = SAMPLE_APK.read_bytes()
    reads: list[tuple[int, int]] = []

    def reader(adb, path):
        def read_range(off, ln):
            reads.append((off, ln))
            return data[off:off + ln]
        return len(data), read_range
    monkeypatch.setattr(manifest, "_adb_range_reader", reader)
    return reads


@needs_apk
def test_inspect_apk_sample(local_reader):
    pytest.importorskip("pyaxmlparser")
    ctx = _Ctx([APK_PATH, APK_PATH.replace("base.apk", "split_config.arm64_v8a.apk")])
    m = inspect_apk(ctx, PKG)
    assert "error" not in m, m.get("error")
    assert m["package"] == PKG and m["version_name"] == "1.21.0" and m["version_code"] == 1021050
    assert (m["min_sdk"], m["target_sdk"]) == (23, 29)
    assert len(m["activities"]) == 25 and len(m["services"]) == 16
    assert len(m["receivers"]) == 15 and len(m["providers"]) == 4
    assert m["main_activity"] == "org.fdroid.fdroid.views.main.MainActivity"
    perms = {p["name"]: p for p in m["uses_permissions"]}
    assert perms["android.permission.INTERNET"]["dangerous"] is False
    assert any(p["dangerous"] for p in perms.values())
    assert m["dex_files"] == ["classes.dex", "classes2.dex"] and m["multidex"] is True
    assert m["native_libs"] == []
    assert m["manifest_xml"].startswith("<manifest") and "org.fdroid.fdroid" in m["manifest_xml"]
    assert m["apk_path"] == APK_PATH and m["apk_size"] == SAMPLE_APK.stat().st_size
    # split sizes came from one quoted stat call
    assert m["splits"] == [{"path": APK_PATH.replace("base.apk", "split_config.arm64_v8a.apk"),
                            "size": 4242}]
    assert sum(c.startswith("stat -c %s '") for c in ctx.adb.cmds) == 1
    assert m["cached"] is False and all(c["tracker"] is None for c in m["activities"])
    # signatures: F-Droid signs v1 + v2 + v3 with one certificate
    sig = m["signatures"]
    assert len(sig) == 1 and sig[0]["scheme"] == "v1+v2+v3"
    assert "Ciaran Gultnieks" in sig[0]["subject"] and sig[0]["issuer"]
    assert len(sig[0]["sha256"]) == 64 and len(sig[0]["sha1"]) == 40 and len(sig[0]["md5"]) == 32
    assert sig[0]["not_before"].startswith("2010-") and sig[0]["algorithm"] == "sha1WithRSAEncryption"


@needs_apk
def test_inspect_apk_caches_by_path_and_size(local_reader):
    pytest.importorskip("pyaxmlparser")
    ctx = _Ctx([APK_PATH])
    first = inspect_apk(ctx, PKG)
    n_reads = len(local_reader)
    assert first["cached"] is False and n_reads > 0
    again = inspect_apk(ctx, PKG)
    assert again["cached"] is True and len(local_reader) == n_reads       # no re-read
    assert again["activities"] == first["activities"] and "_key" not in again
    assert ctx.store.snapshots["manifests"][PKG]["_key"] == f"{APK_PATH}:{SAMPLE_APK.stat().st_size}"
    assert inspect_apk(ctx, PKG, refresh=True)["cached"] is False and len(local_reader) == 2 * n_reads
    # a different APK path (reinstall) invalidates the entry
    ctx.adb.paths = ["/data/app/~~new==/org.fdroid.fdroid-2==/base.apk"]
    assert inspect_apk(ctx, PKG)["cached"] is False and len(local_reader) == 3 * n_reads
    assert manifest.cached_manifest(ctx, PKG)["cached"] is True
    assert manifest.cached_manifest(ctx, "com.never") is None


@needs_apk
def test_scan_app_sample(local_reader):
    pytest.importorskip("pyaxmlparser")
    ctx = _Ctx([APK_PATH])
    s = scan_app(ctx, PKG)
    assert "error" not in s, s.get("error")
    assert s["package"] == PKG and s["dex_files"] == 2 and s["truncated"] is False
    assert s["classes_scanned"] > 10000 and s["cached"] is False and s["scanned_at"] > 0
    libs = {lib["name"]: lib for lib in s["libraries"]}
    assert libs["OkHttp"]["classes"] > 50 and libs["ZXing"]["classes"] > 50
    assert libs["OkHttp"]["website"].startswith("http")
    assert s["trackers"] == []                   # F-Droid is tracker-free
    assert s["native_libs"] == [] and s["apk_size"] == SAMPLE_APK.stat().st_size
    # the manifest was inspected (and cached) for component attribution
    assert PKG in ctx.store.snapshots["manifests"]
    assert scan_app(ctx, PKG)["cached"] is True
    assert manifest.cached_scan(ctx, PKG)["libraries"] == s["libraries"]
    assert scan_app(ctx, PKG, refresh=True)["cached"] is False


@needs_apk
def test_scan_finds_app_classes_and_signing_block(local_reader):
    data = SAMPLE_APK.read_bytes()
    rz = manifest._ApkZip(len(data), lambda off, ln: data[off:off + ln])
    names = dex_class_names(rz.extract("classes.dex")) + dex_class_names(rz.extract("classes2.dex"))
    assert any(n.startswith("org.fdroid.fdroid.") for n in names)
    assert "okhttp3.OkHttpClient" in names
    # v2 and v3 blocks each carry the same signer certificate
    blk = manifest._signing_block(rz)
    assert blk is not None
    ids = {iid for iid, _ in manifest._block_pairs(blk)}
    assert {0x7109871A, 0xF05368C0} <= ids
    certs = {hash(der) for iid, val in manifest._block_pairs(blk)
             if iid in (0x7109871A, 0xF05368C0) for der in manifest._signer_certs(val)}
    assert len(certs) == 1


def test_signing_block_absent_or_mangled(tmp_path):
    import zipfile
    p = tmp_path / "plain.apk"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"x" * 100)
    data = p.read_bytes()
    rz = manifest._ApkZip(len(data), lambda off, ln: data[off:off + ln])
    assert rz.cd_off > 0 and manifest._signing_block(rz) is None
    assert manifest.apk_signatures(rz) == []
    assert manifest._signer_certs(b"\x10\x00\x00\x00garbage") == []
    assert manifest._block_pairs(struct.pack("<Q", 24) + b"\0" * 24) == []


def test_errors_are_results_not_exceptions(local_reader):
    assert inspect_apk(_Ctx([APK_PATH]), "bad pkg!") == {
        "package": "bad pkg!", "error": "invalid package name", "cached": False}
    assert scan_app(_Ctx([]), "com.gone") == {
        "package": "com.gone", "error": "no APK path (not installed for this user?)", "cached": False}
    # an APK outside the known install locations never reaches a shell
    got = inspect_apk(_Ctx(["/sdcard/evil.apk"]), "com.x")
    assert got["error"].startswith("unexpected APK path") and local_reader == []
    got = inspect_apk(_Ctx(["/data/app/x/base.apk; id"]), "com.x")
    assert "error" in got and local_reader == []
