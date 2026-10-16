"""APK inspection over a ranged reader: manifest, signatures, dex scan,
signature tables and the prefix matcher."""
from __future__ import annotations

import datetime
import io
import json
import re
import struct
import time
import zipfile
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
_ISO_UTC = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00")

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


def test_protection_level_flags_match_aosp():
    pl = manifest._protection_level
    assert pl("0x00000012") == "signature|privileged"
    # PermissionInfo.PROTECTION_FLAG_* tail bits (module..knownSigner)
    assert pl("0x00400002") == "signature|module"
    assert pl("0x00800002") == "signature|companion"
    assert pl("0x01000002") == "signature|retailDemo"
    assert pl("0x02000002") == "signature|recents"
    assert pl("0x04000012") == "signature|privileged|role"
    assert pl("0x08000002") == "signature|knownSigner"
    assert pl("0x00000081") == "dangerous|pre23" and pl("3") == "signatureOrSystem"
    assert pl(None) is None and pl("dangerous") == "dangerous"
    bits = [b for b, _ in manifest._PROT_FLAGS]
    assert bits == sorted(bits) and all(b & (b - 1) == 0 for b in bits)
    assert len({n for _, n in manifest._PROT_FLAGS}) == len(bits)


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
    # a table outside the file (short read, bogus header) is an error, not 0 classes
    with pytest.raises(ValueError, match="tables outside file"):
        dex_class_names(dex[:0x7c])
    for off in (0x3C, 0x44):                 # string_ids_off, type_ids_off
        bad = bytearray(dex)
        struct.pack_into("<I", bad, off, 0xFFFFFF00)
        with pytest.raises(ValueError, match="tables outside file"):
            dex_class_names(bytes(bad))
    # a huge size with a sane offset is the same corruption
    bad = bytearray(dex)
    struct.pack_into("<I", bad, 0x40, 0x7FFFFFFF)
    with pytest.raises(ValueError):
        dex_class_names(bytes(bad))


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
    assert s["classes_scanned"] > 10000 and s["cached"] is False
    assert _ISO_UTC.fullmatch(s["scanned_at"]) and s["scanned_ts"] > 0
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


# ---------------- main activity choice (static XML) ----------------
def _manifest_xml(body: str) -> bytes:
    return (b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">'
            b'<application>' + body.encode() + b'</application></manifest>')


_MAIN_LAUNCHER = ('<intent-filter><action android:name="android.intent.action.MAIN"/>'
                  '<category android:name="android.intent.category.LAUNCHER"/></intent-filter>')
_MAIN_LEANBACK = ('<intent-filter><action android:name="android.intent.action.MAIN"/>'
                  '<category android:name="android.intent.category.LEANBACK_LAUNCHER"/></intent-filter>')


class _FakeApk:
    """Only the accessors parse_manifest uses; pyaxmlparser's get_main_activity
    (a set.pop(), hash-seed random for several launchers) must not be consulted."""

    def get_min_sdk_version(self):
        return "21"

    def get_target_sdk_version(self):
        return "30"

    def get_max_sdk_version(self):
        return None

    def get_androidversion_name(self):
        return "1.0"

    def get_androidversion_code(self):
        return "1"

    def get_main_activity(self):
        raise AssertionError("pyaxmlparser main activity must not be used")


def test_main_activity_is_first_launcher_in_manifest_order():
    etree = pytest.importorskip("lxml.etree")
    xml = _manifest_xml(
        '<activity android:name=".Old" android:enabled="false">' + _MAIN_LAUNCHER + '</activity>'
        # MAIN and LAUNCHER in two different filters is not a launcher entry
        '<activity android:name=".Split"><intent-filter><action android:name="android.intent.action.MAIN"/>'
        '</intent-filter><intent-filter><category android:name="android.intent.category.LAUNCHER"/>'
        '</intent-filter></activity>'
        '<activity android:name=".Tv">' + _MAIN_LEANBACK + '</activity>'
        '<activity android:name=".Main">' + _MAIN_LAUNCHER + '</activity>'
        '<activity android:name=".Settings">' + _MAIN_LAUNCHER + '</activity>'
        '<activity-alias android:name=".LegacyIcon" android:targetActivity=".Main">' + _MAIN_LAUNCHER
        + '</activity-alias>')
    for apk in (None, _FakeApk()):
        for _ in range(3):
            m = parse_manifest(etree.fromstring(xml), "com.example.app", apk)
            assert m["main_activity"] == "com.example.app.Main"
    # an alias is the entry point only when no activity is
    xml = _manifest_xml('<activity android:name=".Main"/>'
                        '<activity-alias android:name=".Icon" android:targetActivity=".Main">'
                        + _MAIN_LAUNCHER + '</activity-alias>')
    assert parse_manifest(etree.fromstring(xml), "com.example.app")["main_activity"] == "com.example.app.Icon"


def test_main_activity_leanback_only_tv_app():
    etree = pytest.importorskip("lxml.etree")
    xml = _manifest_xml('<activity android:name=".Other"/>'
                        '<activity android:name=".TvMain">' + _MAIN_LEANBACK + '</activity>')
    assert parse_manifest(etree.fromstring(xml), "com.example.tv")["main_activity"] == "com.example.tv.TvMain"
    assert parse_manifest(etree.fromstring(_manifest_xml('<activity android:name=".A"/>')),
                          "com.example.app")["main_activity"] is None


# ---------------- certificates (synthetic) ----------------
def _cert(cn: str, issuer: str, key, signer_key, hash_alg, serial: int):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    now = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
    name = lambda s: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, s)])  # noqa: E731
    return (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(name(issuer))
            .public_key(key.public_key()).serial_number(serial).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650)).sign(signer_key, hash_alg))


def _der(tag: int, body: bytes) -> bytes:
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    ln = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(ln)]) + ln + body


def _pkcs7(certs_der: list[bytes]) -> bytes:
    """SignedData carrying only a certificates SET, in the given order (a
    jarsigner CERT.RSA has the SET DER-sorted, i.e. the shorter CA first)."""
    id_data, id_signed = bytes.fromhex("06092a864886f70d010701"), bytes.fromhex("06092a864886f70d010702")
    sd = _der(0x30, _der(0x02, b"\x01") + _der(0x31, b"") + _der(0x30, id_data)
              + _der(0xA0, b"".join(certs_der)) + _der(0x31, b""))
    return _der(0x30, id_signed + _der(0xA0, sd))


class _CertZip:
    def __init__(self, p7: bytes) -> None:
        self.entries = {"META-INF/CERT.RSA": (0, len(p7), len(p7), 0), "classes.dex": (0, 1, 1, 0)}
        self.cd_off = 0
        self.p7 = p7

    def extract(self, name):
        return self.p7

    def read(self, off, ln):
        return b""


def test_v1_signer_is_the_leaf_not_the_first_cert():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding
    ca_key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca = _cert("CA", "CA", ca_key, ca_key, hashes.SHA256(), 1).public_bytes(Encoding.DER)
    leaf = _cert("App Signer, a longer name", "CA", leaf_key, ca_key, hashes.SHA256(), 2).public_bytes(Encoding.DER)
    # DER SET OF ordering puts the shorter CA cert first, as jarsigner emits it
    assert sorted([ca, leaf]) == [ca, leaf]
    assert manifest._v1_certs(_CertZip(_pkcs7([ca, leaf]))) == [leaf]
    sigs = manifest.apk_signatures(_CertZip(_pkcs7([ca, leaf])))
    assert [(s["scheme"], s["subject"], s["issuer"]) for s in sigs] == [
        ("v1", "CN=App Signer\\, a longer name", "CN=CA")]
    # a lone self-signed cert is its own leaf
    assert manifest._v1_certs(_CertZip(_pkcs7([ca]))) == [ca]
    certs = [x509.load_der_x509_certificate(d) for d in (ca, leaf)]
    assert manifest._signer_cert(certs) is certs[1] and manifest._signer_cert(certs[::-1]) is certs[1]
    assert manifest._signer_cert(certs[:1]) is certs[0]


def test_cert_algorithm_falls_back_to_dotted_oid():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding
    key = ec.generate_private_key(ec.SECP256R1())
    named = _cert("Dev", "Dev", key, key, hashes.SHA256(), 1).public_bytes(Encoding.DER)
    assert manifest._cert_info(named, "v2")["algorithm"] == "ecdsa-with-SHA256"
    # ecdsa-with-SHA3-256 has no name in cryptography: show the OID, not "Unknown OID"
    unnamed = _cert("Dev", "Dev", key, key, hashes.SHA3_256(), 1).public_bytes(Encoding.DER)
    info = manifest._cert_info(unnamed, "v2")
    assert info["algorithm"] == "2.16.840.1.101.3.4.3.10" and info["subject"] == "CN=Dev"
    assert _ISO_UTC.fullmatch(info["not_before"]) and _ISO_UTC.fullmatch(info["not_after"])


# ---------------- synthetic APK through a fake device ----------------
def _apk_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


@pytest.fixture
def serve(monkeypatch):
    """Serve synthetic APK bytes through manifest._adb_range_reader; returns
    the list of byte-range reads."""
    def _serve(data: bytes) -> list[tuple[int, int]]:
        reads: list[tuple[int, int]] = []

        def reader(adb, path):
            def read_range(off, ln):
                reads.append((off, ln))
                return data[off:off + ln]
            return len(data), read_range
        monkeypatch.setattr(manifest, "_adb_range_reader", reader)
        return reads
    return _serve


def test_apk_path_allow_list_includes_adoptable_storage(serve):
    ok = ("/mnt/expand/57f8f4bc-abf4-655f-bf67-946fc0f9f25b/app/com.example-1/base.apk",
          "/mnt/expand/57f8f4bc-abf4-655f-bf67-946fc0f9f25b/app/~~Xy==/com.example-Ab==/split_config.apk",
          "/data/app-private/com.example-1.apk", "/data/app/~~a==/com.x-b==/base.apk",
          "/system/priv-app/Foo/Foo.apk", "/apex/com.android.x/app/Y/Y.apk")
    bad = ("/mnt/expand/../app/x.apk", "/mnt/expand/x.apk", "/mnt/expand//app/x.apk", "/sdcard/x.apk",
           "/data/app/x/base.apk\n", "/data/app/x/base.apk; id", "/data/local/tmp/x.apk", "data/app/x.apk")
    assert all(manifest._APK_PATH_RE.match(p) for p in ok)
    assert not any(manifest._APK_PATH_RE.match(p) for p in bad)
    assert not manifest._PKG.match("com.example\n")
    # an app moved to adopted storage is inspected rather than refused
    reads = serve(_apk_bytes({"classes.dex": b"x"}))
    got = inspect_apk(_Ctx([ok[0], ok[1]]), "com.example")
    assert got["error"] == "no AndroidManifest.xml in APK" and reads      # past the path check, read the zip
    assert got["apk_path"] == ok[0]


def test_scan_synthetic_apk_timestamps_and_corrupt_dex(serve):
    good = _mini_dex([b"Lcom/appsflyer/AppsFlyerLib;", b"Lcom/example/Main;"])
    ctx = _Ctx([APK_PATH])
    serve(_apk_bytes({"classes.dex": good}))
    before = time.time()
    s = scan_app(ctx, PKG)
    assert "error" not in s, s.get("error")
    assert s["classes_scanned"] == 2 and s["dex_files"] == 1 and s["truncated"] is False
    assert [t["name"] for t in s["trackers"]] == ["AppsFlyer"]
    # scanned_at is ISO-8601 UTC (like the certificate dates), scanned_ts the epoch behind it
    assert _ISO_UTC.fullmatch(s["scanned_at"])
    assert before - 1 <= s["scanned_ts"] <= time.time() + 1
    assert abs(datetime.datetime.fromisoformat(s["scanned_at"]).timestamp() - s["scanned_ts"]) < 1
    hit = scan_app(ctx, PKG)
    assert hit["cached"] is True and hit["scanned_at"] == s["scanned_at"]

    # a dex whose string_ids table points outside the file is a scan error,
    # never a clean "0 classes, no trackers" result (and never cached)
    bad = bytearray(good)
    struct.pack_into("<I", bad, 0x3C, 0xFFFFFF00)
    ctx = _Ctx([APK_PATH])
    serve(_apk_bytes({"classes.dex": bytes(bad), "classes2.dex": good}))
    s = scan_app(ctx, PKG)
    assert s["error"] == "classes.dex: dex tables outside file" and s["cached"] is False
    assert "trackers" not in s and ctx.store.snapshots == {}
    s = scan_app(ctx, PKG, refresh=True)
    assert s["error"] == "classes.dex: dex tables outside file"
    # a dex entry that is not a dex at all is reported the same way
    serve(_apk_bytes({"classes.dex": b"PK\x03\x04" + b"\0" * 200}))
    assert scan_app(_Ctx([APK_PATH]), PKG)["error"] == "classes.dex: not a dex file"
