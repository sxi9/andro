"""App-name resolution: built-in map, heuristic, and ranged APK label extraction."""
from __future__ import annotations

import io
import os
import zipfile
from pathlib import Path

import pytest

from sentinel.enrich import labels
from sentinel.enrich.labels import (RemoteZip, _manifest_meta, extract_label_from_apk,
                                    friendly_name, label_for, resolve_labels)

SAMPLE_APK = Path("/tmp/claude-0/-home-user-andro/9f21e297-6624-5b9e-afc1-ff4f09c54e08/"
                  "scratchpad/apk-test/fdroid-sample.apk")


def test_friendly_names():
    assert friendly_name("com.android.chrome") == "Chrome"
    assert friendly_name("com.google.android.apps.photos") == "Google Photos"
    assert friendly_name("com.wx.weatherpro") == "Weatherpro"
    assert friendly_name("com.led.qr_flash") == "Qr flash"
    assert label_for("com.whatsapp") == "WhatsApp"
    assert label_for("com.x.y", {"com.x.y": "Real Name"}) == "Real Name"


def test_friendly_names_skip_webapks_and_hashes():
    # Chromium WebAPK shells: the package is a hash, never a name
    assert friendly_name("org.chromium.webapk.ae2b93f705916af0e_v2") == "Web app (WebAPK)"
    assert friendly_name("com.sec.android.app.sbrowser.webapk.abc123def4567890") == "Web app (WebAPK)"
    # hash-like tail segment and version suffix are skipped, not capitalised
    got = friendly_name("com.foo.a1b2c3d4e5f6_v2")
    assert "a1b2" not in got.lower() and got == "Foo"
    assert friendly_name("com.example.scanner_v3") == "Scanner"
    assert friendly_name("com.example.scanner.v2") == "Scanner"
    # everything after the TLD is hash -> first real segment
    assert friendly_name("org.chromium.ae2b93f705916af0e") == "Chromium"
    # short digit-bearing tokens are still words
    assert friendly_name("com.example.mp3") == "Mp3"
    # new browser/ROM entries resolve from the built-in map
    assert friendly_name("org.matrix.chromext") == "ChromeXt"
    assert friendly_name("org.cromite.cromite") == "Cromite"
    assert friendly_name("com.miui.gallery") == "Gallery (MIUI)"


_MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="org.chromium.webapk.ae2b93f705916af0e_v2">
  <application android:label="ChatGPT">
    <meta-data android:name="org.chromium.webapk.shell_apk.hostBrowserPackageName"
               android:value="org.cromite.cromite"/>
    <meta-data android:name="org.chromium.webapk.shell_apk.startUrl"
               android:value="https://chatgpt.com/"/>
    <meta-data android:name="org.chromium.webapk.shell_apk.scope"
               android:value="https://chatgpt.com/"/>
    <meta-data android:name="org.chromium.webapk.shell_apk.shellApkVersion"
               android:value="170"/>
    <activity android:name=".MainActivity">
      <meta-data android:name="org.chromium.webapk.shell_apk.startUrl"
                 android:value="https://ignored.example/"/>
    </activity>
  </application>
</manifest>"""


def test_manifest_meta_reads_webapk_entries():
    etree = pytest.importorskip("lxml.etree")
    root = etree.fromstring(_MANIFEST.encode())
    assert _manifest_meta(root) == {"host_browser": "org.cromite.cromite",
                                    "start_url": "https://chatgpt.com/",
                                    "scope": "https://chatgpt.com/"}
    # tolerant of anything that is not a WebAPK manifest
    assert _manifest_meta(None) == {}
    assert _manifest_meta(etree.fromstring(b"<manifest/>")) == {}
    assert _manifest_meta(etree.fromstring(b"<manifest><application/></manifest>")) == {}
    assert _manifest_meta(object()) == {}


class _Store:
    def __init__(self) -> None:
        self.snapshots: dict[str, object] = {}
        self.puts: list[str] = []

    def get_snapshot(self, key):
        return self.snapshots.get(key)

    def put_snapshot(self, key, data):
        self.puts.append(key)
        self.snapshots[key] = data


class _Adb:
    def apk_paths(self, pkg):
        return ["/data/app/~~x/" + pkg + "-1/base.apk"]


class _Ctx:
    def __init__(self) -> None:
        self.adb = _Adb()
        self.store = _Store()


def test_resolve_labels_writes_labels_and_meta_snapshots(monkeypatch):
    ctx = _Ctx()
    ctx.store.snapshots["labels"] = {"com.cached": "Cached"}
    monkeypatch.setattr(labels, "_adb_range_reader", lambda adb, path: (1234, lambda o, n: b""))
    monkeypatch.setattr(labels, "extract_label_from_apk",
                        lambda size, rr: {"label": "ChatGPT",
                                          "meta": {"start_url": "https://chatgpt.com/"}})
    pkg = "org.chromium.webapk.ae2b93f705916af0e_v2"
    seen: list[tuple[int, int]] = []
    got = resolve_labels(ctx, [pkg, "com.cached"], progress=lambda i, n: seen.append((i, n)))
    assert got == {"com.cached": "Cached", pkg: "ChatGPT"}
    assert ctx.store.snapshots["labels"] == got
    assert ctx.store.snapshots["apk_meta"] == {pkg: {"start_url": "https://chatgpt.com/"}}
    assert "labels" in ctx.store.puts and "apk_meta" in ctx.store.puts
    assert seen == [(1, 1)]  # the cached package was not re-read


def _local_reader(path: Path):
    data = path.read_bytes()
    return len(data), (lambda off, ln: data[off:off + ln])


def test_remote_zip_reads_only_requested_entries(tmp_path: Path):
    # build a zip with a few entries, read it through the ranged reader
    p = tmp_path / "t.zip"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>" * 50)
        zf.writestr("resources.arsc", b"\x02\x00\x0c\x00" + b"R" * 1000)
        # big, incompressible payload so the file is far larger than the 64 KB
        # end-of-directory window the reader has to fetch
        zf.writestr("classes.dex", os.urandom(400_000))
    size, rr = _local_reader(p)
    reads: list[tuple[int, int]] = []

    def counting(off, ln):
        reads.append((off, ln))
        return rr(off, ln)

    rz = RemoteZip(size, counting)
    assert set(rz.entries) == {"AndroidManifest.xml", "resources.arsc", "classes.dex"}
    assert rz.extract("AndroidManifest.xml") == b"<manifest/>" * 50
    assert rz.extract("resources.arsc").startswith(b"\x02\x00\x0c\x00")
    # we never read the big classes.dex entry
    total = sum(ln for _, ln in reads)
    assert total < size


@pytest.mark.skipif(not SAMPLE_APK.exists(), reason="sample APK not downloaded")
def test_extract_label_from_real_apk():
    pytest.importorskip("pyaxmlparser")
    size, rr = _local_reader(SAMPLE_APK)
    got = extract_label_from_apk(size, rr)
    assert got.get("label") == "F-Droid"
