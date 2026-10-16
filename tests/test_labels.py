"""App-name resolution: built-in map, heuristic, and ranged APK label extraction."""
from __future__ import annotations

import io
import os
import zipfile
from pathlib import Path

import pytest

from sentinel.enrich.labels import (RemoteZip, extract_label_from_apk, friendly_name,
                                    label_for)

SAMPLE_APK = Path("/tmp/claude-0/-home-user-andro/9f21e297-6624-5b9e-afc1-ff4f09c54e08/"
                  "scratchpad/apk-test/fdroid-sample.apk")


def test_friendly_names():
    assert friendly_name("com.android.chrome") == "Chrome"
    assert friendly_name("com.google.android.apps.photos") == "Google Photos"
    assert friendly_name("com.wx.weatherpro") == "Weatherpro"
    assert friendly_name("com.led.qr_flash") == "Qr flash"
    assert label_for("com.whatsapp") == "WhatsApp"
    assert label_for("com.x.y", {"com.x.y": "Real Name"}) == "Real Name"


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
