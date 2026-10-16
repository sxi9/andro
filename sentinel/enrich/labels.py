"""Human-readable app names (and optionally icons) for package names.

Three tiers, cheapest first:
  1. a built-in map of the packages people actually look for
     ("com.android.chrome" -> "Chrome")
  2. a heuristic from the package name ("com.foo.weatherpro" -> "Weatherpro")
  3. the real label from the APK's own resources, extracted WITHOUT pulling
     the whole APK: we read the zip's central directory over adb, fetch only
     AndroidManifest.xml + resources.arsc by byte range, and decode them with
     `pyaxmlparser` (a requirement, but imported lazily so everything else
     works without it). Results are cached in the store; for WebAPKs the
     manifest's start URL / scope / host browser are cached too ("apk_meta").
"""
from __future__ import annotations

import io
import logging
import os
import re
import struct
import tempfile
import zipfile
import zlib
from typing import Callable

log = logging.getLogger("sentinel.labels")

# Chromium-style WebAPKs: a browser-generated shell whose package is a hash,
# so the only useful name lives in the manifest (see _manifest_meta).
_WEBAPK_RE = re.compile(r"^org\.chromium\.webapk\.|\.webapk\.")
# "foo_v2" -> "foo"; a bare "v2" segment becomes empty (dropped). A bare vN is
# stripped only when it IS the segment, so "tv2" stays a word.
_VSUFFIX_RE = re.compile(r"(?:^|_)v\d+$")
_HEXHASH_RE = re.compile(r"^[a-f0-9]{8,}(_v\d+)?$")
_HEX = set("0123456789abcdef")
# generic vendor/noise segments never shown as a name
_NOISE = {"android", "app", "apps", "mobile", "client", "ui", "lite", "pro", "free"}

BUILTIN_LABELS: dict[str, str] = {
    # Google
    "com.android.chrome": "Chrome", "com.google.android.apps.photos": "Google Photos",
    "com.google.android.gm": "Gmail", "com.google.android.apps.maps": "Google Maps",
    "com.google.android.youtube": "YouTube", "com.google.android.apps.youtube.music": "YouTube Music",
    "com.google.android.gms": "Google Play Services", "com.android.vending": "Google Play Store",
    "com.google.android.googlequicksearchbox": "Google", "com.google.android.apps.messaging": "Messages",
    "com.google.android.dialer": "Phone", "com.google.android.contacts": "Contacts",
    "com.google.android.calendar": "Google Calendar", "com.google.android.keep": "Google Keep",
    "com.google.android.apps.docs": "Google Drive", "com.google.android.apps.tachyon": "Google Meet",
    "com.google.android.apps.nbu.files": "Files by Google", "com.google.android.deskclock": "Clock",
    "com.google.android.calculator": "Calculator", "com.google.android.apps.walletnfcrel": "Google Wallet",
    "com.google.android.apps.translate": "Google Translate", "com.google.android.apps.chromecast.app": "Google Home",
    "com.google.android.apps.fitness": "Google Fit", "com.google.android.apps.authenticator2": "Google Authenticator",
    "com.google.android.inputmethod.latin": "Gboard", "com.google.android.tts": "Speech Services",
    "com.google.android.webview": "Android System WebView", "com.google.android.apps.wellbeing": "Digital Wellbeing",
    "com.google.android.apps.safetyhub": "Personal Safety", "com.google.android.apps.recorder": "Recorder",
    "com.google.android.apps.turbo": "Device Health Services", "com.google.android.projection.gearhead": "Android Auto",
    # Android system
    "com.android.settings": "Settings", "com.android.systemui": "System UI",
    "com.android.phone": "Phone Services", "com.android.providers.contacts": "Contacts Storage",
    "com.android.providers.media": "Media Storage", "com.android.bluetooth": "Bluetooth",
    "com.android.camera2": "Camera", "com.android.documentsui": "Files",
    "com.android.packageinstaller": "Package Installer", "com.google.android.packageinstaller": "Package Installer",
    "com.android.shell": "Shell", "com.android.nfc": "NFC Service",
    # Samsung
    "com.sec.android.app.camera": "Camera (Samsung)", "com.samsung.android.messaging": "Samsung Messages",
    "com.sec.android.app.sbrowser": "Samsung Internet", "com.samsung.android.app.notes": "Samsung Notes",
    "com.sec.android.gallery3d": "Gallery", "com.samsung.android.dialer": "Phone (Samsung)",
    "com.sec.android.app.samsungapps": "Galaxy Store", "com.samsung.android.bixby.agent": "Bixby",
    "com.samsung.android.oneconnect": "SmartThings", "com.sec.android.app.myfiles": "My Files",
    "com.samsung.android.lool": "Device Care", "com.samsung.android.spay": "Samsung Pay",
    "com.samsung.android.app.spage": "Samsung Free", "com.samsung.android.calendar": "Samsung Calendar",
    # Messaging / social
    "com.whatsapp": "WhatsApp", "com.whatsapp.w4b": "WhatsApp Business",
    "org.telegram.messenger": "Telegram", "org.thoughtcrime.securesms": "Signal",
    "com.facebook.katana": "Facebook", "com.facebook.orca": "Messenger",
    "com.facebook.lite": "Facebook Lite", "com.instagram.android": "Instagram",
    "com.zhiliaoapp.musically": "TikTok", "com.ss.android.ugc.trill": "TikTok",
    "com.snapchat.android": "Snapchat", "com.twitter.android": "X",
    "com.reddit.frontpage": "Reddit", "com.discord": "Discord",
    "com.linkedin.android": "LinkedIn", "com.pinterest": "Pinterest",
    "com.viber.voip": "Viber", "jp.naver.line.android": "LINE",
    "com.tencent.mm": "WeChat", "com.skype.raider": "Skype",
    "us.zoom.videomeetings": "Zoom", "com.microsoft.teams": "Microsoft Teams",
    "com.Slack": "Slack",
    # Media / shopping / misc
    "com.spotify.music": "Spotify", "com.netflix.mediaclient": "Netflix",
    "com.amazon.mShop.android.shopping": "Amazon Shopping", "com.amazon.avod.thirdpartyclient": "Prime Video",
    "com.amazon.kindle": "Kindle", "com.ebay.mobile": "eBay",
    "com.ubercab": "Uber", "com.ubercab.eats": "Uber Eats",
    "com.airbnb.android": "Airbnb", "com.booking": "Booking.com",
    "com.paypal.android.p2pmobile": "PayPal", "com.google.android.apps.paidtasks": "Google Opinion Rewards",
    "com.microsoft.office.outlook": "Outlook", "com.microsoft.office.word": "Word",
    "com.microsoft.office.excel": "Excel", "com.microsoft.skydrive": "OneDrive",
    "com.dropbox.android": "Dropbox", "com.adobe.reader": "Adobe Acrobat",
    "com.duolingo": "Duolingo", "com.strava": "Strava",
    "com.myfitnesspal.android": "MyFitnessPal", "com.fitbit.FitbitMobile": "Fitbit",
    "com.waze": "Waze", "com.twitch.android.app": "Twitch",
    "tv.twitch.android.app": "Twitch", "com.roku.remote": "Roku",
    "com.brave.browser": "Brave", "org.mozilla.firefox": "Firefox",
    "com.opera.browser": "Opera", "com.microsoft.emmx": "Microsoft Edge",
    "com.sec.android.app.launcher": "One UI Home", "com.google.android.apps.nexuslauncher": "Pixel Launcher",
    "com.termux": "Termux", "org.fdroid.fdroid": "F-Droid",
    "io.github.muntashirakon.AppManager": "App Manager", "com.topjohnwu.magisk": "Magisk",
    "eu.chainfire.supersu": "SuperSU", "me.weishu.kernelsu": "KernelSU",
    # Browsers (the role-holder views lean on these)
    "org.chromium.chrome": "Chromium", "com.kiwibrowser.browser": "Kiwi Browser",
    "org.cromite.cromite": "Cromite", "org.bromite.bromite": "Bromite",
    "app.vanadium.browser": "Vanadium", "us.spotco.mulch": "Mulch",
    "org.mozilla.fenix": "Firefox Nightly", "us.spotco.fennec_dos": "Mull",
    "org.lineageos.jelly": "Jelly Browser", "com.vivaldi.browser": "Vivaldi",
    "com.duckduckgo.mobile.android": "DuckDuckGo", "com.mi.globalbrowser": "Mi Browser",
    "com.android.browser": "Browser", "org.matrix.chromext": "ChromeXt",
    # AOSP / custom-ROM defaults
    "com.miui.gallery": "Gallery (MIUI)", "org.lineageos.aperture": "Aperture Camera",
    "com.android.launcher3": "Launcher3", "com.android.dialer": "Phone",
    "com.android.messaging": "Messaging",
}


def _hash_like(seg: str) -> bool:
    """True for WebAPK/build-hash segments ("ae2b93f705916af0e", "a1b2c3d4e5f6")
    that would otherwise become the display name."""
    s = seg.lower()
    if _HEXHASH_RE.match(s):
        return True
    if len(s) >= 10 and set(s) <= _HEX:
        return True
    # long tokens that are mostly digits (build ids); shorter ones like "mp3",
    # "x264", "game2048" or "pes2023" are real words
    return len(s) >= 12 and sum(c.isdigit() for c in s) / len(s) >= 0.5


def friendly_name(pkg: str) -> str:
    """Best-effort readable name when no label is known."""
    if pkg in BUILTIN_LABELS:
        return BUILTIN_LABELS[pkg]
    if _WEBAPK_RE.search(pkg):
        return "Web app (WebAPK)"
    parts = [p for p in pkg.split(".") if p]
    if not parts:
        return pkg
    # drop version suffixes and hash-like segments before choosing a name
    words = [w for w in (_VSUFFIX_RE.sub("", p) for p in parts) if w and not _hash_like(w)]
    # prefer the last meaningful segment after the TLD ("com.foo.bar" -> bar);
    # only noise left -> first one after the TLD; only hashes -> whatever remains
    rest = words[1:]
    meaningful = [w for w in rest if w.lower() not in _NOISE]
    if meaningful:
        seg = meaningful[-1]
    elif rest:
        seg = rest[0]
    else:
        seg = words[0] if words else parts[-1]
    seg = seg.replace("_", " ")
    return seg[:1].upper() + seg[1:]


# ---------------- zip-over-adb (ranged) ----------------
_EOCD_SIG = 0x06054B50
_CD_SIG = 0x02014B50
_LH_SIG = 0x04034B50


class RemoteZip:
    """Minimal zip reader over a `read_range(offset, length) -> bytes`
    callable and a known file size. Reads only the central directory and the
    entries asked for, so a 150 MB APK costs a couple of MB to inspect."""

    def __init__(self, size: int, read_range: Callable[[int, int], bytes]) -> None:
        self.size = size
        self.read = read_range
        self.entries: dict[str, tuple[int, int, int, int]] = {}  # name -> (method, csize, usize, lh_off)
        self._load_cd()

    def _load_cd(self) -> None:
        tail_len = min(self.size, 65557)
        tail = self.read(self.size - tail_len, tail_len)
        idx = tail.rfind(struct.pack("<I", _EOCD_SIG))
        if idx < 0:
            raise ValueError("no zip end-of-central-directory")
        _sig, _dn, _cdn, _n_this, _n_total, cd_size, cd_off, _clen = struct.unpack(
            "<IHHHHIIH", tail[idx:idx + 22])
        cd = self.read(cd_off, cd_size)
        pos = 0
        while pos + 46 <= len(cd):
            if struct.unpack("<I", cd[pos:pos + 4])[0] != _CD_SIG:
                break
            (_sig, _vm, _vn, _flag, method, _t, _d, _crc, csize, usize,
             nlen, elen, clen, _dsk, _ia, _ea, lh_off) = struct.unpack("<IHHHHHHIIIHHHHHII", cd[pos:pos + 46])
            name = cd[pos + 46:pos + 46 + nlen].decode("utf-8", "replace")
            self.entries[name] = (method, csize, usize, lh_off)
            pos += 46 + nlen + elen + clen

    def extract(self, name: str) -> bytes:
        method, csize, usize, lh_off = self.entries[name]
        lh = self.read(lh_off, 30)
        if struct.unpack("<I", lh[:4])[0] != _LH_SIG:
            raise ValueError("bad local header for " + name)
        nlen, elen = struct.unpack("<HH", lh[26:30])
        data = self.read(lh_off + 30 + nlen + elen, csize)
        if method == 0:
            return data
        if method == 8:
            return zlib.decompress(data, -15)
        raise ValueError(f"unsupported zip method {method} for {name}")


def _adb_range_reader(adb, remote_path: str) -> tuple[int, Callable[[int, int], bytes]]:
    """Size + byte-range reader for a device file, via exec-out tail/head."""
    import shlex
    q = shlex.quote(remote_path)
    size = int(adb.shell_sync(f"stat -c %s {q}", timeout=15).strip() or "0")

    def read_range(off: int, length: int) -> bytes:
        # tail -c +N is 1-based; exec-out keeps the bytes intact
        cmd = f"tail -c +{off + 1} {q} | head -c {length}"
        return adb.exec_out_bytes(cmd, timeout=120)
    return size, read_range


_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
# <meta-data android:name=...> entries a Chromium WebAPK shell carries
_META_KEYS = {
    "org.chromium.webapk.shell_apk.hostBrowserPackageName": "host_browser",
    "org.chromium.webapk.shell_apk.startUrl": "start_url",
    "org.chromium.webapk.shell_apk.scope": "scope",
}


def _manifest_meta(root) -> dict:
    """{host_browser?, start_url?, scope?} from <application><meta-data> of a
    parsed manifest (lxml Element). Anything odd -> {} rather than an error."""
    out: dict[str, str] = {}
    try:
        app = root.find("application") if root is not None else None
        for md in (app.findall("meta-data") if app is not None else []):
            key = _META_KEYS.get(md.get(_ANDROID_NS + "name") or "")
            val = md.get(_ANDROID_NS + "value")
            if key and val is not None and str(val).strip():
                out[key] = str(val).strip()
    except Exception as e:  # noqa: BLE001 - manifest quirks are not our problem
        log.debug("manifest meta: %s", e)
        return {}
    return out


def extract_label_from_apk(size: int, read_range: Callable[[int, int], bytes]) -> dict:
    """Return {label?, meta?} using only the manifest + resources; meta is the
    WebAPK subset from _manifest_meta and is present only when non-empty."""
    try:
        from pyaxmlparser import APK  # type: ignore
    except ImportError:
        return {}
    rz = RemoteZip(size, read_range)
    wanted = ["AndroidManifest.xml", "resources.arsc"]
    if not all(w in rz.entries for w in wanted):
        return {}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for w in wanted:
            zf.writestr(w, rz.extract(w))
    # pyaxmlparser wants a path
    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tf:
        tf.write(buf.getvalue())
        tmp = tf.name
    try:
        apk = APK(tmp)
        label = (apk.get_app_name() or "").strip()
        out: dict = {"label": label} if label else {}
        meta = _manifest_meta(apk.get_android_manifest_xml())
        if meta:
            out["meta"] = meta
        return out
    except Exception as e:  # noqa: BLE001 - any APK quirk just means "no label"
        log.debug("label extraction failed: %s", e)
        return {}
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def resolve_labels(dctx, pkgs: list[str], progress=None) -> dict[str, str]:
    """Resolve real labels for pkgs over adb, caching in the device store.
    Returns {pkg: label} for everything resolved (cached + new). WebAPK
    manifest facts land in the "apk_meta" snapshot alongside."""
    cache: dict[str, str] = dctx.store.get_snapshot("labels") or {}
    meta_cache: dict[str, dict] = dctx.store.get_snapshot("apk_meta") or {}
    # WebAPKs labelled before meta existed are read once more for their URL
    todo = [p for p in pkgs
            if p not in cache or (_WEBAPK_RE.search(p) and p not in meta_cache)]
    for i, pkg in enumerate(todo):
        try:
            paths = dctx.adb.apk_paths(pkg)
            if not paths:
                continue
            size, rr = _adb_range_reader(dctx.adb, paths[0])
            if size <= 0:
                continue
            got = extract_label_from_apk(size, rr)
            if got.get("label"):
                cache[pkg] = got["label"]
            if got.get("meta"):
                meta_cache[pkg] = got["meta"]
        except Exception as e:  # noqa: BLE001
            log.debug("label %s: %s", pkg, e)
        if progress and (i % 10 == 0 or i == len(todo) - 1):
            progress(i + 1, len(todo))
        if i % 25 == 0:
            dctx.store.put_snapshot("labels", cache)
            dctx.store.put_snapshot("apk_meta", meta_cache)
    dctx.store.put_snapshot("labels", cache)
    dctx.store.put_snapshot("apk_meta", meta_cache)
    return cache


def label_for(pkg: str, cache: dict[str, str] | None = None) -> str:
    if cache and pkg in cache:
        return cache[pkg]
    return friendly_name(pkg)
