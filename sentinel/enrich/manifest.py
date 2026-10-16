"""APK inspection without pulling the whole APK: manifest, signing
certificates and a tracker/library scan of the dex code.

Everything is read by byte range over adb through labels.RemoteZip: the zip
central directory, AndroidManifest.xml, resources.arsc, the META-INF
signature files, the APK Signing Block (v2/v3) and, for a scan, each
classes*.dex one at a time. A 150 MB game costs a few MB to inspect and
only its dex files to scan.

Both entry points block (adb + parsing) and are meant to run through
asyncio.to_thread. They never raise: a failure comes back as
{package, error, cached: False}. Results are cached per device in the
"manifests" / "scans" snapshots, keyed by APK path + size so a reinstall
invalidates them.
"""
from __future__ import annotations

import hashlib
import io
import logging
import os
import re
import shlex
import struct
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from typing import Any, Callable

from . import signatures
from .labels import RemoteZip, _adb_range_reader

log = logging.getLogger("sentinel.manifest")

_NS = "{http://schemas.android.com/apk/res/android}"
_PKG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.]{1,254}\Z")
# where `pm path` may legitimately point (incl. adoptable storage, /mnt/expand/<uuid>/app);
# anything else never reaches a shell
_APK_PATH_RE = re.compile(r"^/(data/app|data/app-private|mnt/expand/[0-9a-fA-F-]+/app"
                          r"|system|product|system_ext|vendor|apex|odm|oem)/.*\.apk\Z")
_DEX_RE = re.compile(r"^classes(\d*)\.dex$")
_SO_RE = re.compile(r"^lib/([^/]+)/([^/]+\.so)$")
_SIGFILE_RE = re.compile(r"^META-INF/[^/]+\.(RSA|DSA|EC|SF|MF)$", re.I)
_CERTFILE_RE = re.compile(r"^META-INF/[^/]+\.(RSA|DSA|EC)$", re.I)
_LAUNCH_MODES = {"0": "standard", "1": "singleTop", "2": "singleTask",
                 "3": "singleInstance", "4": "singleInstancePerTask"}
_PROT_BASE = {0: "normal", 1: "dangerous", 2: "signature", 3: "signatureOrSystem", 4: "internal"}
_PROT_FLAGS = ((0x10, "privileged"), (0x20, "development"), (0x40, "appop"), (0x80, "pre23"),
               (0x100, "installer"), (0x200, "verifier"), (0x400, "preinstalled"),
               (0x800, "setup"), (0x1000, "instant"), (0x2000, "runtime"), (0x4000, "oem"),
               (0x8000, "vendorPrivileged"), (0x10000, "systemTextClassifier"),
               (0x20000, "wellbeing"), (0x40000, "documenter"), (0x80000, "configurator"),
               (0x100000, "incidentReportApprover"), (0x200000, "appPredictor"),
               (0x400000, "module"), (0x800000, "companion"), (0x1000000, "retailDemo"),
               (0x2000000, "recents"), (0x4000000, "role"), (0x8000000, "knownSigner"))

# APK Signing Block (https://source.android.com/docs/security/features/apksigning/v2)
_SIG_MAGIC = b"APK Sig Block 42"
_SIG_SCHEMES = {0x7109871A: "v2", 0xF05368C0: "v3", 0x1B93AD61: "v3.1"}
_SCHEME_ORDER = {"v1": 0, "v2": 1, "v3": 2, "v3.1": 3}
_MAX_SIG_BLOCK = 4 * 1024 * 1024

_MAX_DEX_FILES = 32
_MAX_DEX_BYTES = 40 * 1024 * 1024

# Runtime ("dangerous") permissions the user grants at run time; short names
# of android.permission.* plus the odd fully-qualified one.
DANGEROUS_PERMISSIONS = frozenset({
    "READ_CALENDAR", "WRITE_CALENDAR", "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS",
    "CAMERA", "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS", "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "ACCESS_MEDIA_LOCATION", "RECORD_AUDIO",
    "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE", "ANSWER_PHONE_CALLS", "ADD_VOICEMAIL",
    "USE_SIP", "ACCEPT_HANDOVER", "BODY_SENSORS", "BODY_SENSORS_BACKGROUND", "ACTIVITY_RECOGNITION",
    "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECEIVE_WAP_PUSH", "RECEIVE_MMS", "READ_CELL_BROADCASTS",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO",
    "READ_MEDIA_AUDIO", "READ_MEDIA_VISUAL_USER_SELECTED", "BLUETOOTH_SCAN", "BLUETOOTH_CONNECT",
    "BLUETOOTH_ADVERTISE", "NEARBY_WIFI_DEVICES", "POST_NOTIFICATIONS", "UWB_RANGING",
    "com.android.voicemail.permission.ADD_VOICEMAIL",
})


def is_dangerous(perm: str) -> bool:
    if not perm:
        return False
    if perm in DANGEROUS_PERMISSIONS:
        return True
    return perm.startswith("android.permission.") and perm.rsplit(".", 1)[-1] in DANGEROUS_PERMISSIONS


# ---------------- zip + cache plumbing ----------------
class _ApkZip(RemoteZip):
    """RemoteZip that also knows where the central directory starts; the APK
    Signing Block sits immediately before it."""

    cd_off: int = 0

    def _load_cd(self) -> None:
        tail_len = min(self.size, 65557)
        tail = self.read(self.size - tail_len, tail_len)
        idx = tail.rfind(struct.pack("<I", 0x06054B50))
        if idx < 0:
            raise ValueError("no zip end-of-central-directory")
        self.cd_off = struct.unpack("<I", tail[idx + 16:idx + 20])[0]
        super()._load_cd()


def _vpkg(pkg: str) -> str:
    if not _PKG.match(pkg or ""):
        raise ValueError("invalid package name")
    return pkg


def _locate(dctx, pkg: str) -> tuple[str, list[str], int, Callable[[int, int], bytes]]:
    """(base apk path, all apk paths, size, range reader) for an installed
    package. The zip itself is opened only after the cache check, so a hit
    costs two adb calls and no reads."""
    paths = [p for p in dctx.adb.apk_paths(pkg) if p]
    if not paths:
        raise ValueError("no APK path (not installed for this user?)")
    apk_path = paths[0]
    for p in paths:
        if not _APK_PATH_RE.match(p):
            raise ValueError("unexpected APK path: " + p[:80])
    size, rr = _adb_range_reader(dctx.adb, apk_path)
    if size <= 0:
        raise ValueError("APK is empty or unreadable")
    return apk_path, paths, size, rr


def _cache_get(dctx, snap: str, pkg: str, key: str) -> dict | None:
    cache = dctx.store.get_snapshot(snap) or {}
    ent = cache.get(pkg)
    if isinstance(ent, dict) and ent.get("_key") == key:
        out = dict(ent)
        out.pop("_key", None)
        out["cached"] = True
        return out
    return None


def _cache_put(dctx, snap: str, pkg: str, key: str, result: dict) -> None:
    cache = dctx.store.get_snapshot(snap) or {}
    ent = dict(result)
    ent.pop("cached", None)
    ent["_key"] = key
    cache[pkg] = ent
    dctx.store.put_snapshot(snap, cache)


def cached_manifest(dctx, pkg: str) -> dict | None:
    """The stored inspect_apk() result, without touching the device."""
    ent = (dctx.store.get_snapshot("manifests") or {}).get(pkg)
    return dict(ent, cached=True) if isinstance(ent, dict) else None


def cached_scan(dctx, pkg: str) -> dict | None:
    """The stored scan_app() result, without touching the device."""
    ent = (dctx.store.get_snapshot("scans") or {}).get(pkg)
    return dict(ent, cached=True) if isinstance(ent, dict) else None


def component_kinds(manifest: dict | None) -> dict[str, str]:
    """{full class name: "activity"|"service"|"receiver"|"provider"} from an
    inspect_apk() result (IFW rules need the component type)."""
    out: dict[str, str] = {}
    for kind, key in (("activity", "activities"), ("service", "services"),
                      ("receiver", "receivers"), ("provider", "providers")):
        for c in (manifest or {}).get(key) or []:
            if c.get("name"):
                out[c["name"]] = kind
    return out


# ---------------- manifest ----------------
def _bool(v: str | None, default: bool | None = None) -> bool | None:
    if v is None:
        return default
    s = str(v).strip().lower()
    if s == "true":
        return True
    if s == "false":
        return False
    return default


def _int(v: Any, default: int | None = None) -> int | None:
    if v is None or v == "":
        return default
    try:
        return int(str(v).strip(), 0)
    except ValueError:
        return default


def _resolve_name(name: str | None, pkg: str) -> str | None:
    """'.Foo' and 'Foo' are relative to the package; '@0x..' refs are junk."""
    if not name or name.startswith("@"):
        return None
    if name.startswith("."):
        return pkg + name
    if "." not in name:
        return pkg + "." + name
    return name


def _exported(raw: str | None, has_filters: bool, target_sdk: int, kind: str) -> bool | None:
    explicit = _bool(raw)
    if explicit is not None:
        return explicit
    if kind == "provider":
        return target_sdk < 17
    if not has_filters:
        return False
    # implicit export via intent-filter; targetSdk 31+ rejects the omission
    return True if target_sdk < 31 else None


def _intent_filter(f) -> dict:
    actions = [a.get(_NS + "name") for a in f.findall("action") if a.get(_NS + "name")]
    cats = [c.get(_NS + "name") for c in f.findall("category") if c.get(_NS + "name")]
    data = []
    for d in f.findall("data"):
        host, port = d.get(_NS + "host"), d.get(_NS + "port")
        data.append({
            "scheme": d.get(_NS + "scheme"),
            "host": f"{host}:{port}" if host and port else host,
            "path": (d.get(_NS + "path") or d.get(_NS + "pathPrefix")
                     or d.get(_NS + "pathPattern") or d.get(_NS + "pathAdvancedPattern")),
            "mime": d.get(_NS + "mimeType"),
        })
    return {"actions": actions, "categories": cats, "data": data}


def _component(el, pkg: str, target_sdk: int, kind: str) -> dict | None:
    name = _resolve_name(el.get(_NS + "name"), pkg)
    if not name:
        return None
    filters = [_intent_filter(f) for f in el.findall("intent-filter")]
    out: dict[str, Any] = {
        "name": name,
        "exported": _exported(el.get(_NS + "exported"), bool(filters), target_sdk, kind),
        "permission": el.get(_NS + "permission"),
        "enabled": _bool(el.get(_NS + "enabled")),
        "process": el.get(_NS + "process"),
        "tracker": signatures.tracker_for_class(name),
    }
    if kind == "provider":
        auth = el.get(_NS + "authorities") or ""
        out["authorities"] = [a for a in auth.split(";") if a]
        out["grant_uri_permissions"] = _bool(el.get(_NS + "grantUriPermissions"), False)
    else:
        lm = el.get(_NS + "launchMode")
        out["launch_mode"] = _LAUNCH_MODES.get(str(lm), lm) if kind == "activity" else None
        out["intent_filters"] = filters
    if el.tag == "activity-alias":
        out["alias"] = True
        out["target_activity"] = _resolve_name(el.get(_NS + "targetActivity"), pkg)
    return out


def _protection_level(raw: str | None) -> str | None:
    n = _int(raw)
    if n is None:
        return raw
    parts = [_PROT_BASE.get(n & 0xF, str(n & 0xF))]
    parts += [name for bit, name in _PROT_FLAGS if n & bit]
    return "|".join(parts)


_MAIN_ACTION = "android.intent.action.MAIN"
_LAUNCHER_CATS = ("android.intent.category.LAUNCHER",
                  "android.intent.category.LEANBACK_LAUNCHER")   # TV-only apps


def _find_main(activities: list[dict]) -> str | None:
    """First enabled activity (or alias) in manifest order with a filter
    carrying both MAIN and LAUNCHER, else MAIN and LEANBACK_LAUNCHER. Done
    here rather than via pyaxmlparser, whose set.pop() is hash-seed random
    when an app has several launcher entries."""
    for cat in _LAUNCHER_CATS:
        for a in activities:
            if a.get("enabled") is False:
                continue
            for f in a.get("intent_filters") or []:
                if _MAIN_ACTION in f["actions"] and cat in f["categories"]:
                    return a["name"]
    return None


def parse_manifest(root, pkg: str, apk=None) -> dict:
    """Everything the UI shows from a decoded manifest (lxml root). `apk` is
    the pyaxmlparser APK, used only for the version/sdk accessors."""
    app = root.find("application")
    if app is None:
        raise ValueError("manifest has no <application>")
    sdk = root.find("uses-sdk")
    min_sdk = _int(apk.get_min_sdk_version() if apk else None) or \
        _int(sdk.get(_NS + "minSdkVersion") if sdk is not None else None) or 1
    target_sdk = _int(apk.get_target_sdk_version() if apk else None) or \
        _int(sdk.get(_NS + "targetSdkVersion") if sdk is not None else None) or min_sdk
    max_sdk = _int(apk.get_max_sdk_version() if apk else None) or \
        _int(sdk.get(_NS + "maxSdkVersion") if sdk is not None else None)

    comps: dict[str, list[dict]] = {"activities": [], "services": [], "receivers": [], "providers": []}
    for tag, kind, key in (("activity", "activity", "activities"),
                           ("activity-alias", "activity", "activities"),
                           ("service", "service", "services"),
                           ("receiver", "receiver", "receivers"),
                           ("provider", "provider", "providers")):
        for el in app.findall(tag):
            c = _component(el, pkg, target_sdk, kind)
            if c:
                comps[key].append(c)

    uses_perms = []
    for el in list(root.findall("uses-permission")) + list(root.findall("uses-permission-sdk-23")):
        name = el.get(_NS + "name")
        if name:
            uses_perms.append({"name": name, "max_sdk": _int(el.get(_NS + "maxSdkVersion")),
                               "dangerous": is_dangerous(name)})
    declared = [{"name": el.get(_NS + "name"),
                 "protection_level": _protection_level(el.get(_NS + "protectionLevel"))}
                for el in root.findall("permission") if el.get(_NS + "name")]
    features = []
    for el in root.findall("uses-feature"):
        name = el.get(_NS + "name")
        gl = el.get(_NS + "glEsVersion")
        if not name and gl:
            name = "android.hardware.opengles.version=" + str(gl)
        if name:
            features.append({"name": name, "required": _bool(el.get(_NS + "required"), True)})
    libs = [{"name": el.get(_NS + "name"), "required": _bool(el.get(_NS + "required"), True)}
            for tag in ("uses-library", "uses-native-library")
            for el in app.findall(tag) if el.get(_NS + "name")]
    meta: dict[str, str] = {}
    for md in app.findall("meta-data"):
        name = md.get(_NS + "name")
        val = md.get(_NS + "value")
        if val is None:
            val = md.get(_NS + "resource")
        if name and val is not None:
            meta[name] = str(val)

    return {
        "package": root.get("package") or pkg,
        "version_name": apk.get_androidversion_name() if apk else root.get(_NS + "versionName"),
        "version_code": _int(apk.get_androidversion_code() if apk else root.get(_NS + "versionCode")),
        "min_sdk": min_sdk, "target_sdk": target_sdk, "max_sdk": max_sdk,
        "main_activity": _find_main(comps["activities"]),
        "debuggable": _bool(app.get(_NS + "debuggable"), False),
        "allow_backup": _bool(app.get(_NS + "allowBackup"), True),
        "test_only": _bool(app.get(_NS + "testOnly"), False),
        "uses_cleartext_traffic": _bool(app.get(_NS + "usesCleartextTraffic"), target_sdk < 28),
        "large_heap": _bool(app.get(_NS + "largeHeap"), False),
        "application_class": _resolve_name(app.get(_NS + "name"), pkg),
        **comps,
        "uses_permissions": uses_perms,
        "declared_permissions": declared,
        "features": features,
        "libraries": libs,
        "meta_data": meta,
    }


# ---------------- signatures ----------------
def _cert_info(der: bytes, scheme: str) -> dict:
    from cryptography import x509
    cert = x509.load_der_x509_certificate(der)
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    oid = cert.signature_algorithm_oid
    alg = getattr(oid, "_name", None)
    if not alg or alg == "Unknown OID":     # cryptography's placeholder for unnamed OIDs
        alg = oid.dotted_string
    return {
        "scheme": scheme,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "x"),
        "not_before": nb.isoformat(),
        "not_after": na.isoformat(),
        "sha256": hashlib.sha256(der).hexdigest(),
        "sha1": hashlib.sha1(der).hexdigest(),
        "md5": hashlib.md5(der).hexdigest(),
        "algorithm": alg,
    }


def _signer_cert(certs: list) -> Any:
    """The leaf of a PKCS#7 certificate set: the one that issued no other
    cert in it (the SET is DER-sorted, so for a chain certs[0] is usually
    the CA). Falls back to the first."""
    for c in certs:
        if not any(o is not c and o.issuer == c.subject for o in certs):
            return c
    return certs[0]


def _v1_certs(rz: RemoteZip) -> list[bytes]:
    """DER of the signer certificate in each META-INF/*.RSA|DSA|EC PKCS#7."""
    from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
    out = []
    for name in sorted(rz.entries):
        if not _CERTFILE_RE.match(name):
            continue
        try:
            certs = pkcs7.load_der_pkcs7_certificates(rz.extract(name))
        except Exception as e:  # noqa: BLE001 - odd/legacy PKCS#7 just means no v1 cert
            log.debug("v1 cert %s: %s", name, e)
            continue
        if certs:
            out.append(_signer_cert(certs).public_bytes(Encoding.DER))
    return out


def _signing_block(rz: _ApkZip) -> bytes | None:
    """The whole APK Signing Block (size prefix .. magic), or None."""
    if rz.cd_off < 32:
        return None
    head = rz.read(rz.cd_off - 24, 24)
    if len(head) != 24 or head[8:] != _SIG_MAGIC:
        return None
    size = struct.unpack("<Q", head[:8])[0]
    start = rz.cd_off - size - 8
    if size < 24 or size > _MAX_SIG_BLOCK or start < 0:
        return None
    blk = rz.read(start, size + 8)
    return blk if len(blk) == size + 8 else None


def _u32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


def _block_pairs(block: bytes) -> list[tuple[int, bytes]]:
    """(id, value) pairs of a signing block: uint64 len, uint32 id, value."""
    size = struct.unpack_from("<Q", block, 0)[0]
    pos, end, pairs = 8, 8 + size - 24, []
    while pos + 12 <= end:
        ln = struct.unpack_from("<Q", block, pos)[0]
        if ln < 4 or pos + 8 + ln > end:
            break
        pairs.append((_u32(block, pos + 8), block[pos + 12:pos + 8 + ln]))
        pos += 8 + ln
    return pairs


def _signer_certs(value: bytes) -> list[bytes]:
    """First certificate (DER) of every signer in a v2/v3/v3.1 block value:
    signers -> signer -> signed data -> [digests] [certificates]. v3 adds
    sdk fields after the certificates, so the walk is the same."""
    out: list[bytes] = []
    try:
        pos, end = 4, 4 + _u32(value, 0)
        while pos + 4 <= end:
            slen = _u32(value, pos)
            signer = value[pos + 4:pos + 4 + slen]
            pos += 4 + slen
            sd = signer[4:4 + _u32(signer, 0)]
            cp = 4 + _u32(sd, 0)               # skip digests
            certs_len = _u32(sd, cp)
            cp += 4
            if certs_len >= 4:
                cl = _u32(sd, cp)
                der = sd[cp + 4:cp + 4 + cl]
                if len(der) == cl:
                    out.append(der)
    except struct.error:
        pass
    return out


def apk_signatures(rz: _ApkZip) -> list[dict]:
    """Certificates across v1 (PKCS#7) and v2/v3/v3.1 (signing block),
    deduplicated by sha256 with the schemes joined ("v1+v2+v3")."""
    found: list[tuple[str, bytes]] = [("v1", der) for der in _v1_certs(rz)]
    try:
        blk = _signing_block(rz)
        for iid, val in (_block_pairs(blk) if blk else []):
            scheme = _SIG_SCHEMES.get(iid)
            if scheme:
                found += [(scheme, der) for der in _signer_certs(val)]
    except Exception as e:  # noqa: BLE001 - a mangled block is not fatal
        log.debug("signing block: %s", e)
    by_hash: dict[str, dict] = {}
    schemes: dict[str, set[str]] = {}
    for scheme, der in found:
        h = hashlib.sha256(der).hexdigest()
        if h not in by_hash:
            try:
                by_hash[h] = _cert_info(der, scheme)
            except Exception as e:  # noqa: BLE001
                log.debug("cert parse (%s): %s", scheme, e)
                continue
        schemes.setdefault(h, set()).add(scheme)
    out = []
    for h, info in by_hash.items():
        info["scheme"] = "+".join(sorted(schemes[h], key=lambda s: _SCHEME_ORDER.get(s, 9)))
        out.append(info)
    return out


# ---------------- entries: dex, native libs, splits ----------------
def _dex_entries(rz: RemoteZip) -> list[str]:
    names = [n for n in rz.entries if _DEX_RE.match(n)]
    return sorted(names, key=lambda n: int(_DEX_RE.match(n).group(1) or "1"))


def _native_libs(rz: RemoteZip) -> list[dict]:
    by_abi: dict[str, list[str]] = {}
    for n in rz.entries:
        m = _SO_RE.match(n)
        if m:
            by_abi.setdefault(m.group(1), []).append(m.group(2))
    return [{"abi": abi, "files": sorted(files)} for abi, files in sorted(by_abi.items())]


def _split_sizes(dctx, paths: list[str]) -> list[dict]:
    """[{path, size}] for the split APKs (every path but the base); one
    quoted `stat` call."""
    if not paths:
        return []
    q = " ".join(shlex.quote(p) for p in paths)
    try:
        lines = dctx.adb.shell_sync(f"stat -c %s {q}", timeout=20).splitlines()
    except Exception as e:  # noqa: BLE001
        log.debug("split sizes: %s", e)
        lines = []
    return [{"path": p, "size": _int(lines[i].strip() if i < len(lines) else None)}
            for i, p in enumerate(paths)]


# ---------------- inspect ----------------
def inspect_apk(dctx, pkg: str, refresh: bool = False) -> dict:
    """Manifest + signatures + file layout of an installed package's base
    APK. Cached in the "manifests" snapshot; never raises."""
    try:
        _vpkg(pkg)
        apk_path, paths, size, rr = _locate(dctx, pkg)
    except Exception as e:  # noqa: BLE001 - adb/validation errors become a result
        return {"package": pkg, "error": str(e) or e.__class__.__name__, "cached": False}
    key = f"{apk_path}:{size}"
    if not refresh:
        hit = _cache_get(dctx, "manifests", pkg, key)
        if hit:
            return hit
    try:
        result = _inspect(_ApkZip(size, rr), pkg)
        result.update({
            "splits": _split_sizes(dctx, paths[1:]),
            "apk_path": apk_path, "apk_size": size, "cached": False,
        })
    except Exception as e:  # noqa: BLE001
        log.debug("inspect %s: %s", pkg, e)
        return {"package": pkg, "apk_path": apk_path, "apk_size": size,
                "error": str(e) or e.__class__.__name__, "cached": False}
    _cache_put(dctx, "manifests", pkg, key, result)
    return result


def _inspect(rz: _ApkZip, pkg: str) -> dict:
    from lxml import etree
    from pyaxmlparser import APK  # type: ignore

    if "AndroidManifest.xml" not in rz.entries:
        raise ValueError("no AndroidManifest.xml in APK")
    # pyaxmlparser wants a file: hand it a tiny zip of just the parts it reads
    wanted = ["AndroidManifest.xml"] + [n for n in ("resources.arsc",) if n in rz.entries] \
        + [n for n in sorted(rz.entries) if _SIGFILE_RE.match(n)]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for w in wanted:
            zf.writestr(w, rz.extract(w))
    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tf:
        tf.write(buf.getvalue())
        tmp = tf.name
    try:
        apk = APK(tmp)
        root = apk.get_android_manifest_xml()
        result = parse_manifest(root, pkg, apk)
        result["manifest_xml"] = etree.tostring(root, pretty_print=True, encoding="unicode")
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    dex = _dex_entries(rz)
    result.update({
        "multidex": len(dex) > 1,
        "native_libs": _native_libs(rz),
        "dex_files": dex,
        "signatures": apk_signatures(rz),
    })
    return result


# ---------------- dex scan ----------------
def dex_class_names(dex: bytes) -> list[str]:
    """Dotted names of every class type in a dex file's type table
    ("Lcom/foo/Bar$1;" -> "com.foo.Bar$1"). Only the header, type_ids and
    string_ids tables are walked."""
    if len(dex) < 0x70 or dex[:4] != b"dex\n":
        raise ValueError("not a dex file")
    ssz, soff, tsz, toff = struct.unpack_from("<IIII", dex, 0x38)
    n = len(dex)
    # a table outside the file is a corrupt or short dex; say so instead of
    # returning a clean-looking empty list
    if soff + 4 * ssz > n or toff + 4 * tsz > n:
        raise ValueError("dex tables outside file")
    out: list[str] = []
    for i in range(tsz):
        sidx = struct.unpack_from("<I", dex, toff + 4 * i)[0]
        if sidx >= ssz:
            continue
        pos = struct.unpack_from("<I", dex, soff + 4 * sidx)[0]
        if pos >= n:
            continue
        # uleb128 utf16 length, then MUTF-8 bytes up to NUL
        while pos < n and dex[pos] & 0x80:
            pos += 1
        pos += 1
        end = dex.find(b"\0", pos)
        if end < 0:
            continue
        s = dex[pos:end]
        if s[:1] == b"L" and s[-1:] == b";":
            out.append(s[1:-1].decode("utf-8", "replace").replace("/", "."))
    return out


def scan_app(dctx, pkg: str, refresh: bool = False) -> dict:
    """Trackers and libraries found in the package's dex code, with the
    manifest components that belong to each tracker. Cached in the "scans"
    snapshot; never raises."""
    try:
        _vpkg(pkg)
        apk_path, _paths, size, rr = _locate(dctx, pkg)
    except Exception as e:  # noqa: BLE001
        return {"package": pkg, "error": str(e) or e.__class__.__name__, "cached": False}
    key = f"{apk_path}:{size}"
    if not refresh:
        hit = _cache_get(dctx, "scans", pkg, key)
        if hit:
            return hit
    try:
        result = _scan(_ApkZip(size, rr))
    except Exception as e:  # noqa: BLE001
        log.debug("scan %s: %s", pkg, e)
        return {"package": pkg, "apk_path": apk_path, "apk_size": size,
                "error": str(e) or e.__class__.__name__, "cached": False}
    # components come from the (cached) manifest; a manifest failure is not a scan failure
    man = inspect_apk(dctx, pkg)
    comps: dict[str, list[str]] = {}
    for key_ in ("activities", "services", "receivers", "providers"):
        for c in man.get(key_) or []:
            if c.get("tracker"):
                comps.setdefault(c["tracker"], []).append(c["name"])
    for name, names in comps.items():
        rec = result["_trackers"].setdefault(name, {"signatures_matched": set(), "classes": 0})
        rec["components"] = sorted(set(names))
    trackers = []
    for name, rec in result.pop("_trackers").items():
        t = signatures.TRACKER_BY_NAME.get(name) or {}
        trackers.append({"name": name, "category": t.get("category"), "website": t.get("website"),
                         "signatures_matched": sorted(rec["signatures_matched"]),
                         "classes": rec["classes"], "components": rec.get("components", [])})
    trackers.sort(key=lambda t: (-t["classes"], t["name"]))
    ts = time.time()
    result.update({"package": pkg, "trackers": trackers, "apk_path": apk_path, "apk_size": size,
                   "scanned_at": datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds"),
                   "scanned_ts": ts, "cached": False})
    _cache_put(dctx, "scans", pkg, key, result)
    return result


def _scan(rz: _ApkZip) -> dict:
    """Walk every classes*.dex (one at a time, with size caps) and match the
    class table against the signature tables."""
    names: set[str] = set()
    dex_names = _dex_entries(rz)
    truncated = len(dex_names) > _MAX_DEX_FILES
    scanned = 0
    for n in dex_names[:_MAX_DEX_FILES]:
        _m, _c, usize, _o = rz.entries[n]
        if usize > _MAX_DEX_BYTES:
            truncated = True
            continue
        data = rz.extract(n)
        try:
            names.update(dex_class_names(data))
        except ValueError as e:
            # a corrupt dex makes the whole scan untrustworthy: surface it
            # as the scan's error rather than a clean 0-class result
            raise ValueError(f"{n}: {e}") from None
        del data
        scanned += 1
    libs = signatures.match_prefixes(names, signatures.LIBRARIES)
    libraries = [{"name": name, "website": (signatures.LIBRARY_BY_NAME.get(name) or {}).get("website"),
                  "classes": rec["classes"]} for name, rec in libs.items()]
    libraries.sort(key=lambda lib: (-lib["classes"], lib["name"]))
    return {
        "_trackers": signatures.match_prefixes(names, signatures.TRACKERS),
        "libraries": libraries,
        "native_libs": _native_libs(rz),
        "dex_files": scanned,
        "classes_scanned": len(names),
        "truncated": truncated,
    }
