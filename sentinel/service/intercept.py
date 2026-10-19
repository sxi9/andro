"""HTTPS interception setup, step 1: device trust store + proxy wiring.

Authorized own-device tooling. This installs the operator's *own* proxy CA
(Burp / mitmproxy) into the trust store of a device they own so non-pinning
apps trust the proxy, and points the device (globally) or one app (a per-uid
nat redirect) at that proxy, so the HTTPS traffic of an app they are allowed
to test can be inspected. See ``docs/SSL-INTERCEPTION-MODULE.md`` (Part A).

Every device-changing call runs over the owner's own ``su``/adb plane, emits
an ``intercept.action`` audit event, and is gated behind ``confirm=true`` at
the route. Every device-/request-derived string that reaches a shell is first
checked against a strict ``\\Z``-anchored pattern (never a bare ``$``, which
would also match before a trailing newline) and then ``shlex.quote``-d; the
fixed trust-store paths are module constants, never built from input.
"""
from __future__ import annotations

import hashlib
import os
import re
import shlex
import tempfile
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ..adb.client import AdbError
from ..core.events import Event, SEV_NOTICE, SEV_WARN
from .appdata import package_uid

# Trust-store locations. On Android 14 (SDK 34+) the live store is served from
# the Conscrypt APEX; the legacy /system path is overlaid too for apps that
# still read it. These are constants, never interpolated from caller input.
APEX_CACERTS = "/apex/com.android.conscrypt/cacerts"
SYS_CACERTS = "/system/etc/security/cacerts"
SELINUX_CTX = "u:object_r:system_security_cacerts_file:s0"
_CHAIN = "SENTINEL_PROXY"  # the per-app nat chain we own and tear down on revert

# \Z, not $: a bare $ also matches just before a trailing newline, which the
# device shell would treat as a second command.
_PKG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.]{1,254}\Z")
# IPv4 or hostname for the proxy endpoint (the ':' of an IPv6 literal is out).
_HOST = re.compile(r"^[A-Za-z0-9_.-]{1,255}\Z")
# an OpenSSL subject-hash cert filename (8 hex + .0); guards the revert path
# that builds `rm <store>/<hash>` from a stored value
_HASH_NAME = re.compile(r"[0-9a-f]{8}\.0")


class _Refused(AdbError):
    """Input refused before anything reached the device (no event is logged)."""


# ---------------- validation ----------------

def _vhost(host) -> str:
    if not isinstance(host, str) or not _HOST.match(host):
        raise _Refused("invalid proxy host (IPv4 or hostname)")
    return host


def _vport(port) -> int:
    try:
        p = int(port)
    except (TypeError, ValueError):
        raise _Refused("invalid proxy port") from None
    if not 1 <= p <= 65535:
        raise _Refused("proxy port out of range (1-65535)")
    return p


def _vpkg(pkg) -> str:
    if not isinstance(pkg, str) or not _PKG.match(pkg):
        raise _Refused("invalid package name")
    return pkg


# ---------------- device / store helpers ----------------

def _sdk(dctx) -> int | None:
    """API level from device_info() (`ro.build.version.sdk`, stored as a str)."""
    dev = getattr(dctx, "device", None)
    if not isinstance(dev, dict):
        dev = (getattr(dctx, "state", None) or {}).get("device") or {}
    try:
        return int(dev.get("sdk") or 0) or None
    except (TypeError, ValueError):
        return None


def _int_or_none(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _store_for(sdk: int | None) -> str:
    # SDK 34 (Android 14) moved the trust store into the Conscrypt APEX.
    return "apex" if (sdk or 0) >= 34 else "system"


def _snapshot(dctx, name: str) -> dict:
    store = getattr(dctx, "store", None)
    try:
        snap = store.get_snapshot(name) if store is not None else None
    except Exception:  # noqa: BLE001 - a broken store never breaks status
        snap = None
    return snap if isinstance(snap, dict) else {}


def _put_snapshot(dctx, name: str, data) -> None:
    store = getattr(dctx, "store", None)
    if store is None:
        return
    try:
        store.put_snapshot(name, data)
    except Exception:  # noqa: BLE001 - persisting state never fails the action
        pass


def _emit(dctx, *, action: str, ok: bool, what: str, detail: str, **extra) -> None:
    """Audit every executed active call (NOTICE on success, WARN on failure)."""
    emit = getattr(dctx, "emit_threadsafe", None)
    if not callable(emit):
        return
    data = {"action": action, "ok": bool(ok)}
    for k in ("host", "port", "package", "store", "output"):
        if extra.get(k) is not None:
            data[k] = str(extra[k])[:400] if k == "output" else extra[k]
    try:
        emit(Event(kind="intercept.action", severity=SEV_NOTICE if ok else SEV_WARN,
                   title=f"{what}: {detail}", detail=str(detail)[:200], data=data))
    except Exception:  # noqa: BLE001 - logging never fails the action
        pass


# ---------------- CA inspection (pure, host-side, no adb) ----------------

def _subject_hash_old(cert: x509.Certificate) -> str:
    """The legacy OpenSSL subject hash, as the trust store filename `<hash>.0`.

    Mirrors ``openssl x509 -subject_hash_old``: the first 4 bytes, little-endian,
    of MD5 over the certificate's (canonicalized) subject DER - computed here,
    not by shelling out to openssl.
    """
    der = cert.subject.public_bytes()
    digest = hashlib.md5(der).digest()  # noqa: S324 - the openssl algorithm, not security
    val = int.from_bytes(digest[:4], "little")
    return f"{val:08x}.0"


def inspect_ca(pem_bytes) -> dict:
    """Parse a proxy CA PEM and report its identity. Pure: touches no device.

    Raises ValueError on anything that is not an X.509 certificate so the route
    can answer 400.
    """
    if isinstance(pem_bytes, str):
        pem_bytes = pem_bytes.encode()
    try:
        cert = x509.load_pem_x509_certificate(pem_bytes)
    except Exception as e:  # noqa: BLE001 - any parse error is a bad cert -> 400
        raise ValueError(f"not a PEM X.509 certificate: {e}") from None
    der = cert.public_bytes(serialization.Encoding.DER)
    # prefer the tz-aware *_utc accessors; fall back for older cryptography
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    try:
        is_ca = bool(cert.extensions.get_extension_for_class(
            x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        is_ca = False
    # ok:true is part of the HTTP /ca/inspect contract, so the route can return
    # this dict straight through; a bad cert raises above and becomes a 400.
    return {
        "ok": True,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "sha256": hashlib.sha256(der).hexdigest(),
        "sha1": hashlib.sha1(der).hexdigest(),  # noqa: S324 - fingerprint, not security
        "hash_name": _subject_hash_old(cert),
        "not_before": nb.isoformat(),
        "not_after": na.isoformat(),
        "is_ca": is_ca,
    }


# ---------------- CA status / install / revert ----------------

def _empty_ca() -> dict:
    return {"installed": False, "subject": None, "sha256": None,
            "hash_name": None, "store": None, "not_after": None}


def ca_status(dctx) -> dict:
    """The ca{} status block: what we recorded installing, and whether the
    hashed file is still present in the active trust dir. Read-only."""
    snap = _snapshot(dctx, "intercept_ca")
    if not snap:
        return _empty_ca()
    store = snap.get("store")
    hash_name = snap.get("hash_name")
    block = {"installed": False, "subject": snap.get("subject"),
             "sha256": snap.get("sha256"), "hash_name": hash_name,
             "store": store, "not_after": snap.get("not_after")}
    active = APEX_CACERTS if store == "apex" else SYS_CACERTS
    adb = getattr(dctx, "adb", None)
    if hash_name and adb is not None:
        try:
            out = adb.shell_sync(f"ls {shlex.quote(active + '/' + hash_name)}",
                                 su=True, timeout=15)
            block["installed"] = hash_name in out and "No such" not in out
        except AdbError:
            block["installed"] = False  # unreadable -> treat as not installed
    return block


def _apex_install_script(pushed: str, hash_name: str, tmp_dir: str) -> str:
    """SDK 34+: overlay the APEX (and legacy) trust store with our CA added.

    NOTE: this overlays the store in the *global* mount namespace. Apps already
    running in their own mount namespace on Android 14 keep the old view until
    they restart / the device reboots (or a Magisk cert module injects into
    each zygote namespace). v1 does not iterate zygote namespaces.
    """
    q_pem, q_hash, q_tmp = shlex.quote(pushed), shlex.quote(hash_name), shlex.quote(tmp_dir)
    cert_tmp = f"{q_tmp}/{q_hash}"  # both tokens are shell-safe (no metachars)
    cert_sys = shlex.quote(f"{SYS_CACERTS}/{hash_name}")
    steps = [
        f"mkdir -p {q_tmp}",
        f"cp {APEX_CACERTS}/* {q_tmp}/ 2>/dev/null",   # seed with the apex certs
        f"cp {SYS_CACERTS}/* {q_tmp}/ 2>/dev/null",    # and the legacy system certs
        f"cp {q_pem} {cert_tmp}",                      # install our CA as <hash>.0
        f"chmod 644 {cert_tmp}",
        f"mount -t tmpfs tmpfs {SYS_CACERTS}",         # fresh tmpfs over the legacy path
        f"cp {q_tmp}/* {SYS_CACERTS}/ 2>/dev/null",    # repopulate it (incl. our CA)
        f"mount -o bind {q_tmp} {APEX_CACERTS}",       # bind our dir over the apex path
        f"chown 0:0 {SYS_CACERTS}/* {APEX_CACERTS}/*",
        f"chmod 644 {SYS_CACERTS}/* {APEX_CACERTS}/*",
        f"chcon {SELINUX_CTX} {SYS_CACERTS}/* {APEX_CACERTS}/*",
        f"rm -rf {q_pem}",                             # drop the staged PEM
        # success probe: the apex bind is what Android 14 apps actually read,
        # so confirm the cert landed there (and in the legacy path)
        f"ls {shlex.quote(f'{APEX_CACERTS}/{hash_name}')} {cert_sys}",
    ]
    return "; ".join(steps)


def _system_install_script(pushed: str, hash_name: str, tmp_dir: str) -> str:
    """SDK < 34: remount /system rw and drop the cert in; if it will not go rw,
    overlay a tmpfs bind that keeps the existing certs and adds ours."""
    q_pem, q_hash, q_tmp = shlex.quote(pushed), shlex.quote(hash_name), shlex.quote(tmp_dir)
    cert_sys = shlex.quote(f"{SYS_CACERTS}/{hash_name}")
    cert_tmp = f"{q_tmp}/{q_hash}"
    steps = [
        (f"if mount -o rw,remount {SYS_CACERTS} 2>/dev/null || "
         f"mount -o rw,remount /system 2>/dev/null || mount -o rw,remount / 2>/dev/null; then "
         f"cp {q_pem} {cert_sys}; "
         f"else mkdir -p {q_tmp}; cp {SYS_CACERTS}/* {q_tmp}/ 2>/dev/null; "
         f"cp {q_pem} {cert_tmp}; mount -o bind {q_tmp} {SYS_CACERTS}; fi"),
        f"chmod 644 {cert_sys}",
        f"chown 0:0 {cert_sys}",
        f"chcon {SELINUX_CTX} {cert_sys}",
        "mount -o ro,remount /system 2>/dev/null || mount -o ro,remount / 2>/dev/null || true",
        f"rm -rf {q_pem}",
        f"ls {cert_sys}",
    ]
    return "; ".join(steps)


def install_ca(dctx, pem_bytes) -> dict:
    """Install the operator's proxy CA into the trust store (version-aware).

    Returns {ok, output, ca:{...status...}}. The route gates this on confirm=true.
    """
    try:
        info = inspect_ca(pem_bytes)
    except ValueError as e:
        return {"ok": False, "output": str(e), "ca": _empty_ca()}
    adb = getattr(dctx, "adb", None)
    if adb is None:
        return {"ok": False, "output": "needs a real device (not demo mode)", "ca": _empty_ca()}

    if isinstance(pem_bytes, str):
        pem_bytes = pem_bytes.encode()
    store = _store_for(_sdk(dctx))
    hash_name = info["hash_name"]
    rand = uuid.uuid4().hex[:12]
    pushed = f"/data/local/tmp/sentinel-ca-{rand}.pem"
    tmp_dir = f"/data/local/tmp/sentinel-cacerts-{rand}"

    # stage the plain PEM via adb push (/data/local/tmp is the shell-writable area)
    fd, local = tempfile.mkstemp(prefix="sentinel-ca-", suffix=".pem")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem_bytes)
        pushed_ok = adb.push_file(local, pushed)
    finally:
        try:
            os.unlink(local)
        except OSError:
            pass
    if not pushed_ok:
        res = {"ok": False, "output": "adb push of the CA PEM failed", "ca": _empty_ca()}
        _emit(dctx, action="ca.install", ok=False, what="CA install",
              detail=info["subject"], store=store)
        return res

    script = (_apex_install_script if store == "apex" else _system_install_script)(
        pushed, hash_name, tmp_dir)
    try:
        out = adb.shell_sync(script, su=True, timeout=90).strip()
        # the trailing `ls` prints the installed path iff the overlay took hold
        ok = hash_name in out and "No such" not in out and "Permission denied" not in out
    except AdbError as e:
        out, ok = str(e), False

    ca = _empty_ca()
    if ok:
        snap = {"subject": info["subject"], "sha256": info["sha256"],
                "hash_name": hash_name, "store": store, "not_after": info["not_after"]}
        _put_snapshot(dctx, "intercept_ca", snap)
        ca = {"installed": True, **snap}
    _emit(dctx, action="ca.install", ok=ok, what="CA install",
          detail=info["subject"], store=store, output=out)
    return {"ok": ok, "output": out or ("installed" if ok else "install failed"), "ca": ca}


def revert_ca(dctx) -> dict:
    """Undo the install: unmount the overlaid trust store, and for a pre-14
    install that wrote the cert into a writable /system, also remove that file
    (an unmount alone would leave it there)."""
    adb = getattr(dctx, "adb", None)
    if adb is None:
        return {"ok": False, "output": "needs a real device (not demo mode)"}
    snap = _snapshot(dctx, "intercept_ca") or {}
    hash_name = snap.get("hash_name")
    steps = [f"umount {shlex.quote(SYS_CACERTS)} 2>/dev/null",
             f"umount {shlex.quote(APEX_CACERTS)} 2>/dev/null"]
    if hash_name and _HASH_NAME.fullmatch(hash_name) and snap.get("store") != "apex":
        # the writable-/system path left a real file; remount rw, delete it, ro
        cert = shlex.quote(f"{SYS_CACERTS}/{hash_name}")
        steps += [
            "mount -o rw,remount /system 2>/dev/null || mount -o rw,remount / 2>/dev/null || true",
            f"rm -f {cert} 2>/dev/null",
            "mount -o ro,remount /system 2>/dev/null || mount -o ro,remount / 2>/dev/null || true",
            f"ls {cert} 2>/dev/null",   # prints nothing once the file is gone
        ]
    cmd = "; ".join(steps) + "; echo reverted"
    try:
        out = adb.shell_sync(cmd, su=True, timeout=30).strip()
        # if we removed a system file, the trailing ls must not still show it
        ok = not (hash_name and snap.get("store") != "apex" and hash_name in out)
    except AdbError as e:
        out, ok = str(e), False
    if ok:
        _put_snapshot(dctx, "intercept_ca", {})
    _emit(dctx, action="ca.revert", ok=ok, what="CA revert",
          detail="trust store restored", output=out)
    return {"ok": ok, "output": out or "reverted"}


# ---------------- proxy status / set ----------------

def _empty_proxy() -> dict:
    return {"mode": "off", "host": None, "port": None, "package": None, "uid": None}


def _proxy_from_snapshot(dctx) -> dict:
    snap = _snapshot(dctx, "intercept_proxy")
    if not snap:
        return _empty_proxy()
    return {"mode": snap.get("mode", "off"), "host": snap.get("host"),
            "port": snap.get("port"), "package": snap.get("package"),
            "uid": snap.get("uid")}


def proxy_status(dctx) -> dict:
    """The proxy{} block from our snapshot, refined by a cheap read-only
    `settings get global http_proxy` (never a mutation)."""
    block = _proxy_from_snapshot(dctx)
    adb = getattr(dctx, "adb", None)
    if adb is None:
        return block
    try:
        out = adb.shell_sync("settings get global http_proxy", timeout=15).strip()
    except AdbError:
        return block
    # a per-app redirect leaves the global setting cleared; don't overwrite it
    if block["mode"] == "per-app":
        return block
    if out and out not in ("null", ":0"):
        host, _, port = out.rpartition(":")
        if host and port.isdigit():
            block.update({"mode": "global", "host": host, "port": int(port)})
    elif out in ("null", ":0") and block["mode"] == "global":
        block["mode"] = "off"  # the setting was explicitly cleared -> reflect it
    return block


def _iptables_on_script(uid: int, host: str, port: int) -> str:
    """Build (and jump to) the SENTINEL_PROXY nat chain on both IP families:
    DNAT 443/80 for this uid to the proxy, scoped by -m owner --uid-owner."""
    dest = shlex.quote(f"{host}:{port}")
    lines: list[str] = []
    for ipt in ("iptables", "ip6tables"):
        lines += [
            f"{ipt} -t nat -N {_CHAIN} 2>/dev/null",  # create (ignore 'exists')
            f"{ipt} -t nat -F {_CHAIN}",              # start clean
            f"{ipt} -t nat -A {_CHAIN} -p tcp --dport 443 -j DNAT --to-destination {dest}",
            f"{ipt} -t nat -A {_CHAIN} -p tcp --dport 80 -j DNAT --to-destination {dest}",
            # delete-then-add the OUTPUT jump so re-running does not stack rules
            f"{ipt} -t nat -D OUTPUT -m owner --uid-owner {int(uid)} -j {_CHAIN} 2>/dev/null",
            f"{ipt} -t nat -A OUTPUT -m owner --uid-owner {int(uid)} -j {_CHAIN}",
        ]
    return "; ".join(lines)


def _iptables_off_script(uids) -> str:
    """Remove the OUTPUT jump for every uid we ever hooked, then flush and drop
    the SENTINEL_PROXY chain on both IP families. Deleting only one uid's jump
    (while the chain is shared) would leave other apps redirected, so we delete
    them all; a bare `-D OUTPUT -j CHAIN` cannot match a `--uid-owner` rule."""
    clean = [int(u) for u in (uids or []) if u is not None]
    lines: list[str] = []
    for ipt in ("iptables", "ip6tables"):
        for u in clean:
            lines.append(
                f"{ipt} -t nat -D OUTPUT -m owner --uid-owner {u} -j {_CHAIN} 2>/dev/null")
        lines += [f"{ipt} -t nat -F {_CHAIN} 2>/dev/null",
                  f"{ipt} -t nat -X {_CHAIN} 2>/dev/null"]
    return "; ".join(lines)


def _hooked_uids(dctx) -> list[int]:
    """Every uid currently jumped into our chain, from the snapshot (falls back
    to the single stored uid for snapshots written before this was tracked)."""
    snap = _snapshot(dctx, "intercept_proxy") or {}
    uids = snap.get("hooked_uids")
    if uids:
        return [int(u) for u in uids if u is not None]
    u = snap.get("uid")
    return [int(u)] if u is not None else []


def set_proxy(dctx, mode, host=None, port=None, package=None) -> dict:
    """Point the device (global) or one app (per-app nat redirect) at the proxy,
    or clear both (off). Returns {ok, output, proxy:{...}}; gated on confirm."""
    try:
        if mode not in ("global", "per-app", "off"):
            raise _Refused("mode must be global, per-app or off")
        if mode in ("global", "per-app"):
            host = _vhost(host)
            port = _vport(port)
        if mode == "per-app":
            package = _vpkg(package)
    except _Refused as e:
        # refused before touching the device -> no event, state unchanged
        return {"ok": False, "output": str(e), "proxy": _proxy_from_snapshot(dctx)}

    adb = getattr(dctx, "adb", None)
    if adb is None:
        return {"ok": False, "output": "needs a real device (not demo mode)",
                "proxy": _empty_proxy()}

    # Resolve the per-app uid BEFORE any teardown, so a failed resolve refuses
    # without disturbing a prior interception.
    uid = None
    if mode == "per-app":
        uid = package_uid(dctx, package, 0)
        if uid is None:
            _emit(dctx, action="proxy.per-app", ok=False, what="Proxy",
                  detail=f"{package} (uid?)", host=host, port=port, package=package)
            return {"ok": False, "output": "could not resolve the app's uid (installed?)",
                    "proxy": _proxy_from_snapshot(dctx)}

    # Tear down every previously-hooked uid before applying the new config: the
    # SENTINEL_PROXY chain is shared, so switching the target app (or going
    # global/off) must not leave an earlier app silently redirected.
    prev_uids = _hooked_uids(dctx)
    teardown = ""
    if prev_uids:
        try:
            teardown = adb.shell_sync(_iptables_off_script(prev_uids), su=True, timeout=30).strip()
        except AdbError as e:
            teardown = str(e)

    if mode == "global":
        try:
            out = adb.shell_sync(
                f"settings put global http_proxy {shlex.quote(f'{host}:{port}')}",
                timeout=20).strip()
            ok = "Exception" not in out
        except AdbError as e:
            out, ok = str(e), False
        new, hooked = {"mode": "global", "host": host, "port": port,
                       "package": None, "uid": None}, []
        _emit(dctx, action="proxy.global", ok=ok, what="Proxy",
              detail=f"global {host}:{port}", host=host, port=port, output=out)

    elif mode == "per-app":
        try:
            out = adb.shell_sync(_iptables_on_script(uid, host, port), su=True, timeout=30).strip()
            ok = "Permission denied" not in out and "not found" not in out
        except AdbError as e:
            out, ok = str(e), False
        new, hooked = {"mode": "per-app", "host": host, "port": port,
                       "package": package, "uid": int(uid)}, [int(uid)]
        _emit(dctx, action="proxy.per-app", ok=ok, what="Proxy",
              detail=f"{package} -> {host}:{port}", host=host, port=port, package=package, output=out)

    else:  # off: the chain + every jump are already gone (teardown above);
           # just clear the global setting
        try:
            out = adb.shell_sync("settings put global http_proxy :0", timeout=20).strip()
            ok = "Permission denied" not in out and "Exception" not in out
        except AdbError as e:
            out, ok = str(e), False
        out = (teardown + "\n" + out).strip()
        new, hooked = _empty_proxy(), []
        _emit(dctx, action="proxy.off", ok=ok, what="Proxy", detail="cleared", output=out)

    if ok:
        # the snapshot tracks hooked_uids for teardown; the returned block does not
        _put_snapshot(dctx, "intercept_proxy", {**new, "hooked_uids": hooked})
    return {"ok": ok, "output": out or ("done" if ok else "failed"),
            "proxy": new if ok else _proxy_from_snapshot(dctx)}


# ---------------- assembled status ----------------

def status(dctx) -> dict:
    """The full /api/intercept/status payload (demo flag added by the route)."""
    dev = getattr(dctx, "device", None) or {}
    errors: dict[str, str] = {}
    try:
        ca = ca_status(dctx)
    except Exception as e:  # noqa: BLE001 - one bad probe must not sink status
        ca, errors["ca"] = _empty_ca(), f"{type(e).__name__}: {e}"
    try:
        proxy = proxy_status(dctx)
    except Exception as e:  # noqa: BLE001
        proxy, errors["proxy"] = _empty_proxy(), f"{type(e).__name__}: {e}"
    return {
        "root": bool(dev.get("root")),
        "sdk": _int_or_none(dev.get("sdk")),
        "android": dev.get("android"),
        "ca": ca,
        "proxy": proxy,
        "errors": errors,
    }
