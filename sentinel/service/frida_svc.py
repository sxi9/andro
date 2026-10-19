"""Frida-based SSL-unpinning for an app the operator is authorized to test.

For an in-scope app that still rejects the proxy after its CA is trusted (it
pins), this hooks the app's TLS validation at runtime so the proxy's cert is
accepted and the traffic can be inspected. `frida` (python) is an optional host
dependency; `frida-server` runs on the device. The session is kept alive and
every hook hit is streamed to the Activity Console, so you drive the app and
watch pinning get bypassed live. Everything targets the one selected package.
"""
from __future__ import annotations

import re
import shlex
import threading
import time

from ..adb.client import AdbError
from ..core.events import Event, SEV_NOTICE, SEV_WARN

_PKG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.]{1,254}\Z")
_SERVER = "/data/local/tmp/frida-server"   # fixed path we own
_MODES = ("spawn", "attach")

# live sessions, kept alive so the hooks keep firing: serial -> (device, session, script, pid)
_SESSIONS: dict[str, tuple] = {}
_LOCK = threading.Lock()

# The comprehensive universal unpinning script: every common stack, each hook
# wrapped so a stack the app does not use is a harmless no-op, and each prints a
# line when it installs or fires so you can see it in the Console.
_UNIVERSAL = r"""
'use strict';
function log(m) { send('[frida] ' + m); }
log('loading unpinning hooks…');

Java.perform(function () {
  // ---- OkHttp 3/4 CertificatePinner ----
  try {
    var CP = Java.use('okhttp3.CertificatePinner');
    var ms = CP.check.overloads;
    ms.forEach(function (ov) {
      ov.implementation = function () { log('OkHttp CertificatePinner.check() bypassed'); return; };
    });
    log('hooked OkHttp CertificatePinner');
  } catch (e) {}

  // ---- Conscrypt / AOSP TrustManagerImpl ----
  try {
    var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    try { TMI.verifyChain.implementation = function (certs, host, ca, oc, tls) {
      log('TrustManagerImpl.verifyChain() bypassed (' + host + ')'); return certs; }; } catch (e) {}
    try { TMI.checkTrustedRecursive.implementation = function () {
      log('TrustManagerImpl.checkTrustedRecursive() bypassed');
      return Java.use('java.util.ArrayList').$new(); }; } catch (e) {}
    log('hooked TrustManagerImpl');
  } catch (e) {}

  // ---- SSLContext trust-all ----
  try {
    var X509TM = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustAll = Java.registerClass({
      name: 'com.sentinel.TrustAll', implements: [X509TM],
      methods: { checkClientTrusted: function () {}, checkServerTrusted: function () {},
                 getAcceptedIssuers: function () { return []; } },
    });
    var inits = SSLContext.init.overloads;
    inits.forEach(function (ov) {
      ov.implementation = function (km, tm, sr) {
        log('SSLContext.init() -> trust-all');
        this.init(km, [TrustAll.$new()], sr);
      };
    });
    log('hooked SSLContext.init');
  } catch (e) {}

  // ---- X509TrustManagerExtensions (checkServerTrusted) ----
  try {
    var X = Java.use('android.net.http.X509TrustManagerExtensions');
    X.checkServerTrusted.implementation = function (chain, at, host) {
      log('X509TrustManagerExtensions.checkServerTrusted() bypassed (' + host + ')');
      return Java.use('java.util.ArrayList').$new();
    };
    log('hooked X509TrustManagerExtensions');
  } catch (e) {}

  // ---- HttpsURLConnection host/verifier ----
  try {
    var HUC = Java.use('javax.net.ssl.HttpsURLConnection');
    HUC.setDefaultHostnameVerifier.implementation = function () { log('HttpsURLConnection host verifier neutralised'); return; };
    HUC.setSSLSocketFactory.implementation = function () { return; };
    HUC.setHostnameVerifier.implementation = function () { return; };
  } catch (e) {}

  // ---- WebViewClient SSL errors ----
  try {
    var WVC = Java.use('android.webkit.WebViewClient');
    WVC.onReceivedSslError.implementation = function (view, handler, err) {
      log('WebViewClient.onReceivedSslError() -> proceed'); handler.proceed();
    };
  } catch (e) {}

  // ---- TrustKit ----
  try {
    var TK = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
    TK.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function () {
      log('TrustKit OkHostnameVerifier bypassed'); return true; };
  } catch (e) {}

  // ---- Appcelerator Titanium PinningTrustManager ----
  try {
    var PTM = Java.use('appcelerator.https.PinningTrustManager');
    PTM.checkServerTrusted.implementation = function () { log('Appcelerator PinningTrustManager bypassed'); };
  } catch (e) {}
});

// ---- Flutter / BoringSSL (native) ----
function hookFlutter() {
  try {
    var m = Process.findModuleByName('libflutter.so');
    if (!m) { return false; }
    // scan for ssl_crypto_x509_session_verify_cert_chain and force success.
    var patterns = {
      'arm64': 'FF 03 05 D1 FC 6B 0E A9 F8 5F 0F A9 F6 57 10 A9 F4 4F 11 A9 08 0A 80 52',
    };
    var found = false;
    Memory.scan(m.base, m.size, patterns.arm64, {
      onMatch: function (addr) {
        found = true;
        Interceptor.attach(addr, { onLeave: function (r) { r.replace(0x1); } });
        send('[frida] Flutter: patched cert verify at ' + addr);
      }, onComplete: function () {}
    });
    if (!found) send('[frida] Flutter: libflutter.so present (no known pattern matched on this build)');
    return true;
  } catch (e) { return false; }
}
if (!hookFlutter()) { setTimeout(hookFlutter, 2000); }

send('[+] sentinel: pinning bypass installed');
"""

_OKHTTP = r"""Java.perform(function(){try{var CP=Java.use('okhttp3.CertificatePinner');CP.check.overloads.forEach(function(o){o.implementation=function(){send('[frida] OkHttp CertificatePinner.check bypassed');};});send('[frida] hooked OkHttp');}catch(e){}});send('[+] sentinel: pinning bypass installed');"""
_TRUSTMANAGER = r"""Java.perform(function(){try{var T=Java.use('com.android.org.conscrypt.TrustManagerImpl');T.verifyChain.implementation=function(c,h,a,o,t){send('[frida] TrustManagerImpl.verifyChain bypassed');return c;};send('[frida] hooked TrustManagerImpl');}catch(e){}});send('[+] sentinel: pinning bypass installed');"""
_WEBVIEW = r"""Java.perform(function(){try{var W=Java.use('android.webkit.WebViewClient');W.onReceivedSslError.implementation=function(v,h,e){send('[frida] WebView onReceivedSslError proceed');h.proceed();};send('[frida] hooked WebView');}catch(e){}});send('[+] sentinel: pinning bypass installed');"""
_FLUTTER_ONLY = _UNIVERSAL  # the universal script already handles Flutter natively

_PRESETS = {
    "all": ("All stacks (recommended)", _UNIVERSAL,
            ["okhttp", "conscrypt", "aosp", "webview", "trustkit", "flutter"]),
    "okhttp": ("OkHttp CertificatePinner", _OKHTTP, ["okhttp"]),
    "trustmanager": ("System TrustManager / Conscrypt", _TRUSTMANAGER, ["conscrypt", "aosp"]),
    "webview": ("WebView SSL errors", _WEBVIEW, ["webview"]),
    "flutter": ("Flutter / BoringSSL (+ all Java)", _UNIVERSAL, ["flutter"]),
}


def _have_frida():
    try:
        import frida  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def presets() -> list[dict]:
    return [{"id": k, "title": t, "stacks": s} for k, (t, _js, s) in _PRESETS.items()]


def _emit(dctx, ok, title, detail=""):
    emit = getattr(dctx, "emit_threadsafe", None)
    if callable(emit):
        try:
            emit(Event(kind="frida.log", severity=SEV_NOTICE if ok else SEV_WARN,
                       title=title, detail=str(detail)[:400],
                       data={"ok": bool(ok), "output": str(detail)[:400]}))
        except Exception:  # noqa: BLE001
            pass


def _server_running(dctx) -> bool:
    try:
        out = dctx.adb.shell_sync("pgrep -f frida-server || true", timeout=10)
        return bool(out.strip())
    except AdbError:
        return False


def status(dctx) -> dict:
    host = _have_frida()
    host_version = None
    if host:
        try:
            import frida
            host_version = frida.__version__
        except Exception:  # noqa: BLE001
            pass
    arch = None
    try:
        arch = dctx.adb.shell_sync("getprop ro.product.cpu.abi", timeout=10).strip() or None
    except AdbError:
        pass
    return {"host_frida": host, "host_version": host_version,
            "server_running": _server_running(dctx), "server_version": None,
            "arch": arch, "unpinning": getattr(dctx, "serial", "") in _SESSIONS}


def push_server(dctx, local_path: str) -> dict:
    import os
    if not local_path or not os.path.isfile(local_path):
        return {"ok": False, "output": "no frida-server file provided"}
    if not dctx.adb.push_file(local_path, _SERVER):
        return {"ok": False, "output": "adb push of frida-server failed"}
    try:
        dctx.adb.shell_sync(f"chmod 755 {shlex.quote(_SERVER)}", su=True, timeout=15)
    except AdbError as e:
        return {"ok": False, "output": str(e)}
    _emit(dctx, True, "frida-server pushed", _SERVER)
    return {"ok": True, "output": f"frida-server pushed to {_SERVER}"}


def start_server(dctx) -> dict:
    cmd = f"{shlex.quote(_SERVER)} -D 2>/dev/null &"
    try:
        dctx.adb.shell_sync(cmd, su=True, timeout=15)
    except AdbError as e:
        _emit(dctx, False, "frida-server start failed", str(e))
        return {"ok": False, "output": str(e)}
    time.sleep(1.0)
    running = _server_running(dctx)
    msg = "frida-server started" if running else "frida-server did not come up (wrong arch binary?)"
    _emit(dctx, running, msg)
    return {"ok": running, "output": msg}


def stop_server(dctx) -> dict:
    stop_unpin(dctx)
    try:
        dctx.adb.shell_sync("pkill -f frida-server || true", su=True, timeout=15)
    except AdbError as e:
        return {"ok": False, "output": str(e)}
    _emit(dctx, True, "frida-server stopped")
    return {"ok": True, "output": "frida-server stopped"}


def list_targets(dctx) -> list[dict]:
    if not _have_frida():
        return []
    try:
        import frida
        dev = frida.get_usb_device(timeout=5)
        return [{"name": a.name, "identifier": a.identifier, "pid": a.pid or None}
                for a in dev.enumerate_applications()]
    except Exception:  # noqa: BLE001
        return []


def stop_unpin(dctx) -> dict:
    serial = getattr(dctx, "serial", "")
    with _LOCK:
        sess = _SESSIONS.pop(serial, None)
    if not sess:
        return {"ok": True, "output": "no unpinning session"}
    _dev, session, script, _pid = sess
    try:
        script.unload()
    except Exception:  # noqa: BLE001
        pass
    try:
        session.detach()
    except Exception:  # noqa: BLE001
        pass
    _emit(dctx, True, "unpinning detached")
    return {"ok": True, "output": "unpinning stopped"}


def unpin(dctx, package: str, preset: str, mode: str) -> dict:
    """Inject the unpinning preset into the in-scope app and KEEP the session
    alive: every hook install and hit streams to the Activity Console as the app
    runs. Drive the app and watch the lines appear. spawn catches pinning set up
    at startup; attach targets the running app."""
    if not _PKG.match(package or ""):
        return {"ok": False, "output": "invalid package name", "bypassed": False}
    if preset not in _PRESETS:
        return {"ok": False, "output": "unknown preset", "bypassed": False}
    if mode not in _MODES:
        return {"ok": False, "output": "mode must be spawn or attach", "bypassed": False}
    if not _have_frida():
        return {"ok": False, "bypassed": False,
                "output": "frida is not installed on THIS computer. Install it in the venv:\n"
                          "  pip install frida-tools\n"
                          "then click Unpin again."}
    stop_unpin(dctx)   # one live session per device
    js = _PRESETS[preset][1]
    try:
        import frida
        dev = frida.get_usb_device(timeout=5)
        installed = {"mark": False}

        def on_message(msg, _data):
            if msg.get("type") == "send":
                line = str(msg.get("payload"))
                if "pinning bypass installed" in line:
                    installed["mark"] = True
                _emit(dctx, True, "frida: " + package, line)
            elif msg.get("type") == "error":
                _emit(dctx, False, "frida error", msg.get("description") or str(msg))

        if mode == "spawn":
            pid = dev.spawn([package])
            session = dev.attach(pid)
        else:
            session = dev.attach(package)
            pid = None
        script = session.create_script(js)
        script.on("message", on_message)
        script.load()
        if mode == "spawn" and pid is not None:
            dev.resume(pid)
        time.sleep(1.2)   # let the install lines arrive
        with _LOCK:
            _SESSIONS[getattr(dctx, "serial", "")] = (dev, session, script, pid)
        note = ("hooks injected — now open/use the app so it makes HTTPS calls; "
                "each bypass streams to the Console. Click Stop unpinning when done.")
        _emit(dctx, True, "frida: " + package, note)
        return {"ok": True, "bypassed": installed["mark"], "streaming": True,
                "output": ("✓ hooks installed\n" if installed["mark"] else "") + note}
    except Exception as e:  # noqa: BLE001 - frida raises many device-specific errors
        msg = f"frida error: {e}"
        _emit(dctx, False, "frida error", msg)
        hint = ""
        if "unable to connect" in str(e).lower() or "server" in str(e).lower():
            hint = "\nIs frida-server running on the phone? (Start server above.)"
        if "not been found" in str(e).lower() or "ProcessNotFound" in str(e):
            hint = "\nApp not running — use Spawn mode, or open the app first for Attach."
        return {"ok": False, "bypassed": False, "output": msg + hint}
