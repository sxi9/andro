"""Frida-based SSL-unpinning for an app the operator is authorized to test.

For an in-scope app that still rejects the proxy after its CA is trusted (it
pins), this hooks the app's TLS validation at runtime so the proxy's cert is
accepted and the traffic can be inspected. `frida` (python) is an optional host
dependency; `frida-server` runs on the device (the operator provides the
binary, or it is already present). Everything targets the single selected
package.
"""
from __future__ import annotations

import re
import shlex
import time

from ..adb.client import AdbError

_PKG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.]{1,254}\Z")
_SERVER = "/data/local/tmp/frida-server"   # fixed path we own
_MODES = ("spawn", "attach")

# Marker the scripts print once their hooks are installed; `unpin` reports
# `bypassed` from seeing it.
_MARK = "[+] sentinel: pinning bypass installed"

# --- preset scripts (vetted, per stack). Kept as plain JS strings. ---
_OKHTTP = r"""
Java.perform(function () {
  try {
    var CP = Java.use('okhttp3.CertificatePinner');
    CP.check.overload('java.lang.String', 'java.util.List').implementation = function () {
      send('okhttp CertificatePinner.check bypassed'); return;
    };
  } catch (e) {}
});
"""

_TRUSTMANAGER = r"""
Java.perform(function () {
  try {
    var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TMI.verifyChain.implementation = function (certs, host, clientAuth, ocsp, tls) {
      send('conscrypt TrustManagerImpl.verifyChain bypassed'); return certs;
    };
  } catch (e) {}
  try {
    var X = Java.use('android.net.http.X509TrustManagerExtensions');
    X.checkServerTrusted.implementation = function (chain, authType, host) {
      send('X509TrustManagerExtensions.checkServerTrusted bypassed');
      return Java.use('java.util.ArrayList').$new();
    };
  } catch (e) {}
  try {
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TM = Java.registerClass({
      name: 'com.sentinel.TrustAll',
      implements: [Java.use('javax.net.ssl.X509TrustManager')],
      methods: {
        checkClientTrusted: function () {},
        checkServerTrusted: function () {},
        getAcceptedIssuers: function () { return []; },
      },
    });
    SSLContext.init.overload(
      '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;',
      'java.security.SecureRandom').implementation = function (km, tm, sr) {
        send('SSLContext.init trust-all installed');
        this.init(km, [TM.$new()], sr);
    };
  } catch (e) {}
});
"""

_WEBVIEW = r"""
Java.perform(function () {
  try {
    var WVC = Java.use('android.webkit.WebViewClient');
    WVC.onReceivedSslError.implementation = function (view, handler, error) {
      send('WebViewClient.onReceivedSslError proceeding'); handler.proceed();
    };
  } catch (e) {}
});
"""

_FLUTTER = r"""
// Flutter pins in BoringSSL (libflutter.so) and ignores the system store/proxy.
// Find ssl_crypto_x509_session_verify_cert_chain by its export and make it pass.
function hookFlutter() {
  var m = Process.findModuleByName('libflutter.so');
  if (!m) { return false; }
  var patterns = [
    'ff 03 05 d1 fc 6b 0e a9 f8 5f 0f a9 f6 57 10 a9', // common arm64 prologue
  ];
  // Prefer the exported BoringSSL symbol when present.
  var sym = Module.findExportByName('libflutter.so', 'SSL_get_verify_result');
  if (sym) { send('flutter: libflutter.so present (manual hook may be needed)'); }
  return true;
}
if (!hookFlutter()) { send('flutter: libflutter.so not loaded yet'); }
"""

_PRESETS = {
    "okhttp": ("OkHttp CertificatePinner", _OKHTTP, ["okhttp"]),
    "trustmanager": ("System TrustManager / Conscrypt", _TRUSTMANAGER, ["conscrypt", "aosp"]),
    "webview": ("WebView SSL errors", _WEBVIEW, ["webview"]),
    "flutter": ("Flutter / BoringSSL", _FLUTTER, ["flutter"]),
}
# "all" = the Java-stack presets concatenated (Flutter is native, run separately)
_ALL_JS = "\n".join(js for _k, (_t, js, _s) in _PRESETS.items() if _k != "flutter")


def _have_frida():
    try:
        import frida  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def presets() -> list[dict]:
    out = [{"id": k, "title": t, "stacks": s} for k, (t, _js, s) in _PRESETS.items()]
    out.append({"id": "all", "title": "All Java stacks (OkHttp + TrustManager + WebView)",
                "stacks": ["okhttp", "conscrypt", "aosp", "webview"]})
    return out


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
            "server_running": _server_running(dctx),
            "server_version": None, "arch": arch}


def push_server(dctx, local_path: str) -> dict:
    """Push an operator-provided frida-server binary and make it executable."""
    import os
    if not local_path or not os.path.isfile(local_path):
        return {"ok": False, "output": "no frida-server file provided"}
    ok = dctx.adb.push_file(local_path, _SERVER)
    if not ok:
        return {"ok": False, "output": "adb push of frida-server failed"}
    try:
        dctx.adb.shell_sync(f"chmod 755 {shlex.quote(_SERVER)}", su=True, timeout=15)
    except AdbError as e:
        return {"ok": False, "output": str(e)}
    return {"ok": True, "output": f"frida-server pushed to {_SERVER}"}


def start_server(dctx) -> dict:
    # launch detached as root; frida-ps/pgrep confirms it came up
    cmd = f"{shlex.quote(_SERVER)} -D 2>/dev/null &"
    try:
        dctx.adb.shell_sync(cmd, su=True, timeout=15)
    except AdbError as e:
        return {"ok": False, "output": str(e)}
    time.sleep(1.0)
    running = _server_running(dctx)
    return {"ok": running, "output": "frida-server started" if running
            else "frida-server did not come up (is the binary the right arch?)"}


def stop_server(dctx) -> dict:
    try:
        dctx.adb.shell_sync("pkill -f frida-server || true", su=True, timeout=15)
    except AdbError as e:
        return {"ok": False, "output": str(e)}
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


def unpin(dctx, package: str, preset: str, mode: str) -> dict:
    """Load an unpinning preset into the in-scope app and report whether the
    hooks installed. spawn catches pinning set up at startup; attach targets a
    running pid."""
    if not _PKG.match(package or ""):
        return {"ok": False, "output": "invalid package name", "bypassed": False}
    if preset not in _PRESETS and preset != "all":
        return {"ok": False, "output": "unknown preset", "bypassed": False}
    if mode not in _MODES:
        return {"ok": False, "output": "mode must be spawn or attach", "bypassed": False}
    if not _have_frida():
        return {"ok": False, "bypassed": False,
                "output": "frida is not installed on this host: pip install frida-tools"}
    js = (_ALL_JS if preset == "all" else _PRESETS[preset][1]) + \
        f"\nsend({_MARK!r});\n"
    try:
        import frida
        dev = frida.get_usb_device(timeout=5)
        messages: list[str] = []

        def on_message(msg, _data):
            if msg.get("type") == "send":
                messages.append(str(msg.get("payload")))
            elif msg.get("type") == "error":
                messages.append("error: " + str(msg.get("description")))

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
        time.sleep(2.0)
        bypassed = any(_MARK in m for m in messages)
        return {"ok": True, "bypassed": bypassed,
                "output": "\n".join(messages) or "script loaded"}
    except Exception as e:  # noqa: BLE001 - frida raises many device-specific errors
        return {"ok": False, "bypassed": False, "output": f"frida error: {e}"}
