"""mitmproxy bridge: run a host mitmdump that streams each HTTP flow into the
per-app request monitor (reqmon). Optional dependency — degrades cleanly when
mitmproxy is not installed, with the UI saying how to install it.

The flows belong to apps the operator is intercepting on their own device (the
proxy is pointed at it by the Intercept tab); mitmdump posts each flow back to
the dashboard's internal endpoint, which hands it to reqmon.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
from pathlib import Path

# the addon mitmdump loads: it POSTs a compact row per response to the local
# dashboard, which calls reqmon.add_flow. Kept tiny and dependency-free.
_ADDON = '''\
import json, urllib.request
from mitmproxy import http

DASH = "http://127.0.0.1:%(port)d/api/_mitm_flow"
DEVICE = %(device)r

def response(flow: http.HTTPFlow):
    try:
        req, resp = flow.request, flow.response
        row = {
            "device": DEVICE,
            "flow": {
                "method": req.method, "host": req.pretty_host,
                "path": req.path.split("?", 1)[0], "scheme": req.scheme,
                "port": req.port, "status": resp.status_code if resp else None,
                "req_bytes": len(req.raw_content or b""),
                "resp_bytes": len(resp.raw_content or b"") if resp else 0,
                "content_type": (resp.headers.get("content-type") if resp else None),
                "req_headers": dict(req.headers), "has_auth": any(
                    k.lower() in ("authorization", "cookie", "x-api-key")
                    for k in req.headers),
            },
        }
        data = json.dumps(row).encode()
        urllib.request.urlopen(urllib.request.Request(
            DASH, data=data, headers={"Content-Type": "application/json",
                                      "Origin": "http://127.0.0.1:%(port)d"}), timeout=2)
    except Exception:
        pass
'''


def _state(hub) -> dict:
    s = getattr(hub, "_mitm", None)
    if s is None:
        s = hub._mitm = {"proc": None, "port": None}
    return s


def _which() -> str | None:
    return shutil.which("mitmdump")


def _version() -> str | None:
    exe = _which()
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True,
                             timeout=10)
        return (out.stdout or out.stderr).splitlines()[0].strip() if out.stdout or out.stderr else None
    except Exception:  # noqa: BLE001
        return None


def status(hub) -> dict:
    s = _state(hub)
    proc = s.get("proc")
    running = proc is not None and proc.poll() is None
    return {"installed": _which() is not None, "running": running,
            "port": s.get("port") if running else None, "version": _version()}


def start(hub, port: int, mode: str, dashboard_port: int) -> dict:
    if _which() is None:
        return {"ok": False, "output": "mitmproxy is not installed: pip install mitmproxy",
                "port": None}
    if not 1 <= int(port) <= 65535:
        return {"ok": False, "output": "port out of range", "port": None}
    if mode not in ("regular", "transparent"):
        return {"ok": False, "output": "mode must be regular or transparent", "port": None}
    s = _state(hub)
    if s.get("proc") and s["proc"].poll() is None:
        return {"ok": False, "output": f"already running on port {s.get('port')}",
                "port": s.get("port")}
    addon_dir = Path(hub.cfg.data_dir) / "mitm"
    addon_dir.mkdir(parents=True, exist_ok=True)
    addon = addon_dir / "sentinel_addon.py"
    addon.write_text(_ADDON % {"port": int(dashboard_port), "device": None})
    cmd = [_which(), "-p", str(int(port)), "-s", str(addon), "-q"]
    if mode == "transparent":
        cmd += ["--mode", "transparent"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                start_new_session=True)
    except OSError as e:
        return {"ok": False, "output": f"could not start mitmdump: {e}", "port": None}
    s["proc"], s["port"] = proc, int(port)
    return {"ok": True, "output": f"mitmdump started on {port} ({mode})", "port": int(port)}


def stop(hub) -> dict:
    s = _state(hub)
    proc = s.get("proc")
    if proc is None or proc.poll() is not None:
        s["proc"], s["port"] = None, None
        return {"ok": True, "output": "not running"}
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        proc.terminate()
    s["proc"], s["port"] = None, None
    return {"ok": True, "output": "mitmdump stopped"}


def ingest(hub, device, flow: dict) -> None:
    """Called by the internal /api/_mitm_flow route: route one flow row into
    the request monitor of the matching (or default) device."""
    from . import reqmon
    dctx = hub.resolve(device if isinstance(device, str) else None)
    if dctx is None:
        return
    row = dict(flow or {})
    reqmon.add_flow(dctx, row)
