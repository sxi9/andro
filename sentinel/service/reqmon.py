"""Per-app HTTP request monitor: a bounded in-memory flow ring per device,
filtered per package, with saved watches that raise alerts, an endpoint map,
and HAR/CSV/JSON export.

Flows are appended by the mitmproxy bridge (full HTTP) and could be fed by the
passive capture too. Nothing here touches the device; it is read/aggregate/
alert over data the operator is already capturing from an in-scope app.
"""
from __future__ import annotations

import csv
import io
import json
import re
import time
from collections import deque
from typing import Any

_RING = "http_flows"         # dctx.state deque of flow rows
_WATCHES = "req_watches"     # store snapshot: [{id,name,package?,filter,severity}]
_MAX = 5000
_AUTH_KEYS = ("authorization", "cookie", "x-api-key", "x-auth-token")


def _ring(dctx) -> deque:
    r = dctx.state.get(_RING)
    if not isinstance(r, deque):
        r = deque(maxlen=_MAX)
        dctx.state[_RING] = r
    return r


def _seen_hosts(dctx) -> set:
    s = dctx.state.get("http_seen_hosts")
    if not isinstance(s, set):
        s = set()
        dctx.state["http_seen_hosts"] = s
    return s


def add_flow(dctx, row: dict) -> dict:
    """Append one flow row (normalised), stamp a flow_id and first-seen-host,
    evaluate the watches, and return the stored row."""
    seen = _seen_hosts(dctx)
    host = str(row.get("host", ""))
    flow = {
        "ts": row.get("ts") or time.time(),
        "package": row.get("package"), "uid": row.get("uid"),
        "method": (row.get("method") or "GET").upper(),
        "host": host, "path": row.get("path") or "/",
        "scheme": row.get("scheme") or ("https" if row.get("port") in (443, None) else "http"),
        "status": row.get("status"),
        "req_bytes": int(row.get("req_bytes") or 0),
        "resp_bytes": int(row.get("resp_bytes") or 0),
        "duration_ms": int(row.get("duration_ms") or 0),
        "content_type": row.get("content_type"),
        "has_auth": bool(row.get("has_auth")
                         or _has_auth(row.get("req_headers") or {})),
        "flow_id": row.get("flow_id") or f"{int((row.get('ts') or time.time())*1000)}-{len(_ring(dctx))}",
        "new_host": host not in seen,
        "req_headers": row.get("req_headers"), "resp_headers": row.get("resp_headers"),
        "req_body_preview": row.get("req_body_preview"),
        "resp_body_preview": row.get("resp_body_preview"),
    }
    if host:
        seen.add(host)
    _ring(dctx).append(flow)
    _evaluate(dctx, flow)
    return flow


def _has_auth(headers: dict) -> bool:
    return any(k.lower() in _AUTH_KEYS for k in headers)


def _match(flow: dict, f: dict) -> bool:
    """Does a flow match a filter dict? Empty/missing keys are ignored."""
    if not f:
        return True
    pkg = f.get("package")
    if pkg and flow.get("package") != pkg:
        return False
    host = f.get("host")
    if host and host.lower() not in str(flow.get("host", "")).lower():
        return False
    rx = f.get("path")
    if rx:
        try:
            if not re.search(rx, flow.get("path", "")):
                return False
        except re.error:
            if rx not in flow.get("path", ""):
                return False
    m = f.get("method")
    if m and flow.get("method") != m.upper():
        return False
    sc = f.get("status_class")
    if sc:
        st = flow.get("status") or 0
        if not (int(str(sc)[0]) * 100 <= st < int(str(sc)[0]) * 100 + 100):
            return False
    scheme = f.get("scheme")
    if scheme and flow.get("scheme") != scheme:
        return False
    if f.get("has_auth") and not flow.get("has_auth"):
        return False
    if f.get("new_host") and not flow.get("new_host"):
        return False
    return True


def list_flows(dctx, package: str | None = None, filters: dict | None = None,
               limit: int = 500) -> list[dict]:
    rows = list(_ring(dctx))
    f = dict(filters or {})
    if package:
        f["package"] = package
    out = [r for r in reversed(rows) if _match(r, f)]
    return out[:limit]


def endpoints(dctx, package: str | None = None) -> list[dict]:
    agg: dict[tuple, dict] = {}
    for r in _ring(dctx):
        if package and r.get("package") != package:
            continue
        key = (r.get("host"), r.get("path"))
        e = agg.get(key)
        if not e:
            e = agg[key] = {"host": r.get("host"), "path": r.get("path"),
                            "methods": set(), "count": 0,
                            "first": r["ts"], "last": r["ts"]}
        e["methods"].add(r.get("method"))
        e["count"] += 1
        e["first"] = min(e["first"], r["ts"])
        e["last"] = max(e["last"], r["ts"])
    return sorted(
        ({"host": e["host"], "path": e["path"], "method_set": sorted(e["methods"]),
          "count": e["count"], "first": e["first"], "last": e["last"]}
         for e in agg.values()), key=lambda e: e["count"], reverse=True)


# ---------------- export ----------------

def export(dctx, package: str | None, fmt: str) -> tuple[str, bytes]:
    rows = list_flows(dctx, package, limit=_MAX)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    tag = (package or "all").replace("/", "_")
    if fmt == "har":
        return f"requests-{tag}-{stamp}.har", _to_har(rows)
    if fmt == "csv":
        return f"requests-{tag}-{stamp}.csv", _to_csv(rows)
    if fmt == "json":
        return f"requests-{tag}-{stamp}.json", json.dumps(
            {"flows": rows, "count": len(rows)}, indent=2).encode()
    raise ValueError("format must be har, csv or json")


def _to_har(rows: list[dict]) -> bytes:
    entries = []
    for r in rows:
        url = f"{r['scheme']}://{r['host']}{r['path']}"
        entries.append({
            "startedDateTime": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(r["ts"])),
            "time": r["duration_ms"],
            "request": {"method": r["method"], "url": url, "httpVersion": "HTTP/1.1",
                        "headers": _har_headers(r.get("req_headers")),
                        "queryString": [], "cookies": [], "headersSize": -1,
                        "bodySize": r["req_bytes"]},
            "response": {"status": r.get("status") or 0, "statusText": "",
                         "httpVersion": "HTTP/1.1",
                         "headers": _har_headers(r.get("resp_headers")),
                         "cookies": [], "content": {"size": r["resp_bytes"],
                         "mimeType": r.get("content_type") or ""},
                         "redirectURL": "", "headersSize": -1, "bodySize": r["resp_bytes"]},
            "cache": {}, "timings": {"send": 0, "wait": r["duration_ms"], "receive": 0},
        })
    return json.dumps({"log": {"version": "1.2",
                               "creator": {"name": "Android Sentinel", "version": "1"},
                               "entries": entries}}, indent=2).encode()


def _har_headers(h) -> list[dict]:
    return [{"name": k, "value": str(v)} for k, v in (h or {}).items()]


def _to_csv(rows: list[dict]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ts", "package", "method", "scheme", "host", "path", "status",
                "req_bytes", "resp_bytes", "duration_ms", "has_auth"])
    for r in rows:
        w.writerow([r["ts"], r.get("package"), r["method"], r["scheme"], r["host"],
                    r["path"], r.get("status"), r["req_bytes"], r["resp_bytes"],
                    r["duration_ms"], r["has_auth"]])
    return buf.getvalue().encode()


# ---------------- watches ----------------

def replay(hub, spec: dict) -> dict:
    """Repeater: send an (edited) HTTP request and return the response. When a
    mitmproxy is running we route through it so the replay is re-captured, just
    like Reqable's resend. Host-side only (does not touch the device)."""
    import urllib.request
    import urllib.error
    url = str((spec or {}).get("url", "")).strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        return {"ok": False, "output": "url must start with http:// or https://"}
    method = str((spec or {}).get("method", "GET")).upper()
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        return {"ok": False, "output": "unsupported method"}
    headers = {str(k): str(v) for k, v in (spec.get("headers") or {}).items()}
    body = spec.get("body")
    data = body.encode() if isinstance(body, str) and body else None

    handlers = []
    try:
        from . import mitm
        st = mitm.status(hub)
        if spec.get("through_proxy", True) and st.get("running") and st.get("port"):
            p = f"http://127.0.0.1:{st['port']}"
            handlers.append(urllib.request.ProxyHandler({"http": p, "https": p}))
    except Exception:  # noqa: BLE001
        pass
    # replaying to a cert minted by our own CA: allow the proxy's leaf cert
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    handlers.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*handlers)

    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    t0 = time.time()
    try:
        resp = opener.open(req, timeout=30)
        raw = resp.read(256 * 1024)
        return {"ok": True, "status": resp.status,
                "headers": dict(resp.headers), "bytes": len(raw),
                "body_preview": raw[:8192].decode("utf-8", "replace"),
                "duration_ms": int((time.time() - t0) * 1000)}
    except urllib.error.HTTPError as e:
        raw = e.read(256 * 1024) if hasattr(e, "read") else b""
        return {"ok": True, "status": e.code, "headers": dict(e.headers or {}),
                "bytes": len(raw), "body_preview": raw[:8192].decode("utf-8", "replace"),
                "duration_ms": int((time.time() - t0) * 1000)}
    except Exception as e:  # noqa: BLE001 - network/TLS/proxy errors
        return {"ok": False, "output": f"replay failed: {e}"}


def list_watches(dctx) -> list[dict]:
    return dctx.store.get_snapshot(_WATCHES) or []


def add_watch(dctx, name: str, filt: dict, package: str | None = None,
              severity: str = "warn") -> dict:
    import uuid
    if not name:
        raise ValueError("a watch needs a name")
    w = {"id": uuid.uuid4().hex[:8], "name": str(name)[:80],
         "package": package, "filter": dict(filt or {}), "severity": severity}
    ws = list_watches(dctx)
    ws.append(w)
    dctx.store.put_snapshot(_WATCHES, ws)
    return w


def delete_watch(dctx, wid: str) -> None:
    dctx.store.put_snapshot(_WATCHES, [w for w in list_watches(dctx) if w["id"] != wid])


def _evaluate(dctx, flow: dict) -> None:
    """Fire an alert for every watch the flow matches."""
    from ..core.events import Event, SEV_WARN, SEV_NOTICE
    for w in list_watches(dctx):
        f = dict(w.get("filter") or {})
        if w.get("package"):
            f["package"] = w["package"]
        if _match(flow, f):
            sev = SEV_WARN if w.get("severity", "warn") == "warn" else SEV_NOTICE
            dctx.emit_threadsafe(Event(
                kind="alert", severity=sev,
                title=f"watch: {w.get('name')}",
                detail=f"{flow['method']} {flow['host']}{flow['path']}",
                app=flow.get("package"),
                data={"watch": w["id"], "flow_id": flow["flow_id"],
                      "host": flow["host"], "path": flow["path"],
                      "status": flow.get("status")}))
