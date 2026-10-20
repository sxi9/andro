"""Automation: auto-apply a performance profile based on device context — on
charger, on battery, low battery, or a specific app in the foreground. Rules are
persisted per device; a background collector evaluates them and applies a profile
only when the chosen one changes (never re-applies every tick).
"""
from __future__ import annotations

import json
import os
import re
import threading

from ..adb.client import AdbError

_PKG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.]{1,254}\Z")
_VALID_PROFILES = ("extreme", "gaming", "performance", "balanced", "powersave", "reset")
_LOCK = threading.Lock()
_LAST: dict[str, str] = {}   # serial -> last applied profile (avoid re-applying)


def _path(dctx) -> str:
    hub = getattr(dctx, "hub", None)
    data_dir = (getattr(getattr(hub, "cfg", None), "data_dir", None)
                or os.path.expanduser("~/.android-sentinel"))
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "automation.json")


def _load_all(dctx) -> dict:
    try:
        with open(_path(dctx), "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _default() -> dict:
    return {"enabled": False, "on_charger": None, "on_battery": None,
            "low_battery": None, "low_battery_pct": 20, "apps": []}


def get_config(dctx) -> dict:
    serial = getattr(dctx, "serial", "") or "default"
    cfg = _load_all(dctx).get(serial) or _default()
    cfg.setdefault("apps", [])
    cfg["_last_applied"] = _LAST.get(serial)
    return cfg


def set_config(dctx, cfg: dict) -> dict:
    serial = getattr(dctx, "serial", "") or "default"
    cfg = cfg or {}

    def _prof(v):
        return v if v in _VALID_PROFILES else None

    clean = {
        "enabled": bool(cfg.get("enabled")),
        "on_charger": _prof(cfg.get("on_charger")),
        "on_battery": _prof(cfg.get("on_battery")),
        "low_battery": _prof(cfg.get("low_battery")),
        "low_battery_pct": max(5, min(int(cfg.get("low_battery_pct") or 20), 95)),
        "apps": [],
    }
    for a in (cfg.get("apps") or [])[:50]:
        pkg = str(a.get("package", ""))
        prof = _prof(a.get("profile"))
        if _PKG_RE.match(pkg) and prof:
            clean["apps"].append({"package": pkg, "profile": prof})
    with _LOCK:
        allc = _load_all(dctx)
        allc[serial] = clean
        try:
            with open(_path(dctx), "w", encoding="utf-8") as f:
                json.dump(allc, f, indent=2)
        except OSError as e:
            return {"ok": False, "output": str(e)}
    return {"ok": True, "output": "automation rules saved", "config": clean}


def _context(dctx) -> dict:
    """Current (charging, level, foreground pkg) — cheap reads."""
    adb = dctx.adb
    charging, level = None, None
    perf = getattr(dctx, "state", {}).get("perf") if hasattr(dctx, "state") else None
    batt = (perf or {}).get("battery") if perf else None
    if batt:
        charging = batt.get("charging")
        level = batt.get("level")
    if charging is None:
        try:
            out = adb.shell_sync("dumpsys battery", timeout=10) or ""
            charging = ("powered: true" in out.lower()) or ("status: 2" in out)
            m = re.search(r"level:\s*(\d+)", out)
            level = int(m.group(1)) if m else None
        except AdbError:
            pass
    fg = None
    try:
        out = adb.shell_sync("dumpsys activity activities | grep -m1 topResumedActivity", timeout=10) or ""
        m = re.search(r"\s([A-Za-z0-9_.]+)/", out)
        fg = m.group(1) if m else None
    except AdbError:
        pass
    return {"charging": charging, "level": level, "foreground": fg}


def _target_profile(cfg: dict, ctx: dict) -> str | None:
    """Decide the profile from rules: app match > low battery > charger/battery."""
    fg = ctx.get("foreground")
    for a in cfg.get("apps", []):
        if a["package"] == fg:
            return a["profile"]
    lvl = ctx.get("level")
    if cfg.get("low_battery") and lvl is not None and lvl <= cfg.get("low_battery_pct", 20) \
            and not ctx.get("charging"):
        return cfg["low_battery"]
    if ctx.get("charging") and cfg.get("on_charger"):
        return cfg["on_charger"]
    if ctx.get("charging") is False and cfg.get("on_battery"):
        return cfg["on_battery"]
    return None


def evaluate(dctx, apply: bool = True) -> dict:
    """Compute the target profile for the current context and apply it if it
    changed since last time. Returns the context + decision."""
    serial = getattr(dctx, "serial", "") or "default"
    cfg = get_config(dctx)
    if not cfg.get("enabled"):
        return {"enabled": False}
    ctx = _context(dctx)
    target = _target_profile(cfg, ctx)
    result = {"enabled": True, "context": ctx, "target": target, "applied": False}
    if apply and target and _LAST.get(serial) != target:
        from . import perf
        try:
            perf.apply_profile(dctx, target)
            _LAST[serial] = target
            result["applied"] = True
        except Exception as e:  # noqa: BLE001
            result["error"] = str(e)
    return result
