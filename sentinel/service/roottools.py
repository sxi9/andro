"""Root power-user tools for the owner's own device: battery health + charge
control, Magisk module management, SELinux mode, build.prop edits, and making
the current kernel tuning survive a reboot via a Magisk service.d script.

Everything runs over the device's own ADB, needs root, is validated here, and
degrades to {ok: false, output} rather than raising to the route.
"""
from __future__ import annotations

import re

from ..adb.client import AdbError

_BATT = "/sys/class/power_supply/battery"
_SVC_D = "/data/adb/service.d"
_CHARGE_LIMIT_SH = _SVC_D + "/sentinel-chargelimit.sh"
_TUNING_SH = _SVC_D + "/sentinel-tuning.sh"
_MODULES = "/data/adb/modules"
_PKG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.]{1,254}\Z")
_MODID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}\Z")


def _cat(adb, path: str) -> str:
    try:
        return (adb.shell_sync(f"cat {path} 2>/dev/null", su=True, timeout=10) or "").strip()
    except AdbError:
        return ""


def _int(s: str):
    s = (s or "").strip()
    return int(s) if s.lstrip("-").isdigit() else None


# ---------------- battery ----------------

def battery(dctx) -> dict:
    adb = dctx.adb
    full = _int(_cat(adb, f"{_BATT}/charge_full"))
    design = _int(_cat(adb, f"{_BATT}/charge_full_design"))
    temp = _int(_cat(adb, f"{_BATT}/temp"))
    cur = _int(_cat(adb, f"{_BATT}/current_now"))
    volt = _int(_cat(adb, f"{_BATT}/voltage_now"))
    out = {
        "capacity": _int(_cat(adb, f"{_BATT}/capacity")),
        "status": _cat(adb, f"{_BATT}/status") or None,
        "health": _cat(adb, f"{_BATT}/health") or None,
        "cycle_count": _int(_cat(adb, f"{_BATT}/cycle_count")),
        "charge_full_uah": full, "charge_full_design_uah": design,
        "health_pct": round(full / design * 100, 1) if full and design else None,
        "temp_c": round(temp / 10.0, 1) if temp is not None else None,
        "current_ma": round(cur / 1000.0) if cur is not None else None,
        "voltage_v": round(volt / 1_000_000.0, 3) if volt is not None else None,
        "charging_enabled": _cat(adb, f"{_BATT}/battery_charging_enabled") != "0",
        "charge_current_max_ma": (lambda v: round(v / 1000) if v else None)(
            _int(_cat(adb, f"{_BATT}/constant_charge_current_max"))),
        "charge_limit_pct": _read_charge_limit(adb),
    }
    return out


def set_charging(dctx, enabled: bool) -> dict:
    """Enable/disable charging outright (battery_charging_enabled / input_suspend)."""
    adb = dctx.adb
    v = "1" if enabled else "0"
    try:
        adb.shell_sync(f"echo {v} > {_BATT}/battery_charging_enabled", su=True, timeout=10)
        # input_suspend is inverted (1 = suspended)
        adb.shell_sync(f"echo {'0' if enabled else '1'} > {_BATT}/input_suspend 2>/dev/null",
                       su=True, timeout=10)
        return {"ok": True, "output": "charging " + ("enabled" if enabled else "paused")}
    except AdbError as e:
        return {"ok": False, "output": str(e)}


def set_charge_current(dctx, milliamps: int) -> dict:
    try:
        ma = int(milliamps)
    except (TypeError, ValueError):
        return {"ok": False, "output": "invalid current"}
    if not (100 <= ma <= 10000):
        return {"ok": False, "output": "current must be 100-10000 mA"}
    try:
        dctx.adb.shell_sync(f"echo {ma * 1000} > {_BATT}/constant_charge_current_max",
                            su=True, timeout=10)
        return {"ok": True, "output": f"charge current cap {ma} mA"}
    except AdbError as e:
        return {"ok": False, "output": str(e)}


def _read_charge_limit(adb) -> int | None:
    txt = _cat(adb, _CHARGE_LIMIT_SH)
    m = re.search(r"LIMIT=(\d+)", txt)
    return int(m.group(1)) if m else None


def set_charge_limit(dctx, pct: int) -> dict:
    """Install (or remove, pct=0) a Magisk service.d poller that pauses charging
    at pct% and resumes a few points below — a persistent charge limit."""
    adb = dctx.adb
    try:
        p = int(pct)
    except (TypeError, ValueError):
        return {"ok": False, "output": "invalid percent"}
    if p == 0:
        try:
            adb.shell_sync(f"rm -f {_CHARGE_LIMIT_SH}", su=True, timeout=10)
            adb.shell_sync(f"echo 1 > {_BATT}/battery_charging_enabled", su=True, timeout=10)
            return {"ok": True, "output": "charge limit removed"}
        except AdbError as e:
            return {"ok": False, "output": str(e)}
    if not (40 <= p <= 100):
        return {"ok": False, "output": "limit must be 40-100 (or 0 to disable)"}
    script = (
        "#!/system/bin/sh\n"
        f"# Sentinel charge limit\nLIMIT={p}\nRESUME=$((LIMIT-4))\n"
        "while true; do\n"
        f"  c=$(cat {_BATT}/capacity 2>/dev/null)\n"
        f"  [ \"$c\" -ge \"$LIMIT\" ] && echo 0 > {_BATT}/battery_charging_enabled 2>/dev/null\n"
        f"  [ \"$c\" -le \"$RESUME\" ] && echo 1 > {_BATT}/battery_charging_enabled 2>/dev/null\n"
        "  sleep 60\ndone &\n"
    )
    try:
        adb.shell_sync(f"mkdir -p {_SVC_D}", su=True, timeout=10)
        _write_file(adb, _CHARGE_LIMIT_SH, script)
        adb.shell_sync(f"chmod 755 {_CHARGE_LIMIT_SH}", su=True, timeout=10)
        adb.shell_sync(f"sh {_CHARGE_LIMIT_SH}", su=True, timeout=10)  # start now too
        return {"ok": True, "output": f"charge limit set to {p}% (persists on reboot)"}
    except AdbError as e:
        return {"ok": False, "output": str(e)}


# ---------------- SELinux ----------------

def selinux_status(dctx) -> dict:
    mode = _cat(dctx.adb, "/sys/fs/selinux/enforce") or ""
    try:
        enf = (dctx.adb.shell_sync("getenforce", timeout=8) or "").strip()
    except AdbError:
        enf = ""
    return {"mode": enf or ("Enforcing" if mode == "1" else "Permissive" if mode == "0" else None)}


def set_selinux(dctx, enforcing: bool) -> dict:
    try:
        dctx.adb.shell_sync(f"setenforce {1 if enforcing else 0}", su=True, timeout=10)
        return {"ok": True, "output": "SELinux " + ("Enforcing" if enforcing else "Permissive")}
    except AdbError as e:
        return {"ok": False, "output": str(e)}


# ---------------- build.prop / resetprop ----------------

def get_prop(dctx, key: str) -> dict:
    if not re.match(r"^[A-Za-z0-9._-]{1,128}\Z", key or ""):
        return {"ok": False, "output": "invalid prop key"}
    try:
        v = (dctx.adb.shell_sync(f"getprop {key}", timeout=8) or "").strip()
        return {"ok": True, "key": key, "value": v}
    except AdbError as e:
        return {"ok": False, "output": str(e)}


def set_prop(dctx, key: str, value: str) -> dict:
    if not re.match(r"^[A-Za-z0-9._-]{1,128}\Z", key or ""):
        return {"ok": False, "output": "invalid prop key"}
    value = str(value or "")
    if len(value) > 256 or "\n" in value or "'" in value:
        return {"ok": False, "output": "invalid value"}
    try:
        dctx.adb.shell_sync(f"resetprop {key} '{value}'", su=True, timeout=10)
        return {"ok": True, "output": f"{key} = {value} (until reboot)"}
    except AdbError as e:
        return {"ok": False, "output": str(e)}


# ---------------- Magisk modules ----------------

def modules(dctx) -> list[dict]:
    adb = dctx.adb
    try:
        ids = (adb.shell_sync(f"ls {_MODULES} 2>/dev/null", su=True, timeout=10) or "").split()
    except AdbError:
        return []
    out = []
    for mid in ids:
        if not _MODID_RE.match(mid):
            continue
        prop = _cat(adb, f"{_MODULES}/{mid}/module.prop")
        name = (re.search(r"^name=(.+)$", prop, re.M) or [None, mid])[1]
        ver = (re.search(r"^version=(.+)$", prop, re.M) or [None, ""])[1]
        disabled = adb.shell_sync(
            f"[ -f {_MODULES}/{mid}/disable ] && echo 1 || echo 0", su=True, timeout=8).strip() == "1"
        out.append({"id": mid, "name": name, "version": ver, "enabled": not disabled})
    out.sort(key=lambda m: m["id"].lower())
    return out


def set_module(dctx, module_id: str, enabled: bool) -> dict:
    if not _MODID_RE.match(module_id or ""):
        return {"ok": False, "output": "invalid module id"}
    adb = dctx.adb
    path = f"{_MODULES}/{module_id}/disable"
    try:
        if enabled:
            adb.shell_sync(f"rm -f {path}", su=True, timeout=10)
        else:
            adb.shell_sync(f"touch {path}", su=True, timeout=10)
        return {"ok": True, "output": f"{module_id} {'enabled' if enabled else 'disabled'} "
                                      "(reboot to apply)"}
    except AdbError as e:
        return {"ok": False, "output": str(e)}


# ---------------- persist current tuning ----------------

def _write_file(adb, path: str, content: str) -> None:
    """Write a file on the device via base64 (safe for any content) over su."""
    import base64
    b64 = base64.b64encode(content.encode()).decode()
    adb.shell_sync(f"echo {b64} | base64 -d > {path}", su=True, timeout=15)


def persist_tuning(dctx, enable: bool) -> dict:
    """Snapshot the current writable tunables into a service.d script so they are
    re-applied on every boot. enable=False removes it."""
    adb = dctx.adb
    if not enable:
        try:
            adb.shell_sync(f"rm -f {_TUNING_SH}", su=True, timeout=10)
            return {"ok": True, "output": "boot persistence removed"}
        except AdbError as e:
            return {"ok": False, "output": str(e)}
    from . import perf
    lines = ["#!/system/bin/sh", "# Sentinel: persisted kernel tuning", "sleep 30"]
    for knob in perf._KNOBS:  # noqa: SLF001 - same package
        try:
            row = perf._read_knob(adb, knob)  # noqa: SLF001
        except Exception:  # noqa: BLE001
            row = None
        if not row or row.get("value") in (None, ""):
            continue
        val = row["value"]
        path = knob["path"]
        if knob.get("per") in ("cpu", "block"):
            lines.append(f"for f in {path}; do echo {val} > $f 2>/dev/null; done")
        else:
            lines.append(f"echo {val} > {path} 2>/dev/null")
    script = "\n".join(lines) + "\n"
    try:
        adb.shell_sync(f"mkdir -p {_SVC_D}", su=True, timeout=10)
        _write_file(adb, _TUNING_SH, script)
        adb.shell_sync(f"chmod 755 {_TUNING_SH}", su=True, timeout=10)
        return {"ok": True, "output": f"persisted {len(lines) - 3} tunables to survive reboot"}
    except AdbError as e:
        return {"ok": False, "output": str(e)}


def persist_status(dctx) -> dict:
    exists = dctx.adb.shell_sync(
        f"[ -f {_TUNING_SH} ] && echo 1 || echo 0", su=True, timeout=8).strip() == "1"
    return {"persisted": exists}


# ---------------- display: refresh rate + KCAL color ----------------

def display_info(dctx) -> dict:
    adb = dctx.adb
    out: dict = {}
    try:
        dd = adb.shell_sync("dumpsys display", timeout=15) or ""
    except AdbError:
        dd = ""
    rates = sorted({int(round(float(m))) for m in re.findall(r"fps=([\d.]+)", dd)}, reverse=True)
    out["refresh_rates"] = rates
    act = re.search(r"mActiveSfDisplayMode=.*?refreshRate=([\d.]+)", dd)
    out["refresh_current"] = int(round(float(act.group(1)))) if act else None
    # KCAL (colour) — only on kernels that expose it
    kpath = ""
    for cand in ("/sys/devices/platform/kcal", "/sys/devices/virtual/graphics/fb0"):
        if adb.shell_sync(f"[ -e {cand}/kcal ] && echo 1 || echo 0", su=True, timeout=8).strip() == "1":
            kpath = cand
            break
    if kpath:
        out["kcal"] = {"path": kpath, "rgb": _cat(adb, f"{kpath}/kcal"),
                       "sat": _cat(adb, f"{kpath}/kcal_sat"), "val": _cat(adb, f"{kpath}/kcal_val")}
    return out


def set_refresh(dctx, hz: int) -> dict:
    try:
        h = int(hz)
    except (TypeError, ValueError):
        return {"ok": False, "output": "invalid refresh rate"}
    if not (24 <= h <= 240):
        return {"ok": False, "output": "refresh rate out of range"}
    try:
        dctx.adb.shell_sync(f"settings put system min_refresh_rate {h}.0", timeout=10)
        dctx.adb.shell_sync(f"settings put system peak_refresh_rate {h}.0", timeout=10)
        return {"ok": True, "output": f"refresh rate forced to {h} Hz"}
    except AdbError as e:
        return {"ok": False, "output": str(e)}


# ---------------- ZRAM ----------------

def zram_info(dctx) -> dict:
    adb = dctx.adb
    size = _int(_cat(adb, "/sys/block/zram0/disksize"))
    algo = _cat(adb, "/sys/block/zram0/comp_algorithm")
    cur = re.search(r"\[(\w+)\]", algo)
    return {"present": size is not None, "disksize_mb": round(size / 1048576) if size else 0,
            "algorithms": [a.strip("[]") for a in algo.split()] if algo else [],
            "algorithm": cur.group(1) if cur else (algo.split()[0] if algo else None)}


def set_zram(dctx, size_mb: int, algorithm: str | None = None) -> dict:
    """Resize ZRAM (swapoff, reset, set size, mkswap, swapon) and optionally set
    the compression algorithm. Reversible."""
    adb = dctx.adb
    try:
        mb = int(size_mb)
    except (TypeError, ValueError):
        return {"ok": False, "output": "invalid size"}
    if not (0 <= mb <= 8192):
        return {"ok": False, "output": "size must be 0-8192 MB"}
    try:
        adb.shell_sync("swapoff /dev/block/zram0 2>/dev/null || true", su=True, timeout=20)
        adb.shell_sync("echo 1 > /sys/block/zram0/reset", su=True, timeout=15)
        if algorithm and re.match(r"^[a-z0-9]{1,16}\Z", algorithm):
            adb.shell_sync(f"echo {algorithm} > /sys/block/zram0/comp_algorithm 2>/dev/null || true",
                           su=True, timeout=10)
        if mb > 0:
            adb.shell_sync(f"echo {mb * 1048576} > /sys/block/zram0/disksize", su=True, timeout=15)
            adb.shell_sync("mkswap /dev/block/zram0 2>/dev/null", su=True, timeout=20)
            adb.shell_sync("swapon /dev/block/zram0 2>/dev/null", su=True, timeout=20)
        return {"ok": True, "output": f"ZRAM set to {mb} MB" + (f" ({algorithm})" if algorithm else "")}
    except AdbError as e:
        return {"ok": False, "output": str(e)}


# ---------------- Private DNS ----------------

def dns_status(dctx) -> dict:
    adb = dctx.adb
    try:
        mode = (adb.shell_sync("settings get global private_dns_mode", timeout=8) or "").strip()
        host = (adb.shell_sync("settings get global private_dns_specifier", timeout=8) or "").strip()
    except AdbError:
        mode, host = "", ""
    return {"mode": None if mode in ("null", "") else mode,
            "hostname": None if host in ("null", "") else host}


def set_dns(dctx, mode: str, hostname: str = "") -> dict:
    """Private DNS: off | opportunistic | hostname (DNS-over-TLS)."""
    adb = dctx.adb
    if mode not in ("off", "opportunistic", "hostname"):
        return {"ok": False, "output": "mode must be off / opportunistic / hostname"}
    try:
        adb.shell_sync(f"settings put global private_dns_mode {mode}", timeout=10)
        if mode == "hostname":
            if not re.match(r"^[A-Za-z0-9.-]{3,253}\Z", hostname or ""):
                return {"ok": False, "output": "invalid DNS hostname"}
            adb.shell_sync(f"settings put global private_dns_specifier {hostname}", timeout=10)
        return {"ok": True, "output": "private DNS: " + mode + (f" ({hostname})" if mode == "hostname" else "")}
    except AdbError as e:
        return {"ok": False, "output": str(e)}


# ---------------- kernel modules + wakelocks ----------------

def kernel_modules(dctx) -> dict:
    try:
        out = dctx.adb.shell_sync("lsmod 2>/dev/null", su=True, timeout=12) or ""
    except AdbError:
        return {"modules": []}
    mods = []
    for line in out.splitlines()[1:]:
        p = line.split()
        if len(p) >= 2 and p[1].isdigit():
            mods.append({"name": p[0], "size": int(p[1]), "used_by": p[3] if len(p) > 3 and p[3] != "-" else ""})
    mods.sort(key=lambda m: m["size"], reverse=True)
    return {"modules": mods, "count": len(mods)}


def wakelocks(dctx) -> dict:
    """Top active kernel wakeup sources (best effort — debugfs may be locked)."""
    adb = dctx.adb
    txt = ""
    for path in ("/sys/kernel/debug/wakeup_sources", "/d/wakeup_sources"):
        txt = _cat(adb, path)
        if txt:
            break
    if not txt:
        return {"available": False, "wakelocks": []}
    rows = []
    lines = txt.splitlines()
    for line in lines[1:]:
        p = line.split()
        if len(p) >= 10 and p[0]:
            try:
                rows.append({"name": p[0], "active_count": int(p[1]),
                             "active_since_ms": int(p[6]) if p[6].isdigit() else 0})
            except (ValueError, IndexError):
                continue
    rows.sort(key=lambda r: r["active_count"], reverse=True)
    return {"available": True, "wakelocks": rows[:20]}
