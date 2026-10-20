"""Device performance actions for the owner's own device.

On-demand reads (kernel log, tunables) and state-changing actions (free memory,
kill a process, set a tunable) that the Performance tab calls. Everything that
mutates runs over the device's own ADB, needs root for the kernel/VM bits, and
is validated here (no open shell, whitelisted knobs). All failures degrade to an
{ok: false, output} dict rather than raising to the route.

The tuning registry (`_KNOBS`) is declarative and auto-detecting: each knob names
a sysfs/proc path and a kind, is read on every refresh, and is only shown when it
exists on this device. It covers VM, the CPU (governor + over/under-clock via the
frequency caps), GPU, I/O, network, voltage (where a custom kernel exposes it),
and the display (resolution / density via `wm`). Writes go to every matching core
or block device.
"""
from __future__ import annotations

import re

from ..adb.client import AdbError
from ..parsers.perf import parse_meminfo, parse_top, parse_cpu_summary

_PKG_RE = re.compile(r"^[A-Za-z0-9_.]+$")


# ---- declarative tuning registry -------------------------------------------
# kind: int | enum | str | freq (int kHz, options from scaling_available_*)
# per:  None | "cpu" (cpu* glob) | "block" (/sys/block/* glob)
# opts: a fixed list, or "@<path>" to read a space-separated options file, or
#       "scheduler" to parse the bracketed /sys/block/*/queue/scheduler format.
_KNOBS = [
    # --- Memory / VM ---
    {"key": "swappiness", "label": "Swappiness", "group": "Memory", "unit": "0-200",
     "path": "/proc/sys/vm/swappiness", "kind": "int", "min": 0, "max": 200},
    {"key": "vfs_cache_pressure", "label": "VFS cache pressure", "group": "Memory",
     "path": "/proc/sys/vm/vfs_cache_pressure", "kind": "int", "min": 0, "max": 1000},
    {"key": "dirty_ratio", "label": "Dirty ratio", "group": "Memory", "unit": "%",
     "path": "/proc/sys/vm/dirty_ratio", "kind": "int", "min": 0, "max": 100},
    {"key": "dirty_background_ratio", "label": "Dirty background ratio", "group": "Memory", "unit": "%",
     "path": "/proc/sys/vm/dirty_background_ratio", "kind": "int", "min": 0, "max": 100},
    {"key": "min_free_kbytes", "label": "Min free", "group": "Memory", "unit": "kB",
     "path": "/proc/sys/vm/min_free_kbytes", "kind": "int", "min": 1024, "max": 1048576},
    {"key": "page_cluster", "label": "Page cluster", "group": "Memory",
     "path": "/proc/sys/vm/page-cluster", "kind": "int", "min": 0, "max": 10},
    {"key": "overcommit_memory", "label": "Overcommit", "group": "Memory",
     "path": "/proc/sys/vm/overcommit_memory", "kind": "enum", "opts": ["0", "1", "2"]},

    # --- CPU: governor + over/under-clock via the frequency caps (per core) ---
    {"key": "cpu_governor", "label": "CPU governor", "group": "CPU", "per": "cpu",
     "path": "/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor", "kind": "enum",
     "opts": "@/sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors"},
    {"key": "cpu_max_freq", "label": "CPU max freq (overclock cap)", "group": "CPU", "per": "cpu", "unit": "kHz",
     "path": "/sys/devices/system/cpu/cpu*/cpufreq/scaling_max_freq", "kind": "freq",
     "opts": "@/sys/devices/system/cpu/cpu0/cpufreq/scaling_available_frequencies"},
    {"key": "cpu_min_freq", "label": "CPU min freq (underclock floor)", "group": "CPU", "per": "cpu", "unit": "kHz",
     "path": "/sys/devices/system/cpu/cpu*/cpufreq/scaling_min_freq", "kind": "freq",
     "opts": "@/sys/devices/system/cpu/cpu0/cpufreq/scaling_available_frequencies"},

    # --- GPU (Adreno/kgsl where present) ---
    {"key": "gpu_governor", "label": "GPU governor", "group": "GPU",
     "path": "/sys/class/kgsl/kgsl-3d0/devfreq/governor", "kind": "enum",
     "opts": "@/sys/class/kgsl/kgsl-3d0/devfreq/available_governors"},
    {"key": "gpu_max_freq", "label": "GPU max freq (overclock)", "group": "GPU", "unit": "Hz",
     "path": "/sys/class/kgsl/kgsl-3d0/devfreq/max_freq", "kind": "enum",
     "opts": "@/sys/class/kgsl/kgsl-3d0/devfreq/available_frequencies"},
    {"key": "gpu_min_freq", "label": "GPU min freq", "group": "GPU", "unit": "Hz",
     "path": "/sys/class/kgsl/kgsl-3d0/devfreq/min_freq", "kind": "enum",
     "opts": "@/sys/class/kgsl/kgsl-3d0/devfreq/available_frequencies"},
    {"key": "gpu_throttling", "label": "GPU thermal throttling", "group": "GPU",
     "path": "/sys/class/kgsl/kgsl-3d0/throttling", "kind": "enum", "opts": ["0", "1"]},

    # --- CPU voltage (undervolt / overvolt) — only on kernels that expose it ---
    {"key": "uv_table", "label": "CPU voltage table (UV/OV mV)", "group": "Voltage",
     "path": "/sys/devices/system/cpu/cpu0/cpufreq/UV_mV_table", "kind": "str"},
    {"key": "vdd_levels", "label": "VDD levels (UV/OV)", "group": "Voltage",
     "path": "/sys/devices/system/cpu/cpufreq/vdd_table/vdd_levels", "kind": "str"},
    {"key": "gpu_uv", "label": "GPU voltage table", "group": "Voltage",
     "path": "/sys/class/kgsl/kgsl-3d0/devfreq/gpu_vdd_table", "kind": "str"},

    # --- I/O (per block device) ---
    {"key": "io_scheduler", "label": "I/O scheduler", "group": "I/O", "per": "block",
     "path": "/sys/block/*/queue/scheduler", "kind": "enum", "opts": "scheduler"},
    {"key": "read_ahead_kb", "label": "Read-ahead", "group": "I/O", "per": "block", "unit": "kB",
     "path": "/sys/block/*/queue/read_ahead_kb", "kind": "int", "min": 0, "max": 16384},
    {"key": "nr_requests", "label": "Queue depth", "group": "I/O", "per": "block",
     "path": "/sys/block/*/queue/nr_requests", "kind": "int", "min": 4, "max": 2048},

    # --- Network ---
    {"key": "tcp_congestion", "label": "TCP congestion control", "group": "Network",
     "path": "/proc/sys/net/ipv4/tcp_congestion_control", "kind": "enum",
     "opts": "@/proc/sys/net/ipv4/tcp_available_congestion_control"},
    {"key": "default_qdisc", "label": "Default qdisc", "group": "Network",
     "path": "/proc/sys/net/core/default_qdisc", "kind": "str"},
    {"key": "tcp_fastopen", "label": "TCP fast open", "group": "Network",
     "path": "/proc/sys/net/ipv4/tcp_fastopen", "kind": "int", "min": 0, "max": 3},

    # --- Kernel ---
    {"key": "panic_timeout", "label": "Panic reboot timeout", "group": "Kernel", "unit": "s",
     "path": "/proc/sys/kernel/panic", "kind": "int", "min": 0, "max": 300},
    {"key": "randomize_va", "label": "ASLR", "group": "Kernel",
     "path": "/proc/sys/kernel/randomize_va_space", "kind": "enum", "opts": ["0", "1", "2"]},
    {"key": "perf_paranoid", "label": "perf_event_paranoid", "group": "Kernel",
     "path": "/proc/sys/kernel/perf_event_paranoid", "kind": "int", "min": -1, "max": 4},
    {"key": "printk", "label": "printk levels", "group": "Kernel",
     "path": "/proc/sys/kernel/printk", "kind": "str"},
]
_BY_KEY = {k["key"]: k for k in _KNOBS}
# knobs edited through `wm` rather than a file
_DISPLAY = {"display_size", "display_density"}


def snapshot(dctx) -> dict:
    adb = dctx.adb
    mem = parse_meminfo(adb.shell_sync("cat /proc/meminfo", timeout=15))
    top = adb.shell_sync("top -b -n1 -m 20 -s 5", timeout=20)
    return {"mem": mem, "cpu": parse_cpu_summary(top), "procs": parse_top(top, 20)}


def kernel_log(dctx, lines: int = 400) -> dict:
    adb = dctx.adb
    lines = max(50, min(int(lines or 400), 2000))
    text = ""
    try:
        text = adb.shell_sync("dmesg", su=True, timeout=20)
    except AdbError:
        text = ""
    if not text.strip():
        try:
            text = adb.shell_sync(f"logcat -b kernel -d -t {lines}", timeout=20)
        except AdbError as e:
            return {"ok": False, "output": str(e), "lines": []}
    rows = [ln for ln in text.splitlines() if ln.strip()][-lines:]
    sev = re.compile(r"\b(SIGSEGV|SIGABRT|panic|oom|lowmemorykiller|out of memory|"
                     r"fatal|segfault|thermal|throttl|killing|watchdog)\b", re.I)
    out = [{"text": ln, "warn": bool(sev.search(ln))} for ln in rows]
    return {"ok": True, "lines": out, "count": len(out)}


def free_memory(dctx) -> dict:
    adb = dctx.adb
    before = parse_meminfo(adb.shell_sync("cat /proc/meminfo", timeout=15))
    steps: list[str] = []
    try:
        adb.shell_sync("am kill-all", timeout=25)
        steps.append("killed background apps")
    except AdbError as e:
        steps.append(f"am kill-all failed: {e}")
    for cmd, label in (
        ("sync; echo 3 > /proc/sys/vm/drop_caches", "dropped page cache"),
        ("echo 1 > /proc/sys/vm/compact_memory", "compacted memory"),
    ):
        try:
            adb.shell_sync(cmd, su=True, timeout=20)
            steps.append(label)
        except AdbError as e:
            steps.append(f"{label} failed (root?): {e}")
    after = parse_meminfo(adb.shell_sync("cat /proc/meminfo", timeout=15))
    freed = after.get("mem_available", 0) - before.get("mem_available", 0)
    return {"ok": True, "freed": freed, "before": before, "after": after, "steps": steps}


def kill_process(dctx, *, pid: int | None = None, package: str | None = None) -> dict:
    adb = dctx.adb
    if package:
        if not _PKG_RE.match(package):
            return {"ok": False, "output": "invalid package name"}
        try:
            adb.shell_sync(f"am force-stop {package}", timeout=20)
            return {"ok": True, "output": f"force-stopped {package}"}
        except AdbError as e:
            return {"ok": False, "output": str(e)}
    if pid is not None:
        try:
            p = int(pid)
        except (TypeError, ValueError):
            return {"ok": False, "output": "invalid pid"}
        if p <= 100:
            return {"ok": False, "output": "refusing to kill a system/low pid"}
        try:
            adb.shell_sync(f"kill {p}", su=True, timeout=15)
            return {"ok": True, "output": f"killed pid {p}"}
        except AdbError as e:
            return {"ok": False, "output": str(e)}
    return {"ok": False, "output": "pid or package required"}


# ---- tunables (read) --------------------------------------------------------

def _cat(adb, path: str) -> str:
    """Read a file, root first (most tuning knobs are root-only to read)."""
    for su in (True, False):
        try:
            v = (adb.shell_sync(f"cat {path} 2>/dev/null", su=su, timeout=8) or "").strip()
            if v:
                return v
        except AdbError:
            continue
    return ""


def _first_path(adb, glob: str) -> str:
    """Resolve the first real path for a cpu*/block* glob (to read one value)."""
    try:
        out = (adb.shell_sync(f"ls -d {glob} 2>/dev/null", su=True, timeout=8) or "").strip()
        return out.splitlines()[0].strip() if out else ""
    except AdbError:
        return ""


def _options(adb, knob: dict) -> list[str]:
    opts = knob.get("opts")
    if isinstance(opts, list):
        return opts
    if opts == "scheduler":
        raw = _cat(adb, _first_path(adb, knob["path"]) or knob["path"])
        # "noop deadline [cfq]" -> list incl. the bracketed current
        return [t.strip("[]") for t in raw.split()] if raw else []
    if isinstance(opts, str) and opts.startswith("@"):
        raw = _cat(adb, opts[1:])
        return raw.split() if raw else []
    return []


def _read_knob(adb, knob: dict) -> dict | None:
    path = knob["path"]
    if knob.get("per") in ("cpu", "block"):
        real = _first_path(adb, path)
        if not real:
            return None
        val = _cat(adb, real)
    else:
        val = _cat(adb, path)
    if val == "":
        return None
    # scheduler value comes bracketed: pull the active one out
    cur = val
    if knob.get("opts") == "scheduler":
        m = re.search(r"\[(\w+)\]", val)
        cur = m.group(1) if m else val.split()[0]
    row = {"key": knob["key"], "label": knob["label"], "group": knob["group"],
           "kind": knob["kind"], "value": cur, "unit": knob.get("unit", "")}
    if knob["kind"] in ("enum", "freq"):
        row["options"] = _options(adb, knob)
    if knob["kind"] == "int":
        row["min"] = knob.get("min")
        row["max"] = knob.get("max")
    return row


def _display(adb) -> list[dict]:
    rows: list[dict] = []
    try:
        size = (adb.shell_sync("wm size", timeout=10) or "").strip()
        m = re.search(r"(Override|Physical) size:\s*(\d+x\d+)", size)
        if m:
            rows.append({"key": "display_size", "label": "Screen resolution", "group": "Display",
                         "kind": "str", "value": m.group(2), "unit": "WxH (or 'reset')"})
    except AdbError:
        pass
    try:
        dens = (adb.shell_sync("wm density", timeout=10) or "").strip()
        m = re.search(r"(Override|Physical) density:\s*(\d+)", dens)
        if m:
            rows.append({"key": "display_density", "label": "Screen density", "group": "Display",
                         "kind": "int", "value": m.group(2), "unit": "dpi (or 'reset')",
                         "min": 120, "max": 640})
    except AdbError:
        pass
    return rows


def tunables(dctx) -> dict:
    """Every knob that exists on this device, grouped, with current value and
    (for enums/freqs) the allowed options. Absent knobs are silently skipped."""
    adb = dctx.adb
    rows: list[dict] = []
    for knob in _KNOBS:
        try:
            r = _read_knob(adb, knob)
        except Exception:  # noqa: BLE001 - a bad knob never breaks the whole read
            r = None
        if r:
            rows.append(r)
    rows.extend(_display(adb))
    groups: dict[str, list] = {}
    for r in rows:
        groups.setdefault(r["group"], []).append(r)
    order = ["Memory", "CPU", "GPU", "Voltage", "I/O", "Network", "Kernel", "Display"]
    out = [{"name": g, "knobs": groups[g]} for g in order if g in groups]
    # keep the legacy flat fields the first UI used, so nothing breaks
    sw = next((r for r in rows if r["key"] == "swappiness"), None)
    gov = next((r for r in rows if r["key"] == "cpu_governor"), None)
    return {
        "ok": True, "groups": out,
        "swappiness": int(sw["value"]) if sw and sw["value"].isdigit() else None,
        "governor": gov["value"] if gov else None,
        "governors": gov.get("options", []) if gov else [],
    }


# ---- tunables (write) -------------------------------------------------------

# ---- one-tap profiles -------------------------------------------------------
# Each value is either a priority list (first option the device supports wins) or
# a freq keyword: "max" | "mid" | "min" (resolved from the device's own freqs).
_PROFILES = {
    "performance": {
        "cpu_governor": ["performance", "schedutil", "interactive"],
        "cpu_max_freq": "max", "cpu_min_freq": "mid",
        "swappiness": "10", "vfs_cache_pressure": "50", "read_ahead_kb": "512",
        "io_scheduler": ["mq-deadline", "deadline", "kyber", "none"],
        "gpu_governor": ["performance", "msm-adreno-tz"], "gpu_max_freq": "max",
    },
    "balanced": {
        "cpu_governor": ["schedutil", "interactive", "ondemand"],
        "cpu_max_freq": "max", "cpu_min_freq": "min",
        "swappiness": "60", "vfs_cache_pressure": "100", "read_ahead_kb": "128",
        "io_scheduler": ["mq-deadline", "deadline", "none"],
        "gpu_governor": ["msm-adreno-tz", "simple_ondemand", "schedutil"],
    },
    "powersave": {
        "cpu_governor": ["powersave", "schedutil", "conservative"],
        "cpu_max_freq": "mid", "cpu_min_freq": "min",
        "swappiness": "100", "vfs_cache_pressure": "120", "read_ahead_kb": "64",
        "io_scheduler": ["none", "mq-deadline"],
        "gpu_governor": ["powersave", "msm-adreno-tz"], "gpu_min_freq": "min",
    },
}


def _resolve_spec(adb, knob: dict, spec) -> str | None:
    """Turn a profile spec into a concrete value for this device's knob."""
    if isinstance(spec, list):
        opts = _options(adb, knob)
        for s in spec:
            if not opts or s in opts:
                return s
        return None
    if spec in ("max", "mid", "min"):
        freqs = sorted(int(x) for x in _options(adb, knob) if x.isdigit())
        if not freqs:
            return None
        return str(freqs[-1] if spec == "max" else freqs[0] if spec == "min"
                   else freqs[len(freqs) // 2])
    return str(spec)


def apply_profile(dctx, profile: str) -> dict:
    """Apply a curated batch of tunables for performance / balanced / powersave.
    Only touches knobs this device actually has; each write is still validated."""
    prof = _PROFILES.get(str(profile))
    if not prof:
        return {"ok": False, "output": f"unknown profile: {profile}"}
    adb = dctx.adb
    applied: list[str] = []
    skipped: list[str] = []
    for key, spec in prof.items():
        knob = _BY_KEY.get(key)
        if not knob or _read_knob(adb, knob) is None:
            skipped.append(key)
            continue
        val = _resolve_spec(adb, knob, spec)
        if val is None:
            skipped.append(key)
            continue
        r = set_tunable(dctx, key, val)
        (applied if r.get("ok") else skipped).append(key + "=" + val if r.get("ok") else key)
    return {"ok": True, "profile": profile, "applied": applied, "skipped": skipped,
            "output": f"{profile}: applied {len(applied)} knob(s)"
                      + (f", skipped {len(skipped)}" if skipped else "")}


def set_tunable(dctx, key: str, value: str) -> dict:
    """Write one whitelisted knob (root), applying to every matching core/block.
    Display knobs go through `wm`. Everything is validated against the registry
    and the device's own allowed options."""
    adb = dctx.adb
    key = str(key or "")
    value = str(value or "").strip()

    # display: resolution / density via wm (reversible with 'reset')
    if key == "display_size":
        if value.lower() == "reset":
            cmd = "wm size reset"
        elif re.match(r"^\d{3,5}x\d{3,5}$", value):
            cmd = f"wm size {value}"
        else:
            return {"ok": False, "output": "resolution must be WxH (e.g. 1080x2400) or 'reset'"}
        try:
            adb.shell_sync(cmd, timeout=15)
            return {"ok": True, "output": cmd}
        except AdbError as e:
            return {"ok": False, "output": str(e)}
    if key == "display_density":
        if value.lower() == "reset":
            cmd = "wm density reset"
        elif value.isdigit() and 120 <= int(value) <= 640:
            cmd = f"wm density {int(value)}"
        else:
            return {"ok": False, "output": "density must be 120-640 dpi or 'reset'"}
        try:
            adb.shell_sync(cmd, timeout=15)
            return {"ok": True, "output": cmd}
        except AdbError as e:
            return {"ok": False, "output": str(e)}

    knob = _BY_KEY.get(key)
    if not knob:
        return {"ok": False, "output": f"unknown tunable: {key}"}
    kind = knob["kind"]

    # validate the value against the knob
    if kind == "int":
        if not re.match(r"^-?\d+$", value):
            return {"ok": False, "output": f"{knob['label']} must be an integer"}
        n = int(value)
        lo, hi = knob.get("min"), knob.get("max")
        if (lo is not None and n < lo) or (hi is not None and n > hi):
            return {"ok": False, "output": f"{knob['label']} must be {lo}-{hi}"}
        value = str(n)
    elif kind == "freq":
        if not value.isdigit():
            return {"ok": False, "output": f"{knob['label']} must be a frequency (kHz)"}
        opts = _options(adb, knob)
        if opts and value not in opts:
            return {"ok": False, "output": f"frequency must be one of: {', '.join(opts)}"}
    elif kind == "enum":
        opts = _options(adb, knob)
        if opts and value not in opts:
            return {"ok": False, "output": f"must be one of: {', '.join(opts) or 'n/a'}"}
    elif kind == "str":
        if len(value) > 200 or "\n" in value or "'" in value:
            return {"ok": False, "output": "invalid value"}

    # write it — to every matching core/block for per-* knobs
    path = knob["path"]
    if knob.get("per") in ("cpu", "block"):
        cmd = f"for f in {path}; do echo {value} > $f 2>/dev/null; done"
    else:
        cmd = f"echo {value} > {path}"
    try:
        adb.shell_sync(cmd, su=True, timeout=20)
    except AdbError as e:
        return {"ok": False, "output": str(e)}
    # read back the first instance to confirm it stuck
    back = _read_knob(adb, knob)
    got = back["value"] if back else "?"
    return {"ok": True, "output": f"{knob['label']} = {got}", "value": got}
