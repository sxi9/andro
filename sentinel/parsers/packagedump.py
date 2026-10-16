"""Parse package inventory: `pm list packages` variants and `dumpsys package packages`."""
from __future__ import annotations

import re
from typing import Any

_PM_LINE = re.compile(
    r"^package:(?:(?P<path>.+?)=)?(?P<pkg>[A-Za-z0-9_.]+)"
    r"(?:\s+installer=(?P<inst>\S+))?"
    r"(?:\s+uid:(?P<uid>\d+(?:,\d+)*))?\s*$"   # Android 13+ lists every user: uid:10146,1010146
)


def parse_pm_list(text: str) -> dict[str, dict[str, Any]]:
    """`pm list packages -f -i -U [-3|-s]` → {pkg: {path, installer, uid}}."""
    out: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        m = _PM_LINE.match(line.strip())
        if not m:
            continue
        inst = m["inst"]
        if inst in ("null", ""):
            inst = None
        uids = [int(u) for u in m["uid"].split(",")] if m["uid"] else []
        out[m["pkg"]] = {
            "path": m["path"],
            "installer": inst,
            "uid": uids[0] if uids else None,   # owner's uid first; work-profile uids follow
            "uids": uids,
        }
    return out


_PKG_HDR = re.compile(r"^\s*Package \[([A-Za-z0-9_.]+)\]")
_VERSION = re.compile(r"\bversionCode=(\d+)")
_VNAME = re.compile(r"\bversionName=(\S+)")
_INSTALLER = re.compile(r"\binstallerPackageName=([A-Za-z0-9_.]+|null)")
_INITIATING = re.compile(r"\binitiatingPackageName=([A-Za-z0-9_.]+|null)")
_LAST_UPDATE = re.compile(r"\blastUpdateTime=([\d\- :.]+)")
_FLAGS = re.compile(r"\b(?:pkgFlags|flags)=\[\s*([^\]]*)\]")
_SIGS = re.compile(r"signatures=PackageSignatures\{[0-9a-fx]+\s+version:\d+,\s+signatures:\[([0-9a-fx, ]*)\]")
_PERM_GRANT = re.compile(r"^\s*([A-Za-z0-9_.\-]+):\s+granted=(true|false)"
                         r"(?:,\s*flags=\[\s*([^\]]*)\])?")
# "    User 0: ceDataInode=1 installed=true hidden=false suspended=false ... enabled=0"
_USER_STATE = re.compile(r"^\s*User (\d+):\s+(.*)$")
_KV = re.compile(r"(\w+)=(\S+)")
_USER_ID = re.compile(r"\b(?:userId|appId)=(\d+)")
_SHARED_USER = re.compile(r"\bsharedUser=(?:SharedUserSetting\{\S*\s+)?([A-Za-z][A-Za-z0-9_.]*)")
_PROCESS = re.compile(r"\bprocessName=([A-Za-z0-9_.:]+)")
_REQ_HDR = re.compile(r"^\s*requested permissions:")
_REQ_PERM = re.compile(r"^\s+([A-Za-z][A-Za-z0-9_.\-]+)(?::.*)?$")
_SECTION_END = re.compile(r"^\s*(install permissions:|runtime permissions:|User \d|"
                          r"declared permissions:|usesOptionalLibraries|libraries:|"
                          r"usesLibraries|dataDir=|timeStamp=|signatures=|splits=|"
                          r"enabled=|lastUpdateTime=|disabledComponents|enabledComponents)")
_DATA_DIR = re.compile(r"\bdataDir=(\S+)")
_TARGET_SDK = re.compile(r"\btargetSdk=(\d+)")
_MIN_SDK = re.compile(r"\bminSdk=(\d+)")
_FIRST_INSTALL = re.compile(r"\bfirstInstallTime=([\d\- :.]+)")
_ENABLED = re.compile(r"\benabled=(\d+)")
_ABI = re.compile(r"\bprimaryCpuAbi=(\S+)")
_COMP = re.compile(r"^\s+([A-Za-z][A-Za-z0-9_.$]+)\s*$")
# package enabled states: 0 default, 1 enabled -> on; 2/3/4 disabled -> off
_ENABLED_ON = {"0", "1"}


def parse_packages_dump(text: str) -> dict[str, dict[str, Any]]:
    """`dumpsys package packages` → per-package details.

    Returns {pkg: {version, version_name, installer, system, sig, last_update,
                   requested: [perm], granted: [perm], users: {id: {installed,
                   hidden, suspended, stopped, enabled_state}}, perm_flags:
                   {perm: [flag]}, uid, shared_user, process, ...}}
    Tolerant of version drift: unknown lines are ignored.
    """
    out: dict[str, dict[str, Any]] = {}
    cur: dict[str, Any] | None = None
    in_requested = False
    in_section = None  # "disabledComponents" | "enabledComponents"

    for line in text.splitlines():
        h = _PKG_HDR.match(line)
        if h:
            cur = out.setdefault(h.group(1), {
                "version": None, "version_name": None, "installer": None,
                "system": False, "sig": None, "last_update": None,
                "first_install": None, "data_dir": None, "target_sdk": None,
                "min_sdk": None, "abi": None, "enabled": True,
                "requested": [], "granted": [],
                "disabled_components": [], "enabled_components": [],
                "users": {}, "perm_flags": {}, "uid": None, "shared_user": None,
                "process": None,
            })
            in_requested = False
            in_section = None
            continue
        if cur is None:
            continue
        if line.strip() and not line[0].isspace():
            # a top-level header ("Shared users:", "Queries:", ...) ends the
            # Packages block: the shared-user section repeats "User N:" lines
            # and permission lists for the whole uid, with none of the
            # per-package state, and must not overwrite it
            cur = None
            in_requested = False
            in_section = None
            continue

        m = _USER_STATE.match(line)
        if m:
            kv = dict(_KV.findall(m.group(2)))
            try:
                cur["users"][int(m.group(1))] = {
                    "installed": kv.get("installed") == "true",
                    "hidden": kv.get("hidden") == "true",
                    "suspended": kv.get("suspended") == "true",
                    "stopped": kv.get("stopped") == "true",
                    "enabled_state": int(kv.get("enabled", "0") or 0),
                }
            except ValueError:
                pass

        if in_section:
            m = _COMP.match(line)
            if m and "." in m.group(1):
                cur[in_section].append(m.group(1))
                continue
            in_section = None  # fall through to normal parsing

        if in_requested:
            if _SECTION_END.match(line) or _PKG_HDR.match(line) or not line.strip():
                in_requested = False
            else:
                m = _REQ_PERM.match(line)
                if m and "." in m.group(1):
                    cur["requested"].append(m.group(1))
                    continue

        if _REQ_HDR.match(line):
            in_requested = True
            continue
        if line.strip().startswith("disabledComponents:"):
            in_section = "disabled_components"
            continue
        if line.strip().startswith("enabledComponents:"):
            in_section = "enabled_components"
            continue

        m = _ENABLED.search(line)
        if m:
            cur["enabled"] = m.group(1) in _ENABLED_ON
        m = _DATA_DIR.search(line)
        if m and cur["data_dir"] is None:
            cur["data_dir"] = m.group(1)
        m = _TARGET_SDK.search(line)
        if m and cur["target_sdk"] is None:
            cur["target_sdk"] = int(m.group(1))
        m = _MIN_SDK.search(line)
        if m and cur["min_sdk"] is None:
            cur["min_sdk"] = int(m.group(1))
        m = _ABI.search(line)
        if m and cur["abi"] is None and m.group(1) != "null":
            cur["abi"] = m.group(1)
        m = _FIRST_INSTALL.search(line)
        if m and cur["first_install"] is None:
            cur["first_install"] = m.group(1).strip()

        m = _VERSION.search(line)
        if m and cur["version"] is None:
            cur["version"] = int(m.group(1))
        m = _VNAME.search(line)
        if m and cur["version_name"] is None:
            cur["version_name"] = m.group(1)
        m = _INITIATING.search(line)
        if m and m.group(1) != "null":
            cur["installer"] = m.group(1)   # initiating pkg is the trustworthy one
        elif cur["installer"] is None:
            m = _INSTALLER.search(line)
            if m and m.group(1) != "null":
                cur["installer"] = m.group(1)
        m = _LAST_UPDATE.search(line)
        if m:
            cur["last_update"] = m.group(1).strip()
        m = _FLAGS.search(line)
        if m and "SYSTEM" in m.group(1):
            cur["system"] = True
        m = _SIGS.search(line)
        if m and cur["sig"] is None:
            cur["sig"] = m.group(1).replace(" ", "")
        m = _PERM_GRANT.match(line)
        if m and "permission" in m.group(1):
            if m.group(2) == "true" and m.group(1) not in cur["granted"]:
                cur["granted"].append(m.group(1))
            if m.group(3) is not None:
                cur["perm_flags"][m.group(1)] = [f.strip() for f in m.group(3).split("|")
                                                 if f.strip()]
        m = _USER_ID.search(line)
        if m and cur["uid"] is None:
            cur["uid"] = int(m.group(1))
        m = _SHARED_USER.search(line)
        if m and cur["shared_user"] is None and m.group(1) != "null":
            cur["shared_user"] = m.group(1)
        m = _PROCESS.search(line)
        if m and cur["process"] is None:
            cur["process"] = m.group(1)

    return out
