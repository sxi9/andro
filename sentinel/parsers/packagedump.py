"""Parse package inventory: `pm list packages` variants and `dumpsys package packages`."""
from __future__ import annotations

import re
from typing import Any

_PM_LINE = re.compile(
    r"^package:(?:(?P<path>.+?)=)?(?P<pkg>[A-Za-z0-9_.]+)"
    r"(?:\s+installer=(?P<inst>\S+))?"
    r"(?:\s+uid:(?P<uid>\d+))?\s*$"
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
        out[m["pkg"]] = {
            "path": m["path"],
            "installer": inst,
            "uid": int(m["uid"]) if m["uid"] else None,
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
_PERM_GRANT = re.compile(r"^\s*([A-Za-z0-9_.\-]+):\s+granted=(true|false)")
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
                   requested: [perm], granted: [perm]}}
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
            })
            in_requested = False
            in_section = None
            continue
        if cur is None:
            continue

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
        if m and m.group(2) == "true" and "permission" in m.group(1):
            if m.group(1) not in cur["granted"]:
                cur["granted"].append(m.group(1))

    return out
