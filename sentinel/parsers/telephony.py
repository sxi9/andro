"""Parse `dumpsys telephony.registry` — call state, data network type, serving cell."""
from __future__ import annotations

import re
from typing import Any

_CALL = re.compile(r"\bmCallState=(\d)")
_RAT = re.compile(r"RilDataRadioTechnology=\d+\(([A-Z0-9_]+)\)")
_RAT2 = re.compile(r"\bgetDataNetworkType\(\)=?(\d+)|\bmDataNetworkType=(\d+)")
_DISPLAY = re.compile(r"TelephonyDisplayInfo.*?network=([A-Z0-9_]+)")
_CI = re.compile(r"\bmCi=(\d+)")
_CID = re.compile(r"\bmCid=(\d+)")
_TAC = re.compile(r"\bmTac=(\d+)")
_LAC = re.compile(r"\bmLac=(\d+)")
_PCI = re.compile(r"\bmPci=(\d+)")
_OPER = re.compile(r'mOperatorAlphaLong=([^,\]]+)|mAlphaLong=([^,\s\]]+)')

CALL_STATES = {0: "idle", 1: "ringing", 2: "offhook"}

# TelephonyManager.NETWORK_TYPE_* constants
_NET_TYPES = {
    0: "UNKNOWN", 1: "GPRS", 2: "EDGE", 3: "UMTS", 4: "CDMA", 5: "EVDO_0",
    6: "EVDO_A", 7: "1xRTT", 8: "HSDPA", 9: "HSUPA", 10: "HSPA", 11: "IDEN",
    12: "EVDO_B", 13: "LTE", 14: "EHRPD", 15: "HSPAP", 16: "GSM",
    17: "TD_SCDMA", 18: "IWLAN", 19: "LTE_CA", 20: "NR",
}


def parse_telephony_registry(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {"call_state": None, "network_type": None, "cell": None,
                           "operator": None}
    m = _CALL.search(text)
    if m:
        out["call_state"] = CALL_STATES.get(int(m.group(1)), m.group(1))

    rats = _RAT.findall(text)
    if rats:
        out["network_type"] = rats[-1]
    else:
        m = _RAT2.search(text)
        if m:
            code = int(m.group(1) or m.group(2))
            out["network_type"] = _NET_TYPES.get(code)
        else:
            m = _DISPLAY.search(text)
            if m:
                out["network_type"] = m.group(1)

    cell: dict[str, int] = {}
    for rx, key in ((_CI, "ci"), (_CID, "ci"), (_TAC, "tac"), (_LAC, "tac"), (_PCI, "pci")):
        if key in cell:
            continue
        m = rx.search(text)
        if m:
            v = int(m.group(1))
            if 0 < v < 2**31 - 1:   # unset fields dump as 0 / 2147483647
                cell[key] = v
    if cell:
        out["cell"] = cell

    m = _OPER.search(text)
    if m:
        op = (m.group(1) or m.group(2) or "").strip()
        if op and op not in ("null", ""):
            out["operator"] = op
    return out
