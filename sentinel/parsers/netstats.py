"""Parse `dumpsys netstats detail` — cumulative per-UID bytes, WiFi vs cellular.

The dump interleaves identity headers and history buckets:

    UID stats:
      ident=[{type=WIFI, subType=COMBINED, networkId="Home", metered=false, ...}] uid=10155 set=DEFAULT tag=0x0
        NetworkStatsHistory: bucketDuration=7200
          st=1760500800 rb=123456 rp=100 tb=23456 tp=80 op=0

We accumulate rb/tb per (uid, MOBILE|WIFI) for tag=0x0 buckets only
(tagged buckets double-count the untagged totals).
"""
from __future__ import annotations

import re
from collections import defaultdict

_IDENT = re.compile(r"ident=\[\{?type=([A-Z_]+)[^\]]*\]?\s*uid=(\d+)\s+set=(\S+)\s+tag=(\S+)")
_BUCKET = re.compile(r"\bst=\d+\s+rb=(\d+)\s+rp=\d+\s+tb=(\d+)")


def parse_netstats_detail(text: str) -> dict[int, dict[str, int]]:
    totals: dict[int, dict[str, int]] = defaultdict(
        lambda: {"wifi_rx": 0, "wifi_tx": 0, "mobile_rx": 0, "mobile_tx": 0})
    cur: tuple[int, str] | None = None  # (uid, 'wifi'|'mobile')
    for line in text.splitlines():
        m = _IDENT.search(line)
        if m:
            nettype, uid, _set, tag = m.groups()
            if tag not in ("0x0", "0"):
                cur = None
                continue
            kind = "mobile" if nettype.startswith("MOBILE") else (
                "wifi" if nettype.startswith("WIFI") else None)
            cur = (int(uid), kind) if kind else None
            continue
        if cur is None:
            continue
        b = _BUCKET.search(line)
        if b:
            uid, kind = cur
            totals[uid][f"{kind}_rx"] += int(b.group(1))
            totals[uid][f"{kind}_tx"] += int(b.group(2))
    return dict(totals)
