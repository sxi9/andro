"""Known advertising / analytics endpoint matching (hostname suffix match).

A deliberately compact built-in list of the trackers that dominate mobile
telemetry. Extend it with one domain per line in <data_dir>/trackers.txt.
Matching is suffix-based: "appsflyer.com" matches "wd.a.appsflyer.com".
"""
from __future__ import annotations

from pathlib import Path

BUILTIN = {
    # measurement / attribution
    "appsflyer.com": "AppsFlyer", "adjust.com": "Adjust", "adjust.io": "Adjust",
    "branch.io": "Branch", "kochava.com": "Kochava", "singular.net": "Singular",
    "amplitude.com": "Amplitude", "mixpanel.com": "Mixpanel", "segment.io": "Segment",
    "segment.com": "Segment", "app-measurement.com": "Google Analytics",
    "google-analytics.com": "Google Analytics", "googletagmanager.com": "Google Tag Manager",
    "crashlytics.com": "Crashlytics", "flurry.com": "Flurry (Yahoo)",
    "appmetrica.yandex.net": "Yandex AppMetrica", "mc.yandex.ru": "Yandex Metrica",
    # ads
    "doubleclick.net": "Google Ads", "googlesyndication.com": "Google Ads",
    "googleadservices.com": "Google Ads", "adservice.google.com": "Google Ads",
    "applovin.com": "AppLovin", "unityads.unity3d.com": "Unity Ads",
    "ironsrc.com": "ironSource", "ironsrc.mobi": "ironSource",
    "supersonicads.com": "ironSource", "vungle.com": "Vungle",
    "chartboost.com": "Chartboost", "inmobi.com": "InMobi", "mopub.com": "MoPub",
    "adcolony.com": "AdColony", "criteo.com": "Criteo", "criteo.net": "Criteo",
    "taboola.com": "Taboola", "outbrain.com": "Outbrain",
    "scorecardresearch.com": "comScore", "startappservice.com": "Start.io",
    "pangle.io": "Pangle (ByteDance)", "amazon-adsystem.com": "Amazon Ads",
    # social SDKs' measurement endpoints
    "graph.facebook.com": "Meta Graph/SDK", "app.adjust.world": "Adjust",
    "business-api.tiktok.com": "TikTok Business SDK",
}


class TrackerMatcher:
    def __init__(self, extra_file: Path | None = None) -> None:
        self._map = dict(BUILTIN)
        if extra_file and extra_file.exists():
            for line in extra_file.read_text(errors="replace").splitlines():
                d = line.strip().lower()
                if d and not d.startswith("#"):
                    self._map.setdefault(d, d)

    def match(self, host: str | None) -> str | None:
        """Returns the tracker name when host matches a known suffix."""
        if not host:
            return None
        h = host.lower().rstrip(".")
        parts = h.split(".")
        for i in range(len(parts) - 1):
            cand = ".".join(parts[i:])
            if cand in self._map:
                return self._map[cand]
        return None

    def count(self) -> int:
        return len(self._map)
