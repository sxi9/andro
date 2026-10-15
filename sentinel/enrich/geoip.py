"""Optional offline GeoIP / ASN enrichment.

Uses MaxMind GeoLite2 .mmdb files via the `geoip2` package when both are
present; degrades to nothing otherwise. Lookups never leave this machine —
that's the point of using the offline database.
"""
from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger("sentinel.geoip")


class GeoIP:
    def __init__(self, city_db: Path | None = None, asn_db: Path | None = None) -> None:
        self._city = None
        self._asn = None
        try:
            import geoip2.database  # type: ignore
        except ImportError:
            if city_db or asn_db:
                log.warning("geoip2 package not installed; pip install geoip2 to enable GeoIP")
            return
        try:
            if city_db and Path(city_db).exists():
                self._city = geoip2.database.Reader(str(city_db))
            if asn_db and Path(asn_db).exists():
                self._asn = geoip2.database.Reader(str(asn_db))
        except Exception as e:  # unreadable db: run without it
            log.warning("GeoIP db open failed: %s", e)

    @property
    def enabled(self) -> bool:
        return self._city is not None or self._asn is not None

    def lookup(self, ip: str) -> dict:
        """Returns {} or any of: country, country_code, city, org, asn."""
        out: dict = {}
        if self._city:
            try:
                r = self._city.city(ip)
                if r.country.iso_code:
                    out["country_code"] = r.country.iso_code
                    out["country"] = r.country.name or r.country.iso_code
                if r.city.name:
                    out["city"] = r.city.name
            except Exception:
                pass
        if self._asn:
            try:
                r = self._asn.asn(ip)
                if r.autonomous_system_organization:
                    out["org"] = r.autonomous_system_organization
                    out["asn"] = r.autonomous_system_number
            except Exception:
                pass
        return out

    def close(self) -> None:
        for r in (self._city, self._asn):
            try:
                if r:
                    r.close()
            except Exception:
                pass
