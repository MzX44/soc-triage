#!/usr/bin/env python3
"""
connectors.py  --  pluggable enrichment sources for soc-triage.

A connector takes an indicator (IP or domain) and returns a NORMALISED verdict
so the scoring layer never has to know a vendor's private JSON shape:

    {
      "source":   "VirusTotal",
      "available": True,            # could we reach/authenticate the source?
      "found":     True,            # did the source have a record?
      "verdict":   "malicious" | "suspicious" | "clean" | "unknown",
      "weight":    "strong" | "weak" | "none",   # how confident THIS source is
      "detail":    "1/94 vendors malicious",      # human-readable one-liner
      "raw":       {...},           # trimmed source-specific fields
    }

New sources are added two ways, neither of which touches the scoring code:
  * a small subclass (see AbuseIPDBConnector), or
  * zero code at all via GenericRestConnector, configured in config.yaml.

This is what makes the tool vendor-agnostic: a buyer points it at their own
feeds by editing YAML, not Python.
"""
from __future__ import annotations

import os
import ipaddress
from typing import Any

import requests

HTTP_TIMEOUT = 30

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def is_internal_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return any(ip in net for net in _PRIVATE_NETS)


def _unavailable(source: str, note: str) -> dict[str, Any]:
    return {"source": source, "available": False, "found": False,
            "verdict": "unknown", "weight": "none", "detail": note, "raw": {}}


# --------------------------------------------------------------------------- #
# Base class + registry
# --------------------------------------------------------------------------- #
class Connector:
    """Base class. Subclasses set `name`, `supports`, and implement query()."""
    name: str = "connector"
    supports: tuple[str, ...] = ()          # e.g. ("ip", "domain")

    def __init__(self, *, api_key: str | None = None, **opts: Any) -> None:
        self.api_key = api_key
        self.opts = opts

    def handles(self, indicator_type: str) -> bool:
        return indicator_type in self.supports

    def query(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        raise NotImplementedError

    # Shared HTTP helper.
    def _get(self, url: str, **kw: Any) -> requests.Response | None:
        kw.setdefault("timeout", HTTP_TIMEOUT)
        try:
            return requests.get(url, **kw)
        except requests.RequestException:
            return None


_REGISTRY: dict[str, type[Connector]] = {}


def register(cls: type[Connector]) -> type[Connector]:
    _REGISTRY[cls.name] = cls
    return cls


def build(name: str, **opts: Any) -> Connector:
    if name not in _REGISTRY:
        raise KeyError(f"unknown connector type '{name}'. Known: {sorted(_REGISTRY)}")
    return _REGISTRY[name](**opts)


# --------------------------------------------------------------------------- #
# VirusTotal
# --------------------------------------------------------------------------- #
@register
class VirusTotalConnector(Connector):
    name = "virustotal"
    supports = ("ip", "domain")

    def query(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        if indicator_type == "ip" and is_internal_ip(indicator):
            return {"source": "VirusTotal", "available": False, "found": False,
                    "verdict": "unknown", "weight": "none",
                    "detail": f"{indicator} is internal/CGNAT; not queried.", "raw": {}}
        if not self.api_key:
            return _unavailable("VirusTotal", "VIRUSTOTAL_API_KEY not set.")
        path = "ip_addresses" if indicator_type == "ip" else "domains"
        r = self._get(f"https://www.virustotal.com/api/v3/{path}/{indicator.strip().strip('.')}",
                      headers={"x-apikey": self.api_key})
        if r is None:
            return _unavailable("VirusTotal", "unreachable.")
        if r.status_code == 404:
            return {"source": "VirusTotal", "available": True, "found": False,
                    "verdict": "unknown", "weight": "none", "detail": "no record.", "raw": {}}
        if r.status_code != 200:
            return _unavailable("VirusTotal", f"HTTP {r.status_code}.")
        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        mal, susp = stats.get("malicious", 0), stats.get("suspicious", 0)
        total = sum(v for v in stats.values() if isinstance(v, int)) or 0
        if mal >= 3:
            verdict, weight = "malicious", "strong"
        elif mal >= 1:
            verdict, weight = "malicious", "weak"
        elif susp >= 1:
            verdict, weight = "suspicious", "weak"
        else:
            verdict, weight = "clean", "none"
        return {
            "source": "VirusTotal", "available": True, "found": True,
            "verdict": verdict, "weight": weight,
            "detail": f"{mal}/{total or '?'} vendors malicious"
                      + (f", {susp} suspicious" if susp else ""),
            "raw": {"malicious": mal, "suspicious": susp, "as_owner": attrs.get("as_owner"),
                    "country": attrs.get("country"), "creation_date": attrs.get("creation_date")},
        }


# --------------------------------------------------------------------------- #
# AbuseIPDB  (free API; corroborates IP reputation -> kills lone-vendor noise)
# --------------------------------------------------------------------------- #
@register
class AbuseIPDBConnector(Connector):
    name = "abuseipdb"
    supports = ("ip",)

    def query(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        if is_internal_ip(indicator):
            return {"source": "AbuseIPDB", "available": False, "found": False,
                    "verdict": "unknown", "weight": "none",
                    "detail": f"{indicator} is internal/CGNAT; not queried.", "raw": {}}
        if not self.api_key:
            return _unavailable("AbuseIPDB", "ABUSEIPDB_API_KEY not set.")
        r = self._get("https://api.abuseipdb.com/api/v2/check",
                      headers={"Key": self.api_key, "Accept": "application/json"},
                      params={"ipAddress": indicator, "maxAgeInDays": 90})
        if r is None:
            return _unavailable("AbuseIPDB", "unreachable.")
        if r.status_code != 200:
            return _unavailable("AbuseIPDB", f"HTTP {r.status_code}.")
        d = r.json().get("data", {})
        conf = int(d.get("abuseConfidenceScore", 0))
        reports = int(d.get("totalReports", 0))
        if conf >= 50:
            verdict, weight = "malicious", "strong"
        elif conf >= 25:
            verdict, weight = "malicious", "weak"
        elif conf > 0:
            verdict, weight = "suspicious", "weak"
        else:
            verdict, weight = "clean", "none"
        return {
            "source": "AbuseIPDB", "available": True, "found": True,
            "verdict": verdict, "weight": weight,
            "detail": f"abuse confidence {conf}% from {reports} report(s)",
            "raw": {"abuseConfidenceScore": conf, "totalReports": reports,
                    "countryCode": d.get("countryCode"), "isp": d.get("isp"),
                    "usageType": d.get("usageType")},
        }


# --------------------------------------------------------------------------- #
# Generic REST connector -- add any key-auth HTTP API with zero new code.
# --------------------------------------------------------------------------- #
@register
class GenericRestConnector(Connector):
    """Configured entirely from YAML. Example config.yaml entry:

        - type: generic_rest
          name: MyFeed
          supports: [ip, domain]
          url: "https://api.myfeed.test/v1/lookup/{indicator}"
          auth_header: "X-Api-Key"
          api_key_env: MYFEED_API_KEY
          malicious_field: "data.malicious_count"   # dotted path into the JSON
          malicious_strong_at: 3                     # >= this -> strong
    """
    name = "generic_rest"
    supports = ()  # set per-instance from config

    def __init__(self, *, display_name: str = "GenericFeed", url: str = "",
                 supports: list[str] | None = None, auth_header: str | None = None,
                 malicious_field: str = "", malicious_strong_at: int = 3,
                 api_key: str | None = None, **opts: Any) -> None:
        super().__init__(api_key=api_key, **opts)
        self.display_name = display_name
        self.url = url
        self.supports = tuple(supports or ())
        self.auth_header = auth_header
        self.malicious_field = malicious_field
        self.malicious_strong_at = malicious_strong_at

    @staticmethod
    def _dig(obj: Any, dotted: str) -> Any:
        for part in dotted.split("."):
            if isinstance(obj, dict):
                obj = obj.get(part)
            else:
                return None
        return obj

    def query(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        if indicator_type == "ip" and is_internal_ip(indicator):
            return {"source": self.display_name, "available": False, "found": False,
                    "verdict": "unknown", "weight": "none",
                    "detail": f"{indicator} is internal/CGNAT; not queried.", "raw": {}}
        headers = {}
        if self.auth_header and self.api_key:
            headers[self.auth_header] = self.api_key
        r = self._get(self.url.format(indicator=indicator), headers=headers or None)
        if r is None or r.status_code != 200:
            return _unavailable(self.display_name,
                                f"HTTP {getattr(r, 'status_code', 'unreachable')}.")
        try:
            data = r.json()
        except ValueError:
            return _unavailable(self.display_name, "non-JSON response.")
        count = self._dig(data, self.malicious_field) if self.malicious_field else None
        count = count if isinstance(count, (int, float)) else 0
        if count >= self.malicious_strong_at:
            verdict, weight = "malicious", "strong"
        elif count >= 1:
            verdict, weight = "malicious", "weak"
        else:
            verdict, weight = "clean", "none"
        return {"source": self.display_name, "available": True, "found": True,
                "verdict": verdict, "weight": weight,
                "detail": f"{self.malicious_field}={count}", "raw": {"value": count}}


# --------------------------------------------------------------------------- #
# URLhaus (abuse.ch)  --  per-host malware-URL lookup via the authenticated API
# --------------------------------------------------------------------------- #
@register
class URLhausConnector(Connector):
    """Flags an IP or domain that hosts malware URLs, per abuse.ch URLhaus.

    Uses the URLhaus host API (urlhaus-api.abuse.ch/v1/host/). As of 2024-25
    abuse.ch requires a FREE Auth-Key for all of its services, so this needs
    URLHAUS_AUTH_KEY in the environment (get one free at auth.abuse.ch). A host
    currently serving live malware URLs is a strong signal; a host with only
    historical (offline) URLs is a weak one. Gives domains a second, independent
    opinion -- the first corroborating source for domain indicators.
    """
    name = "urlhaus"
    supports = ("ip", "domain")

    API_URL = "https://urlhaus-api.abuse.ch/v1/host/"

    def query(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        host = indicator.strip().strip(".").lower()
        if indicator_type == "ip" and is_internal_ip(host):
            return {"source": "URLhaus", "available": False, "found": False,
                    "verdict": "unknown", "weight": "none",
                    "detail": f"{host} is internal/CGNAT; not queried.", "raw": {}}
        if not self.api_key:
            return _unavailable("URLhaus", "URLHAUS_AUTH_KEY not set.")
        try:
            r = requests.post(self.API_URL, data={"host": host},
                              headers={"Auth-Key": self.api_key}, timeout=HTTP_TIMEOUT)
        except requests.RequestException:
            return _unavailable("URLhaus", "unreachable.")
        if r.status_code != 200:
            return _unavailable("URLhaus", f"HTTP {r.status_code}.")
        try:
            data = r.json()
        except ValueError:
            return _unavailable("URLhaus", "non-JSON response.")
        status = data.get("query_status")
        if status == "no_results":
            return {"source": "URLhaus", "available": True, "found": True,
                    "verdict": "clean", "weight": "none",
                    "detail": "no malware URLs recorded for this host.", "raw": {}}
        if status != "ok":
            return _unavailable("URLhaus", data.get("error") or status or "unexpected response.")
        urls = data.get("urls") or []
        online = [u for u in urls if str(u.get("url_status")) == "online"]
        count = data.get("url_count") or len(urls)
        if online:
            verdict, weight = "malicious", "strong"
            detail = f"{len(online)} active (online) malware URL(s) hosted here."
        elif urls:
            verdict, weight = "malicious", "weak"
            detail = f"{count} historical malware URL(s); none currently online."
        else:
            verdict, weight = "clean", "none"
            detail = "listed but no malware URLs returned."
        return {"source": "URLhaus", "available": True, "found": True,
                "verdict": verdict, "weight": weight, "detail": detail,
                "raw": {"url_count": count, "blacklists": data.get("blacklists")}}
