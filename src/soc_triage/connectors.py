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

New sources can be added either as a small subclass (see AbuseIPDBConnector) or
with no code at all via GenericRestConnector, configured in config.yaml. Neither
path requires changes to the scoring layer.
"""
from __future__ import annotations

import time
import ipaddress
from urllib.parse import quote
from typing import Any

import requests

HTTP_TIMEOUT = 30
RETRIES = 3
BACKOFF = 1.5          # base seconds for exponential backoff
MAX_BACKOFF = 20.0     # cap on a single sleep


def _retry_after(resp: requests.Response) -> float | None:
    """Seconds to wait from a Retry-After header, if present and numeric."""
    val = resp.headers.get("Retry-After")
    if not val:
        return None
    try:
        return float(val)
    except ValueError:
        return None

# CGNAT (RFC 6598) is classified as neither private nor global by the standard
# library, so it needs an explicit check alongside is_global.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")

# Hostname suffixes and labels that denote internal/private infrastructure and
# must never be sent to a third party.
_INTERNAL_HOST_SUFFIXES = (
    ".local", ".internal", ".intranet", ".corp", ".lan", ".home",
    ".localdomain", ".home.arpa", ".in-addr.arpa", ".ip6.arpa",
)


def is_internal_ip(value: str) -> bool:
    """True if value is a non-public IP that must not leave the network.

    Uses the standard library's address classification so it covers private,
    loopback, link-local, reserved and documentation ranges for both IPv4 and
    IPv6, unwraps IPv4-mapped IPv6 (e.g. ``::ffff:10.0.0.5``), and treats CGNAT
    (100.64.0.0/10) as internal.
    """
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if ip.version == 4 and ip in _CGNAT:
        return True
    return not ip.is_global


def is_internal_host(value: str) -> bool:
    """True if a domain/hostname denotes internal infrastructure, so it must not
    be sent to a third party. Covers internal TLD suffixes, single-label names
    (e.g. ``dc01``), and ``localhost``."""
    host = value.strip().strip(".").lower()
    if not host:
        return False
    if host == "localhost" or host.endswith(_INTERNAL_HOST_SUFFIXES):
        return True
    # A single-label hostname (no dot) is not a public domain.
    return "." not in host


def _unavailable(source: str, note: str) -> dict[str, Any]:
    return {"source": source, "available": False, "found": False,
            "verdict": "unknown", "weight": "none", "detail": note, "raw": {}}


def _refused_internal(source: str, indicator: str) -> dict[str, Any]:
    return {"source": source, "available": False, "found": False, "refused": True,
            "verdict": "unknown", "weight": "none",
            "detail": f"{indicator} is internal/non-public; not queried.", "raw": {}}


def is_private_indicator(indicator: str, indicator_type: str) -> bool:
    """True if an IP or domain indicator is internal and must not be sent out."""
    if indicator_type == "ip":
        return is_internal_ip(indicator)
    if indicator_type == "domain":
        return is_internal_host(indicator)
    return False


# --------------------------------------------------------------------------- #
# Base class + registry
# --------------------------------------------------------------------------- #
class Connector:
    """Base class. Subclasses set `name`, `supports`, and implement query()."""
    name: str = "connector"
    supports: tuple[str, ...] = ()          # e.g. ("ip", "domain")
    commercial_ok: bool = False             # may this source back a paid product?

    def __init__(self, *, api_key: str | None = None, **opts: Any) -> None:
        self.api_key = api_key
        self.opts = opts
        self._cache: dict[tuple[str, str], dict[str, Any]] = {}

    def handles(self, indicator_type: str) -> bool:
        return indicator_type in self.supports

    def lookup(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        """Cached wrapper around query(): a repeated indicator in one run costs
        one request per source, not one per occurrence."""
        key = (indicator_type, indicator)
        if key not in self._cache:
            self._cache[key] = self.query(indicator, indicator_type)
        return self._cache[key]

    def query(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        raise NotImplementedError

    def _request(self, method: str, url: str, **kw: Any) -> requests.Response | None:
        """HTTP with bounded retry + exponential backoff, honouring Retry-After
        on 429/503. Returns the Response, or None if unreachable after retries."""
        kw.setdefault("timeout", HTTP_TIMEOUT)
        for attempt in range(RETRIES):
            try:
                r = requests.request(method, url, **kw)
            except requests.RequestException:
                if attempt == RETRIES - 1:
                    return None
                time.sleep(min(BACKOFF * (2 ** attempt), MAX_BACKOFF))
                continue
            if r.status_code in (429, 500, 502, 503, 504) and attempt < RETRIES - 1:
                time.sleep(min(_retry_after(r) or BACKOFF * (2 ** attempt), MAX_BACKOFF))
                continue
            return r
        return None

    def _get(self, url: str, **kw: Any) -> requests.Response | None:
        return self._request("GET", url, **kw)


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
        if is_private_indicator(indicator, indicator_type):
            return _refused_internal("VirusTotal", indicator)
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
        creation = attrs.get("creation_date")
        detail = (f"{mal}/{total or '?'} vendors malicious"
                  + (f", {susp} suspicious" if susp else ""))
        # A domain registered within the last 30 days is a weak risk signal in
        # its own right, even when no vendor has flagged it yet.
        if indicator_type == "domain" and verdict == "clean" and creation:
            age_days = (time.time() - creation) / 86400
            if 0 <= age_days < 30:
                verdict, weight = "suspicious", "weak"
                detail = f"domain registered {int(age_days)} day(s) ago; {detail}"
        return {
            "source": "VirusTotal", "available": True, "found": True,
            "verdict": verdict, "weight": weight, "detail": detail,
            "raw": {"malicious": mal, "suspicious": susp, "as_owner": attrs.get("as_owner"),
                    "country": attrs.get("country"), "creation_date": creation},
        }


# --------------------------------------------------------------------------- #
# AbuseIPDB  --  IP abuse-confidence reputation
# --------------------------------------------------------------------------- #
@register
class AbuseIPDBConnector(Connector):
    name = "abuseipdb"
    supports = ("ip",)

    def query(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        if is_internal_ip(indicator):
            return _refused_internal("AbuseIPDB", indicator)
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
        # Below 25% confidence AbuseIPDB reports are treated as no signal, so a
        # handful of low-confidence reports cannot, on their own, raise a verdict.
        if conf >= 50:
            verdict, weight = "malicious", "strong"
        elif conf >= 25:
            verdict, weight = "malicious", "weak"
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
                 commercial_ok: bool = False,
                 api_key: str | None = None, **opts: Any) -> None:
        super().__init__(api_key=api_key, **opts)
        self.display_name = display_name
        self.url = url
        self.supports = tuple(supports or ())
        self.auth_header = auth_header
        self.malicious_field = malicious_field
        self.malicious_strong_at = malicious_strong_at
        self.commercial_ok = commercial_ok

    @staticmethod
    def _dig(obj: Any, dotted: str) -> Any:
        for part in dotted.split("."):
            if isinstance(obj, dict):
                obj = obj.get(part)
            else:
                return None
        return obj

    def query(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        if is_private_indicator(indicator, indicator_type):
            return _refused_internal(self.display_name, indicator)
        headers = {}
        if self.auth_header and self.api_key:
            headers[self.auth_header] = self.api_key
        # URL-encode the indicator so it cannot inject path segments or query
        # parameters into the configured feed URL.
        url = self.url.format(indicator=quote(indicator, safe=""))
        r = self._get(url, headers=headers or None)
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
        if is_private_indicator(indicator, indicator_type):
            return _refused_internal("URLhaus", indicator)
        if not self.api_key:
            return _unavailable("URLhaus", "URLHAUS_AUTH_KEY not set.")
        r = self._request("POST", self.API_URL, data={"host": host},
                          headers={"Auth-Key": self.api_key})
        if r is None:
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
