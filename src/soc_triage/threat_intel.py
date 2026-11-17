#!/usr/bin/env python3
"""
threat_intel.py  --  CVE threat-intelligence enrichment.

Answers whether a CVE is being exploited in the wild, and how likely it is to be,
from free, authoritative, licence-clean sources:

  * CISA KEV   (Known Exploited Vulnerabilities) -- confirms a CVE is being
               actively exploited; includes a ransomware-campaign flag.
  * EPSS       (FIRST.org Exploit Prediction Scoring System) -- probability the
               CVE will be exploited in the next 30 days (0..1) + percentile.
  * NVD        (NIST National Vulnerability Database) -- CVSS base score/severity
               and the canonical description.

Implementation notes:
  * The KEV catalogue is cached on disk with a TTL, so it is fetched once rather
    than once per CVE per run.
  * Every network call retries with backoff and degrades to a structured
    "unavailable" result instead of raising; a missing feed is reported, never
    fabricated.
  * enrich_cve() returns a plain dict. An optional NVD_API_KEY raises the NVD
    rate limit; no credentials are otherwise required.
"""
from __future__ import annotations

import os
import re
import sys
import json
import time
from pathlib import Path
from typing import Any, Optional

import requests

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

HTTP_TIMEOUT = 30
RETRIES = 3
BACKOFF = 1.5  # seconds, exponential

# Cache the (large, slow-changing) KEV catalogue on disk between runs. A
# per-user cache directory is used rather than a world-writable temp dir, so
# another account cannot plant a catalogue for this process to trust.
def _default_cache_dir() -> Path:
    env = os.getenv("SOC_CACHE_DIR")
    if env:
        return Path(env)
    if os.name == "nt":
        base = os.getenv("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
    elif sys.platform == "darwin":
        base = os.path.join(os.path.expanduser("~"), "Library", "Caches")
    else:
        base = os.getenv("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "soc_triage"


CACHE_DIR = _default_cache_dir()
KEV_CACHE = CACHE_DIR / "cisa_kev.json"
KEV_TTL_SECONDS = 6 * 60 * 60        # serve cache without refetching for 6 hours
KEV_MAX_AGE_SECONDS = 72 * 60 * 60   # beyond this a stale cache is not trusted

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# Small HTTP helper with retry/backoff
# --------------------------------------------------------------------------- #
def _get(url: str, *, params: dict | None = None, headers: dict | None = None) -> Optional[requests.Response]:
    """GET with bounded retries. Returns the Response, or None if unreachable."""
    for attempt in range(RETRIES):
        try:
            r = requests.get(url, params=params, headers=headers, timeout=HTTP_TIMEOUT)
            # Retry transient server/rate errors; return anything else to caller.
            if r.status_code in (429, 500, 502, 503, 504):
                time.sleep(BACKOFF * (2 ** attempt))
                continue
            return r
        except requests.RequestException:
            time.sleep(BACKOFF * (2 ** attempt))
    return None


# --------------------------------------------------------------------------- #
# CISA KEV (cached catalogue)
# --------------------------------------------------------------------------- #
def _read_kev_cache() -> tuple[dict[str, Any], float] | None:
    """Return (cached data, age in seconds), or None if no trustworthy cache.

    The file must be owned by the current user, so a catalogue planted by
    another account in a shared directory is ignored.
    """
    try:
        if not KEV_CACHE.exists():
            return None
        st = KEV_CACHE.stat()
        if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
            return None
        data = json.loads(KEV_CACHE.read_text())
        if not isinstance(data, dict) or "vulns" not in data:
            return None
        return data, time.time() - st.st_mtime
    except (OSError, ValueError):
        return None


def _write_kev_cache(data: dict[str, Any]) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        KEV_CACHE.write_text(json.dumps(data))
    except OSError:
        pass  # caching is best-effort


def _load_kev_catalogue(force_refresh: bool = False) -> dict[str, Any] | None:
    """Return {'vulns', 'catalog_version', 'count', 'age_seconds', 'stale'}, or
    None if the catalogue cannot be obtained at all (no cache and feed down)."""
    cached = _read_kev_cache()
    if not force_refresh and cached is not None:
        data, age = cached
        if age < KEV_TTL_SECONDS:
            return {**data, "age_seconds": age, "stale": False}

    r = _get(KEV_URL)
    if r is None or r.status_code != 200:
        if cached is not None:  # fall back to cache, flagged stale past the max age
            data, age = cached
            return {**data, "age_seconds": age, "stale": age > KEV_MAX_AGE_SECONDS}
        return None
    try:
        raw = r.json()
    except ValueError:
        if cached is not None:
            data, age = cached
            return {**data, "age_seconds": age, "stale": age > KEV_MAX_AGE_SECONDS}
        return None

    vulns = {v["cveID"].upper(): v for v in raw.get("vulnerabilities", []) if v.get("cveID")}
    data = {"vulns": vulns, "catalog_version": raw.get("catalogVersion"),
            "count": raw.get("count", len(vulns))}
    _write_kev_cache(data)
    return {**data, "age_seconds": 0.0, "stale": False}


def kev_lookup(cve: str, catalogue: dict[str, dict] | None = None) -> dict[str, Any]:
    """Is this CVE in the CISA Known Exploited Vulnerabilities catalogue?

    `catalogue`, when given, is a plain {cveID: entry} index (used in tests).
    Otherwise the on-disk cache is used, and a catalogue older than the max age
    that cannot be refreshed is reported as unavailable rather than trusted.
    """
    cve = cve.upper().strip()
    if catalogue is not None:
        index, version, age_hours = catalogue, None, None
    else:
        loaded = _load_kev_catalogue()
        if loaded is None:
            return {"source": "CISA KEV", "available": False,
                    "note": "KEV catalogue unavailable (feed unreachable, no cache)."}
        if loaded.get("stale"):
            return {"source": "CISA KEV", "available": False,
                    "catalog_version": loaded.get("catalog_version"),
                    "age_hours": round(loaded.get("age_seconds", 0) / 3600, 1),
                    "note": f"KEV catalogue is stale (> {KEV_MAX_AGE_SECONDS // 3600}h) "
                            "and could not be refreshed."}
        index = loaded["vulns"]
        version = loaded.get("catalog_version")
        age_hours = round(loaded.get("age_seconds", 0) / 3600, 1)

    base = {"source": "CISA KEV", "available": True,
            "catalog_version": version, "age_hours": age_hours}
    entry = index.get(cve)
    if not entry:
        return {**base, "known_exploited": False}
    return {
        **base,
        "known_exploited": True,
        "vulnerability_name": entry.get("vulnerabilityName"),
        "vendor_project": entry.get("vendorProject"),
        "product": entry.get("product"),
        "date_added": entry.get("dateAdded"),
        "due_date": entry.get("dueDate"),
        "known_ransomware_use": entry.get("knownRansomwareCampaignUse"),
        "required_action": entry.get("requiredAction"),
    }


# --------------------------------------------------------------------------- #
# EPSS (exploit probability)
# --------------------------------------------------------------------------- #
def epss_lookup(cve: str) -> dict[str, Any]:
    """Exploit Prediction Scoring System: P(exploit in next 30 days)."""
    cve = cve.upper().strip()
    r = _get(EPSS_URL, params={"cve": cve})
    if r is None or r.status_code != 200:
        return {"source": "EPSS", "available": False,
                "note": "EPSS API unreachable."}
    try:
        data = r.json().get("data", [])
    except ValueError:
        return {"source": "EPSS", "available": False, "note": "EPSS returned non-JSON."}
    if not data:
        return {"source": "EPSS", "available": True, "has_score": False}
    row = data[0]
    return {
        "source": "EPSS",
        "available": True,
        "has_score": True,
        "epss": float(row.get("epss", 0)),          # 0..1 probability
        "percentile": float(row.get("percentile", 0)),
        "score_date": row.get("date"),
    }


# --------------------------------------------------------------------------- #
# NVD (CVSS + description)
# --------------------------------------------------------------------------- #
def nvd_lookup(cve: str) -> dict[str, Any]:
    """CVSS base score/severity and the canonical description from NVD."""
    cve = cve.upper().strip()
    headers = {}
    if os.getenv("NVD_API_KEY"):
        headers["apiKey"] = os.getenv("NVD_API_KEY")
    r = _get(NVD_URL, params={"cveId": cve}, headers=headers or None)
    if r is None or r.status_code != 200:
        return {"source": "NVD", "available": False, "note": "NVD API unreachable."}
    try:
        vulns = r.json().get("vulnerabilities", [])
    except ValueError:
        return {"source": "NVD", "available": False, "note": "NVD returned non-JSON."}
    if not vulns:
        return {"source": "NVD", "available": True, "found": False}
    cve_obj = vulns[0].get("cve", {})
    desc = next((d.get("value") for d in cve_obj.get("descriptions", [])
                 if d.get("lang") == "en"), None)
    metrics = cve_obj.get("metrics", {})
    cvss = severity = version = scored_by = None
    # Prefer the newest CVSS version NVD exposes. CVSS 4.0 (cvssMetricV40) was
    # ignored before; CVEs scored only in 4.0 previously lost their severity.
    for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                     ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        if metrics.get(key):
            metric = metrics[key][0]
            data = metric.get("cvssData", {})
            cvss = data.get("baseScore")
            severity = data.get("baseSeverity") or metric.get("baseSeverity")
            version = ver
            # Whether the score came from NIST or a CNA/ADP source.
            scored_by = metric.get("source") or metric.get("type")
            break
    return {
        "source": "NVD",
        "available": True,
        "found": True,
        "description": (desc or "")[:600],
        "cvss_base_score": cvss,
        "cvss_severity": severity,
        "cvss_version": version,
        "cvss_scored_by": scored_by,
        "published": cve_obj.get("published"),
    }


# --------------------------------------------------------------------------- #
# Combined enrichment
# --------------------------------------------------------------------------- #
def enrich_cve(cve: str, kev_catalogue: dict[str, dict] | None = None) -> dict[str, Any]:
    """Enrich one CVE across KEV + EPSS + NVD.

    Returns the raw evidence from each source. The single triage band and
    priority are derived by the scorer in ioc_investigate, so there is one rule
    set rather than two that can disagree.
    """
    cve = cve.upper().strip()
    if not CVE_RE.fullmatch(cve):
        return {"cve": cve, "error": "not a valid CVE identifier (expected CVE-YYYY-NNNNN)."}
    kev = kev_lookup(cve, catalogue=kev_catalogue)
    return {
        "cve": cve,
        "actively_exploited": bool(kev.get("known_exploited")),
        "kev": kev,
        "epss": epss_lookup(cve),
        "nvd": nvd_lookup(cve),
    }


def extract_cves(text: str) -> list[str]:
    """Pull unique CVE IDs out of free text (ticket description, evidence)."""
    seen, out = set(), []
    for m in CVE_RE.findall(text or ""):
        u = m.upper()
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    print(json.dumps(enrich_cve(target), indent=2))
