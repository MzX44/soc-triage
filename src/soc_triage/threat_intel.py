#!/usr/bin/env python3
"""
threat_intel.py  --  CVE threat-intelligence enrichment for the SOC agent.

This is the legitimate, production-safe version of "dark-web / zero-day insight":
instead of crawling Tor markets (legally fraught, unreliable, an OPSEC liability),
it answers the question an analyst actually needs -- "is this vulnerability being
exploited in the wild right now, and how likely is it to be?" -- from free,
authoritative, licence-clean sources:

  * CISA KEV   (Known Exploited Vulnerabilities) -- ground truth that a CVE is
               being actively exploited; includes ransomware-campaign flag.
  * EPSS       (FIRST.org Exploit Prediction Scoring System) -- probability the
               CVE will be exploited in the next 30 days (0..1) + percentile.
  * NVD        (NIST National Vulnerability Database) -- CVSS base score/severity
               and the canonical description.

Design notes (these are the "product", not the script, parts):
  * The KEV catalogue is cached on disk with a TTL so we fetch it once, not once
    per CVE per run.
  * Every network call retries with backoff and degrades to a clear, structured
    "unavailable" result instead of raising -- a missing feed is a stated
    limitation, never fabricated data.
  * enrich_cve() returns a plain dict (machine-readable); the @tool wrapper
    serialises it for the agent. No secrets required; an optional NVD_API_KEY
    raises the NVD rate limit.

Public sources, no credentials needed. NVD allows a free API key for higher
rate limits (set NVD_API_KEY in the environment if you have one).
"""
from __future__ import annotations

import os
import re
import json
import time
import tempfile
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

# Cache the (large, slow-changing) KEV catalogue on disk between runs.
CACHE_DIR = Path(os.getenv("SOC_CACHE_DIR", Path(tempfile.gettempdir()) / "soc_agent_cache"))
KEV_CACHE = CACHE_DIR / "cisa_kev.json"
KEV_TTL_SECONDS = 6 * 60 * 60  # 6 hours

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# Small HTTP helper with retry/backoff
# --------------------------------------------------------------------------- #
def _get(url: str, *, params: dict | None = None, headers: dict | None = None) -> Optional[requests.Response]:
    """GET with bounded retries. Returns the Response, or None if unreachable."""
    last_exc = None
    for attempt in range(RETRIES):
        try:
            r = requests.get(url, params=params, headers=headers, timeout=HTTP_TIMEOUT)
            # Retry transient server/rate errors; return anything else to caller.
            if r.status_code in (429, 500, 502, 503, 504):
                last_exc = f"HTTP {r.status_code}"
                time.sleep(BACKOFF * (2 ** attempt))
                continue
            return r
        except requests.RequestException as e:
            last_exc = e
            time.sleep(BACKOFF * (2 ** attempt))
    return None


# --------------------------------------------------------------------------- #
# CISA KEV (cached catalogue)
# --------------------------------------------------------------------------- #
def _load_kev_catalogue(force_refresh: bool = False) -> dict[str, dict] | None:
    """Return {cveID: entry} for the CISA KEV catalogue, cached on disk.

    Returns None if the catalogue cannot be obtained (no cache, feed down).
    """
    # Serve from cache if it is fresh.
    if not force_refresh and KEV_CACHE.exists():
        age = time.time() - KEV_CACHE.stat().st_mtime
        if age < KEV_TTL_SECONDS:
            try:
                return json.loads(KEV_CACHE.read_text())
            except (ValueError, OSError):
                pass  # fall through and refetch

    r = _get(KEV_URL)
    if r is None or r.status_code != 200:
        # Fall back to a stale cache rather than nothing.
        if KEV_CACHE.exists():
            try:
                return json.loads(KEV_CACHE.read_text())
            except (ValueError, OSError):
                return None
        return None

    try:
        raw = r.json()
    except ValueError:
        return None

    index = {
        v.get("cveID", "").upper(): v
        for v in raw.get("vulnerabilities", [])
        if v.get("cveID")
    }
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        KEV_CACHE.write_text(json.dumps(index))
    except OSError:
        pass  # caching is best-effort
    return index


def kev_lookup(cve: str, catalogue: dict[str, dict] | None = None) -> dict[str, Any]:
    """Is this CVE in the CISA Known Exploited Vulnerabilities catalogue?"""
    cve = cve.upper().strip()
    cat = catalogue if catalogue is not None else _load_kev_catalogue()
    if cat is None:
        return {"source": "CISA KEV", "available": False,
                "note": "KEV catalogue unavailable (feed unreachable, no cache)."}
    entry = cat.get(cve)
    if not entry:
        return {"source": "CISA KEV", "available": True, "known_exploited": False}
    return {
        "source": "CISA KEV",
        "available": True,
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
    cvss = None
    severity = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0].get("cvssData", {})
            cvss = m.get("baseScore")
            severity = m.get("baseSeverity") or metrics[key][0].get("baseSeverity")
            break
    return {
        "source": "NVD",
        "available": True,
        "found": True,
        "description": (desc or "")[:600],
        "cvss_base_score": cvss,
        "cvss_severity": severity,
        "published": cve_obj.get("published"),
    }


# --------------------------------------------------------------------------- #
# Combined enrichment + a single analyst-facing priority signal
# --------------------------------------------------------------------------- #
def _priority(kev: dict, epss: dict, nvd: dict) -> str:
    """Collapse the three signals into one triage priority for the analyst."""
    if kev.get("known_exploited"):
        if str(kev.get("known_ransomware_use", "")).lower() == "known":
            return "CRITICAL - actively exploited, linked to ransomware campaigns"
        return "CRITICAL - actively exploited in the wild (CISA KEV)"
    if epss.get("has_score") and epss.get("epss", 0) >= 0.5:
        return "HIGH - high probability of exploitation (EPSS >= 0.5)"
    sev = str(nvd.get("cvss_severity", "")).upper()
    if sev == "CRITICAL":
        return "ELEVATED - critical CVSS, no confirmed in-the-wild exploitation"
    if epss.get("has_score") and epss.get("epss", 0) >= 0.1:
        return "ELEVATED - non-trivial exploitation probability (EPSS >= 0.1)"
    if sev in ("HIGH", "MEDIUM", "LOW"):
        return f"{sev} CVSS - no confirmed in-the-wild exploitation"
    return "UNKNOWN - insufficient data to prioritise"


def enrich_cve(cve: str, kev_catalogue: dict[str, dict] | None = None) -> dict[str, Any]:
    """Enrich one CVE across KEV + EPSS + NVD and attach a triage priority."""
    cve = cve.upper().strip()
    if not CVE_RE.fullmatch(cve):
        return {"cve": cve, "error": "not a valid CVE identifier (expected CVE-YYYY-NNNNN)."}
    kev = kev_lookup(cve, catalogue=kev_catalogue)
    epss = epss_lookup(cve)
    nvd = nvd_lookup(cve)
    return {
        "cve": cve,
        "priority": _priority(kev, epss, nvd),
        "actively_exploited": bool(kev.get("known_exploited")),
        "kev": kev,
        "epss": epss,
        "nvd": nvd,
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


# --------------------------------------------------------------------------- #
# LangChain tool wrapper (import-safe: only defined if langchain is present)
# --------------------------------------------------------------------------- #
try:
    from langchain_core.tools import tool

    @tool
    def cve_threat_intel(cve: str) -> str:
        """Enrich a CVE with real-world exploitation intelligence. Returns whether
        the CVE is actively exploited in the wild (CISA KEV, incl. ransomware
        use), its EPSS exploitation probability, its CVSS score/severity (NVD),
        and a single triage priority. Use this for any CVE mentioned in a ticket
        or its evidence. A CVE's presence in CISA KEV is strong evidence the
        activity deserves escalation.

        Args:
            cve: A CVE identifier, e.g. 'CVE-2021-44228'.
        """
        return json.dumps(enrich_cve(cve), default=str)[:4000]
except ImportError:  # module still usable as a plain library without langchain
    cve_threat_intel = None  # type: ignore


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    print(json.dumps(enrich_cve(target), indent=2))
