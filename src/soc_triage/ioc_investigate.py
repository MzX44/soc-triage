#!/usr/bin/env python3
"""
ioc_investigate.py  --  standalone IOC (indicator-of-compromise) investigator.

Runs ANYWHERE (your main Kali, a laptop, a server) -- no lab, no VPN, no SIEM.
Give it an IP, a domain, or a CVE and it gathers public threat intelligence and
produces a structured, rule-scored assessment:

    python ioc_investigate.py 45.146.164.110
    python ioc_investigate.py incendium-cdn.example.xyz
    python ioc_investigate.py CVE-2021-44228
    python ioc_investigate.py 45.146.164.110 CVE-2021-44228 --json

Why this is the "product" shape, not a script:
  * The VERDICT is deterministic and rule-based (auditable), computed in code
    from the evidence -- not asked of an LLM. An LLM is optional and only writes
    the prose summary. A security buyer trusts a scoring rule they can read;
    they do not trust "the AI said so".
  * Internal/CGNAT addresses are refused in code before any third-party call.
  * Every source degrades to a clear "unavailable" instead of fabricating.

Sources (all free, licence-clean, no scraping):
  * VirusTotal v3   -- IP / domain reputation            (VIRUSTOTAL_API_KEY)
  * CISA KEV + EPSS + NVD (via threat_intel.py)          -- CVE exploitation intel
Optional: NVD_API_KEY raises the NVD rate limit.
"""
from __future__ import annotations

import os
import sys
import json
import ipaddress
from dataclasses import dataclass, field, asdict
from typing import Any

import requests
from dotenv import load_dotenv

from . import threat_intel as ti

load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

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


def classify(indicator: str) -> str:
    """Return 'ip', 'cve', 'domain', or 'unknown'."""
    s = indicator.strip()
    if ti.CVE_RE.fullmatch(s.upper()):
        return "cve"
    try:
        ipaddress.ip_address(s)
        return "ip"
    except ValueError:
        pass
    if "." in s and " " not in s and "/" not in s:
        return "domain"
    return "unknown"


# --------------------------------------------------------------------------- #
# VirusTotal
# --------------------------------------------------------------------------- #
def _vt_get(path: str) -> dict[str, Any]:
    if not VIRUSTOTAL_API_KEY:
        return {"available": False, "note": "VIRUSTOTAL_API_KEY not set."}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/{path}",
                         headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=HTTP_TIMEOUT)
    except requests.RequestException as e:
        return {"available": False, "note": f"VirusTotal unreachable: {e}"}
    if r.status_code == 404:
        return {"available": True, "found": False}
    if r.status_code != 200:
        return {"available": False, "note": f"VirusTotal HTTP {r.status_code}"}
    attrs = r.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}) or {}
    return {
        "available": True, "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attrs.get("reputation"),
        "as_owner": attrs.get("as_owner"),
        "country": attrs.get("country"),
        "creation_date": attrs.get("creation_date"),  # domains
    }


def vt_ip(ip: str) -> dict[str, Any]:
    if is_internal_ip(ip):
        return {"available": False, "refused": True,
                "note": f"{ip} is internal/CGNAT; not sent to a third party."}
    return _vt_get(f"ip_addresses/{ip}")


def vt_domain(domain: str) -> dict[str, Any]:
    return _vt_get(f"domains/{domain.strip().strip('.')}")


# --------------------------------------------------------------------------- #
# Deterministic risk scoring (the auditable core)
# --------------------------------------------------------------------------- #
@dataclass
class Assessment:
    indicator: str
    kind: str
    score: int = 0                       # 0..100
    severity: str = "informational"      # informational|low|medium|high|critical
    reasons: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    def add(self, points: int, reason: str) -> None:
        self.score += points
        self.reasons.append(f"(+{points}) {reason}")


def _severity_for(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 30:
        return "medium"
    if score >= 10:
        return "low"
    return "informational"


def score_vt(a: Assessment, vt: dict[str, Any]) -> None:
    if not vt.get("available"):
        a.reasons.append(f"(0) VirusTotal: {vt.get('note', 'unavailable')}")
        return
    if not vt.get("found", True):
        a.reasons.append("(0) VirusTotal: no record for this indicator.")
        return
    mal, susp = vt.get("malicious", 0), vt.get("suspicious", 0)
    if mal >= 5:
        a.add(60, f"VirusTotal: {mal} vendors flag this as malicious.")
    elif mal >= 1:
        a.add(40, f"VirusTotal: {mal} vendor(s) flag this as malicious.")
    elif susp >= 1:
        a.add(20, f"VirusTotal: {susp} vendor(s) flag this as suspicious.")
    else:
        a.reasons.append("(0) VirusTotal: 0 malicious detections (not proof of benign).")
    # Newly registered domains are a known staging signal.
    if a.kind == "domain" and vt.get("creation_date"):
        a.evidence["domain_creation_date"] = vt["creation_date"]


def score_cve(a: Assessment, enr: dict[str, Any]) -> None:
    kev, epss, nvd = enr.get("kev", {}), enr.get("epss", {}), enr.get("nvd", {})
    if kev.get("known_exploited"):
        if str(kev.get("known_ransomware_use", "")).lower() == "known":
            a.add(80, "CISA KEV: actively exploited AND linked to ransomware campaigns.")
        else:
            a.add(65, "CISA KEV: actively exploited in the wild.")
    if epss.get("has_score"):
        p = epss.get("epss", 0)
        if p >= 0.5:
            a.add(25, f"EPSS: {p:.0%} probability of exploitation in 30 days.")
        elif p >= 0.1:
            a.add(10, f"EPSS: {p:.0%} probability of exploitation in 30 days.")
    sev = str(nvd.get("cvss_severity", "")).upper()
    if sev == "CRITICAL":
        a.add(15, "NVD: CVSS severity CRITICAL.")
    elif sev == "HIGH":
        a.add(8, "NVD: CVSS severity HIGH.")


def investigate(indicator: str) -> Assessment:
    kind = classify(indicator)
    a = Assessment(indicator=indicator, kind=kind)
    if kind == "ip":
        vt = vt_ip(indicator)
        a.evidence["virustotal"] = vt
        score_vt(a, vt)
    elif kind == "domain":
        vt = vt_domain(indicator)
        a.evidence["virustotal"] = vt
        score_vt(a, vt)
    elif kind == "cve":
        enr = ti.enrich_cve(indicator)
        a.evidence["cve_intel"] = enr
        score_cve(a, enr)
    else:
        a.reasons.append("(0) Unrecognised indicator type (expected IP, domain, or CVE).")
    a.score = min(a.score, 100)
    a.severity = _severity_for(a.score)
    return a


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
_BADGE = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
          "low": "LOW", "informational": "INFO"}


def render(a: Assessment) -> str:
    lines = [
        f"Indicator : {a.indicator}  ({a.kind})",
        f"Severity  : [{_BADGE[a.severity]}]  risk score {a.score}/100",
        "Reasons   :",
    ]
    for r in a.reasons:
        lines.append(f"  - {r}")
    if a.kind == "cve":
        enr = a.evidence.get("cve_intel", {})
        lines.append(f"Priority  : {enr.get('priority', 'n/a')}")
    return "\n".join(lines)


def main() -> None:
    args = [x for x in sys.argv[1:] if x != "--json"]
    as_json = "--json" in sys.argv
    if not args:
        print("Usage: python ioc_investigate.py <IP|domain|CVE> [more...] [--json]")
        sys.exit(1)
    results = [investigate(x) for x in args]
    if as_json:
        print(json.dumps([asdict(a) for a in results], indent=2, default=str))
    else:
        print("\n\n".join(render(a) for a in results))


if __name__ == "__main__":
    main()
