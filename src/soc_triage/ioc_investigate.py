#!/usr/bin/env python3
"""
ioc_investigate.py  --  standalone IOC investigator (config-driven connectors).

Takes an IP, a domain, or a CVE and produces a deterministic, rule-scored
assessment. Reputation is drawn from the configured connectors (VirusTotal,
AbuseIPDB, URLhaus, or any feed declared in config.yaml); IP and domain scores
reflect how many independent sources corroborate a detection, so a single
low-confidence flag does not dominate the result.

    ioc-triage 45.146.164.110
    ioc-triage suspicious-domain.xyz
    ioc-triage CVE-2021-44228
    ioc-triage 1.1.1.1 CVE-2021-44228 --json

The verdict is computed in code; no LLM is involved. Internal and CGNAT
addresses are refused in-connector before any third-party request.
"""
from __future__ import annotations

import sys
import json
import ipaddress
from dataclasses import dataclass, field, asdict
from typing import Any

from dotenv import load_dotenv

from . import threat_intel as ti
from . import connectors as C
from .config import load_connectors

load_dotenv()

# Re-export so callers/tests can use the same guard the connectors use.
is_internal_ip = C.is_internal_ip


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
# Assessment + scoring
# --------------------------------------------------------------------------- #
@dataclass
class Assessment:
    indicator: str
    kind: str
    score: int = 0
    severity: str = "informational"
    reasons: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


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


def aggregate_reputation(results: list[dict[str, Any]]) -> tuple[int, list[str]]:
    """Corroboration-based score for an IP or domain from N connector verdicts.

    A single source's flag is treated as a lead, not a verdict. The score scales
    with the number of independent sources that agree: one weak detection lands
    at the low band, while two strong detections reach the critical band.
    """
    strong = [r for r in results if r.get("weight") == "strong" and r.get("verdict") == "malicious"]
    weak = [r for r in results if r.get("weight") == "weak" and r.get("verdict") in ("malicious", "suspicious")]
    ns, nw = len(strong), len(weak)

    if ns >= 2:
        score = 85
    elif ns == 1 and nw >= 1:
        score = 70
    elif ns == 1:
        score = 55
    elif nw >= 2:
        score = 40
    elif nw == 1:
        score = 15
    else:
        score = 0

    reasons: list[str] = []
    for r in strong + weak:
        reasons.append(f"[{r['source']}] {r.get('detail', r.get('verdict'))}")
    for r in results:  # transparency: show clean/unavailable sources too
        if r not in strong and r not in weak:
            if not r.get("available"):
                reasons.append(f"[{r['source']}] unavailable: {r.get('detail', '')}")
            elif r.get("verdict") == "clean":
                reasons.append(f"[{r['source']}] clean (not proof of benign)")
    if ns == 0 and nw == 1:
        reasons.append("Only one source flagged this, with low confidence; scored low pending corroboration.")
    return score, reasons


def score_cve(enr: dict[str, Any]) -> tuple[int, list[str]]:
    kev, epss, nvd = enr.get("kev", {}), enr.get("epss", {}), enr.get("nvd", {})
    score, reasons = 0, []
    if kev.get("known_exploited"):
        if str(kev.get("known_ransomware_use", "")).lower() == "known":
            score += 80
            reasons.append("CISA KEV: actively exploited AND linked to ransomware campaigns.")
        else:
            score += 65
            reasons.append("CISA KEV: actively exploited in the wild.")
    if epss.get("has_score"):
        p = epss.get("epss", 0)
        if p >= 0.5:
            score += 25
            reasons.append(f"EPSS: {p:.0%} probability of exploitation in 30 days.")
        elif p >= 0.1:
            score += 10
            reasons.append(f"EPSS: {p:.0%} probability of exploitation in 30 days.")
    sev = str(nvd.get("cvss_severity", "")).upper()
    if sev == "CRITICAL":
        score += 15
        reasons.append("NVD: CVSS severity CRITICAL.")
    elif sev == "HIGH":
        score += 8
        reasons.append("NVD: CVSS severity HIGH.")
    return score, reasons


def investigate(indicator: str, conns: list[C.Connector] | None = None) -> Assessment:
    kind = classify(indicator)
    a = Assessment(indicator=indicator, kind=kind)

    if kind == "cve":
        enr = ti.enrich_cve(indicator)
        a.evidence["cve_intel"] = enr
        a.score, a.reasons = score_cve(enr)
    elif kind in ("ip", "domain"):
        if conns is None:
            conns = load_connectors()
        results = [c.query(indicator, kind) for c in conns if c.handles(kind)]
        a.evidence["sources"] = results
        if results:
            a.score, a.reasons = aggregate_reputation(results)
        else:
            a.reasons.append("No enrichment source is configured for this indicator type.")
    else:
        a.reasons.append("Unrecognised indicator type (expected IP, domain, or CVE).")

    a.score = min(a.score, 100)
    a.severity = _severity_for(a.score)
    return a


# --------------------------------------------------------------------------- #
# Rendering / CLI
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
        lines.append(f"Priority  : {a.evidence.get('cve_intel', {}).get('priority', 'n/a')}")
    return "\n".join(lines)


def main() -> None:
    args = [x for x in sys.argv[1:] if x != "--json"]
    as_json = "--json" in sys.argv
    if not args:
        print("Usage: ioc-triage <IP|domain|CVE> [more...] [--json]")
        sys.exit(1)
    conns = load_connectors()  # built once, reused across indicators
    results = [investigate(x, conns) for x in args]
    if as_json:
        print(json.dumps([asdict(a) for a in results], indent=2, default=str))
    else:
        print("\n\n".join(render(a) for a in results))


if __name__ == "__main__":
    main()
