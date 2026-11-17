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

import re
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

# Re-export so callers/tests can use the same guards the connectors use.
is_internal_ip = C.is_internal_ip
is_internal_host = C.is_internal_host

# A bare, well-formed domain name (no scheme, port, path, user, or whitespace).
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def _refang(value: str) -> str:
    """Undo common indicator defanging so ``evil[.]com`` and ``hxxp://x`` are
    normalised before classification (a defanged URL still classifies as a URL,
    i.e. 'unknown', and is not looked up)."""
    s = value.strip()
    for a, b in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[:]", ":")):
        s = s.replace(a, b)
    s = re.sub(r"\[dot\]", ".", s, flags=re.IGNORECASE)
    s = re.sub(r"(?i)^hxxp(s?)://", r"http\1://", s)
    return s


def classify(indicator: str) -> str:
    """Return 'ip', 'cve', 'domain', or 'unknown'.

    Only a bare IP, a CVE id, or a bare domain name are recognised. Emails,
    URLs, host:port strings, paths and anything else return 'unknown' and are
    never looked up.
    """
    s = indicator.strip()
    if ti.CVE_RE.fullmatch(s.upper()):
        return "cve"
    try:
        ipaddress.ip_address(s)
        return "ip"
    except ValueError:
        pass
    # Reject non-indicator shapes before treating anything as a domain.
    if any(c in s for c in "@/\\ \t") or ":" in s:
        return "unknown"
    if _DOMAIN_RE.fullmatch(s.strip(".")):
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
    priority: str = "INFO"
    reasons: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


# A single severity -> priority mapping, so the band and the printed priority can
# never disagree (they are derived from the same score).
_PRIORITY = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "ELEVATED",
    "low": "LOW", "informational": "INFO", "inconclusive": "INCONCLUSIVE",
}


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
    """Score a CVE so the band agrees with exploitation evidence.

    KEV membership is a floor at the critical band and EPSS >= 0.5 is a floor at
    the high band, because confirmed or predicted exploitation should not be
    out-voted by a CVSS modifier. CVSS and mid-range EPSS only add below those
    floors. This keeps the band and the printed priority consistent.
    """
    kev, epss, nvd = enr.get("kev", {}), enr.get("epss", {}), enr.get("nvd", {})
    reasons: list[str] = []

    kev_floor = 0
    if kev.get("known_exploited"):
        if str(kev.get("known_ransomware_use", "")).lower() == "known":
            kev_floor = 90
            reasons.append("CISA KEV: actively exploited AND linked to ransomware campaigns.")
        else:
            kev_floor = 80
            reasons.append("CISA KEV: actively exploited in the wild.")

    epss_floor = add = 0
    if epss.get("has_score"):
        p = epss.get("epss", 0)
        if p >= 0.5:
            epss_floor = 55
            reasons.append(f"EPSS: {p:.0%} probability of exploitation in 30 days.")
        elif p >= 0.1:
            add += 10
            reasons.append(f"EPSS: {p:.0%} probability of exploitation in 30 days.")

    sev = str(nvd.get("cvss_severity", "")).upper()
    ver = nvd.get("cvss_version")
    label = f"CVSS {('v' + ver + ' ') if ver else ''}severity {sev}"
    if sev == "CRITICAL":
        add += 15
        reasons.append(f"NVD: {label}.")
    elif sev == "HIGH":
        add += 8
        reasons.append(f"NVD: {label}.")

    return min(max(kev_floor, epss_floor, add), 100), reasons


def _investigate_network(a: Assessment, indicator: str, kind: str,
                         conns: list[C.Connector] | None) -> None:
    if conns is None:
        conns = load_connectors()
    results = [c.lookup(indicator, kind) for c in conns if c.handles(kind)]
    a.evidence["sources"] = results
    answered = [r for r in results if r.get("available")]
    refused = [r for r in results if r.get("refused")]
    a.evidence["coverage"] = {"answered": len(answered), "configured": len(results)}

    if not results:
        a.severity = "inconclusive"
        a.reasons.append("No enrichment source is configured for this indicator type.")
        return
    if not answered:
        if refused:
            a.severity = "informational"
            a.reasons.append("Internal/non-public indicator; not sent to third parties and not scored.")
        else:
            a.severity = "inconclusive"
            a.reasons.append("No source could be reached (keys missing, quota exhausted, or "
                             "network down); result is inconclusive, not clean.")
            for r in results:
                a.reasons.append(f"[{r['source']}] unavailable: {r.get('detail', '')}")
        return
    a.score, a.reasons = aggregate_reputation(results)
    a.severity = _severity_for(a.score)


def investigate(indicator: str, conns: list[C.Connector] | None = None) -> Assessment:
    norm = _refang(indicator)
    kind = classify(norm)
    a = Assessment(indicator=norm, kind=kind)

    if kind == "cve":
        enr = ti.enrich_cve(norm)
        a.evidence["cve_intel"] = enr
        if not enr.get("kev", {}).get("available", False):
            a.severity = "inconclusive"
            a.reasons.append("CISA KEV feed unavailable; exploitation status unknown, so the "
                             "result is inconclusive rather than scored.")
        else:
            a.score, a.reasons = score_cve(enr)
            a.severity = _severity_for(a.score)
    elif kind in ("ip", "domain"):
        _investigate_network(a, norm, kind, conns)
    else:
        a.severity = "informational"
        a.reasons.append("Unrecognised indicator (expected a bare IP, domain, or CVE id); "
                         "not looked up.")

    a.score = min(a.score, 100)
    a.priority = _PRIORITY.get(a.severity, "INFO")
    return a


# --------------------------------------------------------------------------- #
# Rendering / CLI
# --------------------------------------------------------------------------- #
_BADGE = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
          "low": "LOW", "informational": "INFO", "inconclusive": "INCONCLUSIVE"}


def render(a: Assessment) -> str:
    if a.severity == "inconclusive":
        head = f"Severity  : [{_BADGE[a.severity]}]  risk not assessed"
    else:
        head = f"Severity  : [{_BADGE[a.severity]}]  risk score {a.score}/100"
    lines = [f"Indicator : {a.indicator}  ({a.kind})", head, "Reasons   :"]
    for r in a.reasons:
        lines.append(f"  - {r}")
    lines.append(f"Priority  : {a.priority}")
    return "\n".join(lines)


def _exit_code(results: list[Assessment]) -> int:
    """0 = nothing actionable, 1 = a high/critical finding, 2 = inconclusive.
    Lets a SOAR playbook or shell script branch without parsing JSON."""
    sev = {a.severity for a in results}
    if "inconclusive" in sev:
        return 2
    if sev & {"high", "critical"}:
        return 1
    return 0


def main() -> None:
    args = [x for x in sys.argv[1:] if x != "--json"]
    as_json = "--json" in sys.argv
    if not args:
        print("Usage: ioc-triage <IP|domain|CVE> [more...] [--json]")
        sys.exit(2)
    conns = load_connectors()  # built once, reused across indicators
    results = [investigate(x, conns) for x in args]
    if as_json:
        print(json.dumps([asdict(a) for a in results], indent=2, default=str))
    else:
        print("\n\n".join(render(a) for a in results))
    sys.exit(_exit_code(results))


if __name__ == "__main__":
    main()
