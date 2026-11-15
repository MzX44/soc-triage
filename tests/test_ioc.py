#!/usr/bin/env python3
"""
Offline tests for ioc_investigate.py -- no network.

Covers classification, the internal-IP guard, CVE scoring, the severity bands,
and the new CORROBORATION aggregation (including the lone-vendor '8.8.8.8' fix).
Run: python tests/test_ioc.py
"""
from soc_triage import ioc_investigate as mod


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    assert cond, name


def test_classify():
    print("Indicator classification:")
    check("ipv4", mod.classify("45.146.164.110") == "ip")
    check("cve (lowercase)", mod.classify("cve-2021-44228") == "cve")
    check("domain", mod.classify("incendium-cdn.example.xyz") == "domain")
    check("junk -> unknown", mod.classify("hello world") == "unknown")


def test_internal_guard():
    print("Internal-IP guard (shared with connectors):")
    for ip in ("10.0.0.5", "192.168.1.1", "100.97.48.128", "172.16.4.4"):
        check(f"{ip} internal", mod.is_internal_ip(ip) is True)
    check("public IP not internal", mod.is_internal_ip("45.146.164.110") is False)


def _r(source, verdict, weight, available=True):
    return {"source": source, "available": available, "found": True,
            "verdict": verdict, "weight": weight, "detail": f"{source} {verdict}"}


def test_corroboration():
    print("Corroboration aggregation:")
    # Two strong malicious -> critical band.
    s, _ = mod.aggregate_reputation([_r("VirusTotal", "malicious", "strong"),
                                     _r("AbuseIPDB", "malicious", "strong")])
    check("2 strong -> 85", s == 85)

    # One strong + one weak -> 70.
    s, _ = mod.aggregate_reputation([_r("VirusTotal", "malicious", "strong"),
                                     _r("AbuseIPDB", "suspicious", "weak")])
    check("1 strong + 1 weak -> 70", s == 70)

    # THE 8.8.8.8 FIX: one weak hit, one source says clean -> LOW, not MEDIUM.
    s, reasons = mod.aggregate_reputation([_r("VirusTotal", "malicious", "weak"),
                                           _r("AbuseIPDB", "clean", "none")])
    check("lone weak hit -> 15 (LOW)", s == 15)
    check("severity is low", mod._severity_for(s) == "low")
    check("clean source surfaced", any("clean" in x for x in reasons))

    # Two independent weak hits DO corroborate -> MEDIUM.
    s, _ = mod.aggregate_reputation([_r("VirusTotal", "malicious", "weak"),
                                     _r("AbuseIPDB", "malicious", "weak")])
    check("2 weak -> 40 (MEDIUM)", s == 40)

    # All clean -> 0.
    s, _ = mod.aggregate_reputation([_r("VirusTotal", "clean", "none"),
                                     _r("AbuseIPDB", "clean", "none")])
    check("all clean -> 0", s == 0)


def test_cve_scoring():
    print("CVE scoring (unchanged logic, tuple return):")
    s, _ = mod.score_cve({"kev": {"known_exploited": True, "known_ransomware_use": "Known"},
                          "epss": {"has_score": True, "epss": 0.94},
                          "nvd": {"cvss_severity": "CRITICAL"}})
    check("KEV+ransomware+EPSS+critical -> 120 (capped later)", s == 120)
    check("maps to critical", mod._severity_for(min(s, 100)) == "critical")

    s2, _ = mod.score_cve({"kev": {"known_exploited": False},
                           "epss": {"has_score": True, "epss": 0.12},
                           "nvd": {"cvss_severity": "HIGH"}})
    check("no KEV -> below critical", mod._severity_for(min(s2, 100)) != "critical")


def test_severity_bands():
    print("Severity banding:")
    check("0 -> informational", mod._severity_for(0) == "informational")
    check("15 -> low", mod._severity_for(15) == "low")
    check("40 -> medium", mod._severity_for(40) == "medium")
    check("60 -> high", mod._severity_for(60) == "high")
    check("85 -> critical", mod._severity_for(85) == "critical")


def test_investigate_with_fake_connectors():
    print("investigate() end-to-end with injected connectors (no network):")
    class FakeConn:
        def __init__(self, result): self._r = result
        def handles(self, k): return k == "ip"
        def query(self, ind, k): return self._r
    conns = [FakeConn(_r("VirusTotal", "malicious", "weak")),
             FakeConn(_r("AbuseIPDB", "clean", "none"))]
    a = mod.investigate("8.8.8.8", conns)
    check("8.8.8.8 lands LOW, not MEDIUM", a.severity == "low" and a.score == 15)


if __name__ == "__main__":
    test_classify()
    test_internal_guard()
    test_corroboration()
    test_cve_scoring()
    test_severity_bands()
    test_investigate_with_fake_connectors()
    print("\nAll tests passed.")
