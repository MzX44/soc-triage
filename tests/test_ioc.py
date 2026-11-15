#!/usr/bin/env python3
"""
Offline tests for ioc_investigate.py -- no network.

Verifies indicator classification, the internal-IP refusal, and the
deterministic risk-scoring rules (the auditable core). Run: python test_ioc.py
"""
from soc_triage import ioc_investigate as mod
from soc_triage import threat_intel as ti


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
    print("Internal-IP refusal (no third-party call):")
    for ip in ("10.0.0.5", "192.168.1.1", "100.97.48.128", "172.16.4.4"):
        r = mod.vt_ip(ip)
        check(f"{ip} refused", r.get("refused") is True and r.get("available") is False)
    check("public IP not refused by guard", mod.is_internal_ip("45.146.164.110") is False)


def test_score_vt():
    print("VirusTotal scoring rules:")
    a = mod.Assessment("1.2.3.4", "ip")
    mod.score_vt(a, {"available": True, "found": True, "malicious": 8, "suspicious": 0})
    check("many malicious -> >=60", a.score >= 60)

    a2 = mod.Assessment("1.2.3.4", "ip")
    mod.score_vt(a2, {"available": True, "found": True, "malicious": 0, "suspicious": 0})
    check("clean VT -> 0 (not proof of benign)", a2.score == 0)

    a3 = mod.Assessment("x.xyz", "domain")
    mod.score_vt(a3, {"available": True, "found": True, "malicious": 0,
                      "suspicious": 1, "creation_date": 1700000000})
    check("1 suspicious -> +20", a3.score == 20)
    check("domain creation date captured", "domain_creation_date" in a3.evidence)


def test_score_cve():
    print("CVE scoring rules:")
    # KEV + ransomware -> critical-weight
    a = mod.Assessment("CVE-2021-44228", "cve")
    mod.score_cve(a, {"kev": {"known_exploited": True, "known_ransomware_use": "Known"},
                      "epss": {"has_score": True, "epss": 0.94},
                      "nvd": {"cvss_severity": "CRITICAL"}})
    a.score = min(a.score, 100)
    check("KEV+ransomware+EPSS+critical -> 100", a.score == 100)
    check("severity critical", mod._severity_for(a.score) == "critical")

    # Not exploited, moderate EPSS, high CVSS -> not critical
    b = mod.Assessment("CVE-2024-0001", "cve")
    mod.score_cve(b, {"kev": {"known_exploited": False},
                      "epss": {"has_score": True, "epss": 0.12},
                      "nvd": {"cvss_severity": "HIGH"}})
    check("no KEV -> below critical", mod._severity_for(min(b.score, 100)) != "critical")
    check("moderate signals scored", 0 < b.score < 55)


def test_severity_bands():
    print("Severity banding:")
    check("0 -> informational", mod._severity_for(0) == "informational")
    check("15 -> low", mod._severity_for(15) == "low")
    check("40 -> medium", mod._severity_for(40) == "medium")
    check("60 -> high", mod._severity_for(60) == "high")
    check("85 -> critical", mod._severity_for(85) == "critical")


if __name__ == "__main__":
    test_classify()
    test_internal_guard()
    test_score_vt()
    test_score_cve()
    test_severity_bands()
    print("\nAll tests passed.")
