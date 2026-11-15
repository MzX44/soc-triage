#!/usr/bin/env python3
"""
Offline tests for threat_intel.py.

These do NOT touch the network. They feed captured samples shaped exactly like
the real CISA KEV / EPSS / NVD responses, so the parsing and the triage-priority
logic are verified deterministically. Run: python test_threat_intel.py
"""
import json
from soc_triage import threat_intel as ti


# --- Captured response samples (trimmed, real field shapes) ----------------- #
KEV_CATALOGUE = {
    "CVE-2021-44228": {  # Log4Shell: exploited + ransomware
        "cveID": "CVE-2021-44228",
        "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
        "vendorProject": "Apache", "product": "Log4j2",
        "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
        "knownRansomwareCampaignUse": "Known",
        "requiredAction": "Apply updates per vendor instructions.",
    },
}

EPSS_SAMPLE = {"status": "OK", "data": [
    {"cve": "CVE-2021-44228", "epss": "0.944260000", "percentile": "0.999870000",
     "date": "2026-11-15"}]}

NVD_SAMPLE = {"vulnerabilities": [{"cve": {
    "id": "CVE-2021-44228", "published": "2021-12-10T10:15:09.143",
    "descriptions": [{"lang": "en", "value": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints (Log4Shell)."}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}]},
}}]}


class _FakeResp:
    def __init__(self, payload, status=200):
        self._p, self.status_code = payload, status
    def json(self):
        return self._p


def _ok(payload):
    return lambda url, params=None, headers=None: _FakeResp(payload)


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    assert cond, name


def test_kev():
    print("KEV lookup (catalogue injected, no network):")
    hit = ti.kev_lookup("cve-2021-44228", catalogue=KEV_CATALOGUE)
    check("case-insensitive match", hit["known_exploited"] is True)
    check("ransomware flag parsed", hit["known_ransomware_use"] == "Known")
    miss = ti.kev_lookup("CVE-2000-0001", catalogue=KEV_CATALOGUE)
    check("non-KEV CVE -> not exploited", miss["known_exploited"] is False)


def test_epss(monkey):
    print("EPSS parsing:")
    ti._get = _ok(EPSS_SAMPLE)
    r = ti.epss_lookup("CVE-2021-44228")
    check("epss parsed as float", abs(r["epss"] - 0.94426) < 1e-6)
    check("percentile parsed", r["percentile"] > 0.99)


def test_nvd():
    print("NVD parsing:")
    ti._get = _ok(NVD_SAMPLE)
    r = ti.nvd_lookup("CVE-2021-44228")
    check("cvss base score", r["cvss_base_score"] == 10.0)
    check("severity", r["cvss_severity"] == "CRITICAL")
    check("description extracted", "Log4Shell" in r["description"])


def test_priority_and_enrich():
    print("Combined enrich + priority (all signals injected):")
    # Point every network call at the canned samples, KEV via catalogue.
    ti._get = lambda url, params=None, headers=None: _FakeResp(
        EPSS_SAMPLE if "epss" in url else NVD_SAMPLE)
    out = ti.enrich_cve("CVE-2021-44228", kev_catalogue=KEV_CATALOGUE)
    check("actively_exploited true", out["actively_exploited"] is True)
    check("priority is CRITICAL+ransomware", out["priority"].startswith("CRITICAL") and "ransomware" in out["priority"])

    # A CVE not in KEV but with high EPSS -> HIGH, not CRITICAL.
    high_epss = {"status": "OK", "data": [{"cve": "CVE-2024-0001", "epss": "0.70",
                 "percentile": "0.9", "date": "2026-11-15"}]}
    ti._get = lambda url, params=None, headers=None: _FakeResp(
        high_epss if "epss" in url else {"vulnerabilities": []})
    out2 = ti.enrich_cve("CVE-2024-0001", kev_catalogue=KEV_CATALOGUE)
    check("not exploited -> not CRITICAL", not out2["priority"].startswith("CRITICAL"))
    check("high EPSS -> HIGH", out2["priority"].startswith("HIGH"))


def test_extract_and_validate():
    print("CVE extraction + validation:")
    cves = ti.extract_cves("Alert references CVE-2021-44228 and cve-2023-23397, dup CVE-2021-44228.")
    check("extracts + dedupes", cves == ["CVE-2021-44228", "CVE-2023-23397"])
    check("rejects junk", "error" in ti.enrich_cve("not-a-cve"))


if __name__ == "__main__":
    _orig = ti._get
    try:
        test_kev()
        test_epss(None)
        test_nvd()
        test_priority_and_enrich()
        test_extract_and_validate()
    finally:
        ti._get = _orig
    print("\nAll tests passed.")
