#!/usr/bin/env python3
"""
Offline tests for threat_intel.py.

These do NOT touch the network. They feed captured samples shaped exactly like
the real CISA KEV / EPSS / NVD responses, so parsing (including CVSS 4.0) and the
KEV staleness guard are verified deterministically. Run: python test_threat_intel.py
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
    check("cvss version", r["cvss_version"] == "3.1")
    check("description extracted", "Log4Shell" in r["description"])


def test_nvd_cvss40():
    print("NVD CVSS 4.0 parsing (was previously ignored):")
    sample = {"vulnerabilities": [{"cve": {
        "id": "CVE-2026-0001", "descriptions": [{"lang": "en", "value": "x"}],
        "metrics": {"cvssMetricV40": [{"cvssData": {"baseScore": 9.3, "baseSeverity": "CRITICAL"}}]},
    }}]}
    ti._get = _ok(sample)
    r = ti.nvd_lookup("CVE-2026-0001")
    check("reads CVSS 4.0 severity", r["cvss_severity"] == "CRITICAL")
    check("labels version 4.0", r["cvss_version"] == "4.0")


def test_enrich():
    print("Combined enrich (evidence only, no separate priority):")
    ti._get = lambda url, params=None, headers=None: _FakeResp(
        EPSS_SAMPLE if "epss" in url else NVD_SAMPLE)
    out = ti.enrich_cve("CVE-2021-44228", kev_catalogue=KEV_CATALOGUE)
    check("actively_exploited true", out["actively_exploited"] is True)
    check("no separate priority key", "priority" not in out)
    check("kev evidence present", out["kev"]["known_exploited"] is True)
    check("epss evidence present", out["epss"]["has_score"] is True)


def test_kev_staleness(_orig_load):
    print("KEV staleness guard:")
    # A stale catalogue that cannot be refreshed is reported unavailable.
    ti._load_kev_catalogue = lambda force_refresh=False: {
        "vulns": {}, "catalog_version": "old", "age_seconds": 90 * 3600, "stale": True}
    r = ti.kev_lookup("CVE-2021-44228")
    check("stale KEV -> unavailable", r["available"] is False)
    check("stale note mentions staleness", "stale" in r.get("note", "").lower())
    # A fresh catalogue is used normally and reports its version.
    ti._load_kev_catalogue = lambda force_refresh=False: {
        "vulns": {"CVE-2021-44228": KEV_CATALOGUE["CVE-2021-44228"]},
        "catalog_version": "2026.11.17", "age_seconds": 100.0, "stale": False}
    r = ti.kev_lookup("CVE-2021-44228")
    check("fresh KEV available", r["available"] is True and r["known_exploited"] is True)
    check("catalogue version surfaced", r["catalog_version"] == "2026.11.17")


def test_extract_and_validate():
    print("CVE extraction + validation:")
    cves = ti.extract_cves("Alert references CVE-2021-44228 and cve-2023-23397, dup CVE-2021-44228.")
    check("extracts + dedupes", cves == ["CVE-2021-44228", "CVE-2023-23397"])
    check("rejects junk", "error" in ti.enrich_cve("not-a-cve"))


if __name__ == "__main__":
    _orig_get = ti._get
    _orig_load = ti._load_kev_catalogue
    try:
        test_kev()
        test_epss(None)
        test_nvd()
        test_nvd_cvss40()
        test_enrich()
        test_kev_staleness(_orig_load)
        test_extract_and_validate()
    finally:
        ti._get = _orig_get
        ti._load_kev_catalogue = _orig_load
    print("\nAll tests passed.")
