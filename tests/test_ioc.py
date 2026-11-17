#!/usr/bin/env python3
"""
Offline tests for ioc_investigate.py -- no network.

Covers classification and defanging, the internal IP/hostname guards (including
IPv6, IPv4-mapped, reserved and CGNAT), CVE scoring with KEV/EPSS floors and
score-vs-priority consistency, the severity bands, the corroboration
aggregation, the inconclusive (fail-closed) behaviour, and exit codes.
Run: python tests/test_ioc.py
"""
from soc_triage import ioc_investigate as mod
from soc_triage import connectors as C


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    assert cond, name


def test_classify_and_refang():
    print("Classification + defanging:")
    check("ipv4", mod.classify("45.146.164.110") == "ip")
    check("ipv6", mod.classify("2001:4860:4860::8888") == "ip")
    check("cve (lowercase)", mod.classify("cve-2021-44228") == "cve")
    check("domain", mod.classify("incendium-cdn.example.xyz") == "domain")
    check("email -> unknown", mod.classify("user@corp.com") == "unknown")
    check("url -> unknown", mod.classify("https://evil.com/login") == "unknown")
    check("ip:port -> unknown", mod.classify("10.0.0.5:443") == "unknown")
    check("junk -> unknown", mod.classify("hello world") == "unknown")
    # Refanging happens in investigate(); a defanged domain normalises to a domain.
    check("refang [.] -> domain", mod.classify(mod._refang("evil[.]com")) == "domain")
    check("refang hxxp URL -> unknown", mod.classify(mod._refang("hxxp://evil[.]com")) == "unknown")


def test_internal_ip_guard():
    print("Internal-IP guard (IPv4, IPv6, mapped, reserved, CGNAT):")
    internal = [
        "10.0.0.5", "192.168.1.1", "172.16.4.4",     # RFC 1918
        "100.97.48.128",                              # CGNAT
        "127.0.0.1", "169.254.0.1",                   # loopback, link-local
        "0.0.0.0", "192.0.2.10", "198.18.0.1",        # reserved / doc / benchmark
        "::1", "fd00::5", "fe80::1",                   # IPv6 loopback/ULA/link-local
        "::ffff:10.0.0.5",                            # IPv4-mapped RFC 1918
    ]
    for ip in internal:
        check(f"{ip} internal", mod.is_internal_ip(ip) is True)
    for ip in ("45.146.164.110", "8.8.8.8", "2001:4860:4860::8888"):
        check(f"{ip} public", mod.is_internal_ip(ip) is False)


def test_internal_host_guard():
    print("Internal-hostname guard:")
    for h in ("dc01.ad.internal", "payroll.corp.local", "server.lan", "localhost", "dc01"):
        check(f"{h} internal", mod.is_internal_host(h) is True)
    for h in ("example.com", "evil.xyz", "sub.domain.co.uk"):
        check(f"{h} public", mod.is_internal_host(h) is False)


def _r(source, verdict, weight, available=True, refused=False):
    return {"source": source, "available": available, "found": True, "refused": refused,
            "verdict": verdict, "weight": weight, "detail": f"{source} {verdict}"}


def test_corroboration():
    print("Corroboration aggregation:")
    s, _ = mod.aggregate_reputation([_r("VirusTotal", "malicious", "strong"),
                                     _r("AbuseIPDB", "malicious", "strong")])
    check("2 strong -> 85", s == 85)
    s, _ = mod.aggregate_reputation([_r("VirusTotal", "malicious", "strong"),
                                     _r("AbuseIPDB", "suspicious", "weak")])
    check("1 strong + 1 weak -> 70", s == 70)
    s, reasons = mod.aggregate_reputation([_r("VirusTotal", "malicious", "weak"),
                                           _r("AbuseIPDB", "clean", "none")])
    check("lone weak detection -> 15 (low)", s == 15)
    check("clean source surfaced", any("clean" in x for x in reasons))
    s, _ = mod.aggregate_reputation([_r("VirusTotal", "malicious", "weak"),
                                     _r("AbuseIPDB", "malicious", "weak")])
    check("2 weak -> 40 (medium)", s == 40)
    s, _ = mod.aggregate_reputation([_r("VirusTotal", "clean", "none"),
                                     _r("AbuseIPDB", "clean", "none")])
    check("all clean -> 0", s == 0)


def _band_and_priority(enr):
    """Mimic investigate(): band from score, priority from band."""
    score, _ = mod.score_cve(enr)
    band = mod._severity_for(score)
    return score, band, mod._PRIORITY[band]


def test_cve_floors_and_consistency():
    print("CVE floors + score/priority consistency:")
    # KEV + ransomware -> critical, whatever CVSS says.
    s, band, prio = _band_and_priority(
        {"kev": {"known_exploited": True, "known_ransomware_use": "Known"},
         "epss": {"has_score": True, "epss": 0.94}, "nvd": {"cvss_severity": "CRITICAL"}})
    check("KEV+ransomware -> critical", band == "critical" and prio == "CRITICAL")

    # Not in KEV, EPSS 0.97, CVSS CRITICAL -> high (EPSS floor), not medium.
    s, band, prio = _band_and_priority(
        {"kev": {"known_exploited": False}, "epss": {"has_score": True, "epss": 0.97},
         "nvd": {"cvss_severity": "CRITICAL"}})
    check("EPSS>=0.5 floors to high", band == "high" and prio == "HIGH")

    # In KEV, EPSS and NVD unavailable -> still critical (KEV floor).
    s, band, prio = _band_and_priority(
        {"kev": {"known_exploited": True}, "epss": {"has_score": False}, "nvd": {}})
    check("KEV alone -> critical", band == "critical" and prio == "CRITICAL")

    # Not in KEV, low EPSS, CVSS CRITICAL -> low, and priority matches the band.
    s, band, prio = _band_and_priority(
        {"kev": {"known_exploited": False}, "epss": {"has_score": True, "epss": 0.02},
         "nvd": {"cvss_severity": "CRITICAL"}})
    check("low EPSS + critical CVSS -> low", band == "low")
    check("priority always matches band", prio == mod._PRIORITY[band])


def test_severity_bands():
    print("Severity banding:")
    for score, band in [(0, "informational"), (15, "low"), (40, "medium"),
                        (60, "high"), (85, "critical")]:
        check(f"{score} -> {band}", mod._severity_for(score) == band)


class _FakeConn(C.Connector):
    """A connector whose query() returns a fixed result (uses the real lookup())."""
    def __init__(self, result, types=("ip",)):
        super().__init__()
        self._result = result
        self.supports = types
    def query(self, indicator, indicator_type):
        return self._result


def test_investigate_outcomes():
    print("investigate() outcomes (injected connectors, no network):")
    # One weak + one clean -> low.
    conns = [_FakeConn(_r("VirusTotal", "malicious", "weak")),
             _FakeConn(_r("AbuseIPDB", "clean", "none"))]
    a = mod.investigate("45.146.164.110", conns)
    check("weak+clean -> low", a.severity == "low" and a.priority == "LOW")

    # All sources unavailable -> inconclusive, NOT informational/clean.
    conns = [_FakeConn(_r("VirusTotal", "unknown", "none", available=False)),
             _FakeConn(_r("AbuseIPDB", "unknown", "none", available=False))]
    a = mod.investigate("45.146.164.110", conns)
    check("all sources down -> inconclusive", a.severity == "inconclusive")
    check("inconclusive priority", a.priority == "INCONCLUSIVE")

    # Internal indicator refused by every source -> not scored, informational.
    conns = [_FakeConn(C._refused_internal("VirusTotal", "10.0.0.5"))]
    a = mod.investigate("10.0.0.5", conns)
    check("internal -> informational, not scored", a.severity == "informational" and a.score == 0)

    # Defanged domain is normalised and looked up as a domain.
    conns = [_FakeConn(_r("URLhaus", "malicious", "strong"), types=("domain",))]
    a = mod.investigate("evil[.]com", conns)
    check("defanged domain investigated", a.indicator == "evil.com" and a.kind == "domain")


def test_exit_codes():
    print("Exit codes:")
    hi = mod.Assessment("x", "ip", severity="high")
    lo = mod.Assessment("y", "ip", severity="low")
    inc = mod.Assessment("z", "cve", severity="inconclusive")
    check("high -> 1", mod._exit_code([hi, lo]) == 1)
    check("inconclusive -> 2", mod._exit_code([hi, inc]) == 2)
    check("nothing actionable -> 0", mod._exit_code([lo]) == 0)


if __name__ == "__main__":
    test_classify_and_refang()
    test_internal_ip_guard()
    test_internal_host_guard()
    test_corroboration()
    test_cve_floors_and_consistency()
    test_severity_bands()
    test_investigate_outcomes()
    test_exit_codes()
    print("\nAll tests passed.")
