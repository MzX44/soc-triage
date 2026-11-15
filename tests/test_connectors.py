#!/usr/bin/env python3
"""
Offline tests for connectors.py + config.py -- no network.

Feeds captured samples shaped like the real VirusTotal / AbuseIPDB responses and
checks each connector's normalised verdict + weight, the internal-IP refusal, the
generic REST connector's dotted-path extraction, and the config loader's env-key
resolution + skip-when-no-key behaviour. Run: python tests/test_connectors.py
"""
import os
from soc_triage import connectors as C
from soc_triage import config as cfg


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    assert cond, name


class _FakeResp:
    def __init__(self, payload, status=200):
        self._p, self.status_code = payload, status
    def json(self):
        return self._p


def _patch(conn, payload, status=200):
    conn._get = lambda url, **kw: _FakeResp(payload, status)


# --- VirusTotal ------------------------------------------------------------- #
def test_virustotal():
    print("VirusTotal connector mapping:")
    c = C.VirusTotalConnector(api_key="x")
    _patch(c, {"data": {"attributes": {"last_analysis_stats":
             {"malicious": 8, "suspicious": 0, "harmless": 50, "undetected": 36}}}})
    r = c.query("45.146.164.110", "ip")
    check("8 malicious -> strong", r["verdict"] == "malicious" and r["weight"] == "strong")

    _patch(c, {"data": {"attributes": {"last_analysis_stats":
             {"malicious": 1, "suspicious": 0, "harmless": 93, "undetected": 0}}}})
    r = c.query("8.8.8.8", "ip")
    check("1 malicious -> weak", r["verdict"] == "malicious" and r["weight"] == "weak")

    _patch(c, {"data": {"attributes": {"last_analysis_stats":
             {"malicious": 0, "suspicious": 0, "harmless": 94, "undetected": 0}}}})
    r = c.query("8.8.8.8", "ip")
    check("0 malicious -> clean/none", r["verdict"] == "clean" and r["weight"] == "none")


def test_virustotal_internal_refused():
    print("VirusTotal refuses internal IP (no call):")
    c = C.VirusTotalConnector(api_key="x")
    _patch(c, {"should": "not be used"})
    r = c.query("10.0.0.5", "ip")
    check("internal refused", r["available"] is False and "internal" in r["detail"])


def test_abuseipdb():
    print("AbuseIPDB connector mapping:")
    c = C.AbuseIPDBConnector(api_key="x")
    _patch(c, {"data": {"abuseConfidenceScore": 80, "totalReports": 42, "isp": "x"}})
    r = c.query("45.146.164.110", "ip")
    check("conf 80 -> strong malicious", r["verdict"] == "malicious" and r["weight"] == "strong")

    _patch(c, {"data": {"abuseConfidenceScore": 30, "totalReports": 2}})
    r = c.query("45.146.164.110", "ip")
    check("conf 30 -> weak malicious", r["verdict"] == "malicious" and r["weight"] == "weak")

    _patch(c, {"data": {"abuseConfidenceScore": 0, "totalReports": 0}})
    r = c.query("8.8.8.8", "ip")
    check("conf 0 -> clean", r["verdict"] == "clean" and r["weight"] == "none")


def test_generic_rest():
    print("Generic REST connector (dotted-path extraction):")
    c = C.GenericRestConnector(display_name="MyFeed", url="https://x/{indicator}",
                               supports=["ip"], auth_header="X-Api-Key", api_key="k",
                               malicious_field="data.hits", malicious_strong_at=5)
    _patch(c, {"data": {"hits": 9}})
    r = c.query("1.2.3.4", "ip")
    check("hits 9 >= 5 -> strong", r["weight"] == "strong")
    _patch(c, {"data": {"hits": 2}})
    r = c.query("1.2.3.4", "ip")
    check("hits 2 -> weak", r["weight"] == "weak")
    check("declares configured support", c.handles("ip") and not c.handles("domain"))


def test_urlhaus():
    print("URLhaus connector (host API, no network):")
    c = C.URLhausConnector(api_key="k")
    # Patch requests.post via the module so no network is used.
    def fake_post(payload):
        return lambda url, data=None, headers=None, timeout=None: _FakeResp(payload)

    orig_post = C.requests.post
    try:
        # Active (online) malware URLs -> strong.
        C.requests.post = fake_post({"query_status": "ok", "url_count": 3,
            "urls": [{"url_status": "online"}, {"url_status": "offline"}]})
        hit = c.query("evil-malware.example", "domain")
        check("online malware URL -> strong", hit["verdict"] == "malicious" and hit["weight"] == "strong")

        # Only historical (offline) URLs -> weak.
        C.requests.post = fake_post({"query_status": "ok", "url_count": 2,
            "urls": [{"url_status": "offline"}, {"url_status": "offline"}]})
        hist = c.query("old-bad.example", "domain")
        check("historical only -> weak", hist["verdict"] == "malicious" and hist["weight"] == "weak")

        # No results -> clean.
        C.requests.post = fake_post({"query_status": "no_results"})
        clean = c.query("good-domain.example", "domain")
        check("no_results -> clean", clean["verdict"] == "clean" and clean["weight"] == "none")

        # Internal IP refused before any call.
        refused = c.query("10.0.0.5", "ip")
        check("internal IP refused", refused["available"] is False)

        # No key -> unavailable, no call.
        nokey = C.URLhausConnector(api_key=None).query("x.example", "domain")
        check("no key -> unavailable", nokey["available"] is False and "AUTH_KEY" in nokey["detail"])
    finally:
        C.requests.post = orig_post


def test_registry():
    print("Registry + build:")
    c = C.build("abuseipdb", api_key="z")
    check("build returns right type", isinstance(c, C.AbuseIPDBConnector))
    try:
        C.build("nope")
        check("unknown type raises", False)
    except KeyError:
        check("unknown type raises", True)


def test_config_loader():
    print("Config loader (defaults, env resolution, skip-no-key):")
    os.environ.pop("ABUSEIPDB_API_KEY", None)
    os.environ["VIRUSTOTAL_API_KEY"] = "present"
    conns = cfg.load_connectors(config_path=None)  # no file -> defaults
    names = {type(c).__name__ for c in conns}
    check("VT loaded (key present)", "VirusTotalConnector" in names)
    check("AbuseIPDB skipped (no key)", "AbuseIPDBConnector" not in names)

    os.environ["ABUSEIPDB_API_KEY"] = "present"
    conns = cfg.load_connectors(config_path=None)
    names = {type(c).__name__ for c in conns}
    check("AbuseIPDB loaded once key present", "AbuseIPDBConnector" in names)


if __name__ == "__main__":
    test_virustotal()
    test_virustotal_internal_refused()
    test_abuseipdb()
    test_generic_rest()
    test_urlhaus()
    test_registry()
    test_config_loader()
    print("\nAll tests passed.")
