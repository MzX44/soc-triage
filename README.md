# soc-triage

[![tests](https://github.com/MzX44/soc-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/MzX44/soc-triage/actions)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Public-source IOC triage for Tier-1 analysts.** Give it an IP, a domain, or a
CVE; it gathers threat intelligence from authoritative public feeds and returns a
**deterministic, rule-scored** assessment — risk 0–100, a severity band, and the
exact reasons behind the score.

The verdict is computed **in code**, not asked of an LLM. A security team can read
the scoring rules and audit every point. That is the difference between a tool
they'll run and "the AI said it's bad."

```text
$ ioc-triage CVE-2021-44228
Indicator : CVE-2021-44228  (cve)
Severity  : [CRITICAL]  risk score 100/100
Reasons   :
  - (+80) CISA KEV: actively exploited AND linked to ransomware campaigns.
  - (+25) EPSS: 94% probability of exploitation in 30 days.
  - (+15) NVD: CVSS severity CRITICAL.
Priority  : CRITICAL - actively exploited, linked to ransomware campaigns
```

## Why it exists

Tier-1 analysts burn time pivoting between tabs — VirusTotal, the NVD, CISA's KEV
list — to answer one question per indicator: *is this actually dangerous, right
now?* `soc-triage` answers it in one command, with a transparent score and no
black box.

## What it checks

| Indicator | Sources |
|---|---|
| **IP** | VirusTotal v3 reputation (vendor detections, ASN, country) |
| **Domain** | VirusTotal v3 reputation + domain creation date (newly-registered signal) |
| **CVE** | CISA KEV (actively exploited? ransomware-linked?) · EPSS (exploit probability) · NVD (CVSS) |

All sources are free and licence-clean. No scraping, no dark-web crawling — the
real-world-exploitation signal (CISA KEV + EPSS) is what commercial "zero-day
intel" is mostly selling anyway, from an authoritative source.

## Install

```bash
git clone https://github.com/MzX44/soc-triage.git
cd soc-triage
python3 -m venv venv && source venv/bin/activate
pip install .                 # gives you the `ioc-triage` command
cp .env.example .env          # then add your VirusTotal key
```

## Use

```bash
ioc-triage 45.146.164.110
ioc-triage suspicious-domain.xyz
ioc-triage CVE-2021-44228
ioc-triage 45.146.164.110 CVE-2021-44228 --json   # machine-readable for pipelines
```

## How the score works

Points accrue from evidence; the total maps to a severity band. The rules live in
`src/soc_triage/ioc_investigate.py` and are deliberately short and readable:

- **CVE in CISA KEV** → +65 (+80 if ransomware-linked). Being exploited in the
  wild is the strongest signal there is.
- **EPSS ≥ 0.5** → +25; **≥ 0.1** → +10.
- **VirusTotal**: ≥5 malicious → +60; ≥1 → +40; suspicious only → +20.
- A **clean VirusTotal result scores 0** — absence of detections is *not* proof of
  benign, and the tool never treats it as such.

Bands: `0–9 informational · 10–29 low · 30–54 medium · 55–79 high · 80+ critical`.

## Safety and compliance

- **Bring your own keys.** The tool calls providers with *your* API key, so the
  terms of use are between you and the provider. **VirusTotal's free/public API is
  non-commercial** — commercial users need a VirusTotal Premium key.
- **No internal data leaves your network.** Internal/RFC1918/CGNAT addresses are
  refused in code before any third-party call.
- **Decision support, not an oracle.** Output assists an analyst's judgement; it
  is not an authoritative verdict. Provided under the MIT licence with no warranty.

## Tests

```bash
python tests/test_threat_intel.py   # 13 checks
python tests/test_ioc.py            # 20 checks
```

Both run with **no network and no keys** — they feed captured samples shaped like
the real feeds, so they verify the parsing and the scoring, not your connectivity.
CI runs them on every push (Python 3.10 and 3.12).

## Roadmap

- [ ] Additional free enrichers (AbuseIPDB, AlienVault OTX, URLhaus)
- [ ] Vendor-agnostic connectors (Splunk / Sentinel / Elastic) for full ticket investigation
- [ ] CSV / STIX batch mode
- [ ] Optional LLM narrative summary (BYO provider)

## License

MIT © 2026 Antonio Misztal
