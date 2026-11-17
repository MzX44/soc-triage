# soc-triage

[![tests](https://github.com/MzX44/soc-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/MzX44/soc-triage/actions)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Public-source IOC triage for Tier-1 analysts.** Give it an IP, a domain, or a
CVE; it gathers threat intelligence from authoritative public feeds and returns a
**deterministic, rule-scored** assessment — risk 0–100, a severity band, and the
exact reasons behind the score.

The verdict is computed **in code**, not asked of an LLM, so every point in the
score is reproducible and can be audited against the rules in the source.

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
| **IP** | VirusTotal v3 + AbuseIPDB + URLhaus (three independent reputations, corroborated) |
| **Domain** | VirusTotal v3 + URLhaus active-malware-host feed (corroborated) + domain creation date |
| **CVE** | CISA KEV (actively exploited? ransomware-linked?) · EPSS (exploit probability) · NVD (CVSS) |

All sources are free, public, and licence-clean. The exploitation signals (CISA
KEV and EPSS) come directly from authoritative upstreams.

## Multiple sources, corroborated

Reputation comes from several independent connectors, and the score reflects **how
many agree** — one source's flag is a lead, not a verdict:

- **2+ sources flag it strongly** → critical.
- **1 strong source** → high.
- **2 sources agree weakly** → medium.
- **1 weak flag, others clean** → low. A single low-confidence detection is
  treated as a lead, not a verdict.

### Add any feed without touching the code

Connectors are declared in `config.yaml` (copy `config.example.yaml`). Ship with
VirusTotal + AbuseIPDB, or point the **generic REST connector** at any key-auth
HTTP API — name the field to read and you're done. Keys live in your environment,
never in the YAML:

```yaml
connectors:
  - type: virustotal
    api_key_env: VIRUSTOTAL_API_KEY
  - type: abuseipdb
    api_key_env: ABUSEIPDB_API_KEY
  - type: urlhaus            # abuse.ch malware-host lookup
    api_key_env: URLHAUS_AUTH_KEY
```

> **URLhaus needs a free abuse.ch Auth-Key** (grab one at auth.abuse.ch) — abuse.ch
> moved all of its services behind free authentication in 2024–25. It gives *domains*
> a second, independent opinion. Without the key it's simply skipped; the other
> sources still run.

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

Scoring is deterministic and lives in `src/soc_triage/ioc_investigate.py`.

**CVEs** accrue additive points from exploitation evidence:

- **In CISA KEV** → +65, or +80 if linked to ransomware campaigns.
- **EPSS ≥ 0.5** → +25; **≥ 0.1** → +10.
- **CVSS CRITICAL** → +15; **HIGH** → +8.

**IPs and domains** are scored by corroboration across the configured sources.
Each source returns a normalised verdict with a confidence weight (`strong`,
`weak`, or none); the aggregate reflects how many independent sources agree:

| Signals | Score | Band |
|---|---|---|
| 2 or more strong | 85 | critical |
| 1 strong + at least 1 weak | 70 | high |
| 1 strong | 55 | high |
| 2 or more weak | 40 | medium |
| 1 weak | 15 | low |
| none | 0 | informational |

How each source maps to a weight:

- **VirusTotal** — 3 or more vendors malicious → strong; 1–2 → weak; suspicious only → weak.
- **AbuseIPDB** — abuse confidence ≥ 50 → strong; 25–49 → weak.
- **URLhaus** — a currently-online malware URL on the host → strong; only historical URLs → weak.
- **Newly registered domain** — a VirusTotal creation date within 30 days adds a weak signal.

A clean result from any source scores nothing on its own; absence of detections
is not treated as proof that an indicator is benign.

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
python tests/test_threat_intel.py   # CVE enrichment parsing + priority
python tests/test_ioc.py            # classification, corroboration scoring, bands
python tests/test_connectors.py     # each connector's verdict mapping + config loader
```

All run with **no network and no keys** — they feed captured samples shaped like
the real feeds, so they verify the parsing and the scoring, not your connectivity.
CI runs them on every push (Python 3.10 and 3.12).

## Roadmap

- [x] Multi-source corroboration (VirusTotal + AbuseIPDB + URLhaus)
- [x] Config-driven, vendor-agnostic connectors (`config.yaml` + generic REST)
- [x] Domain corroboration (URLhaus host API)
- [ ] More free enrichers (AlienVault OTX, Spamhaus DROP) via config
- [ ] Connectors for full ticket investigation (Splunk / Sentinel / Elastic)
- [ ] CSV / STIX batch mode
- [ ] Optional LLM narrative summary (BYO provider)

## License

MIT © 2026 Antonio Misztal
