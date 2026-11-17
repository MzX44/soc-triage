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
Severity  : [CRITICAL]  risk score 90/100
Reasons   :
  - CISA KEV: actively exploited AND linked to ransomware campaigns.
  - EPSS: 97% probability of exploitation in 30 days.
  - NVD: CVSS v3.1 severity CRITICAL.
Priority  : CRITICAL
```

The exit code reflects the outcome so a pipeline can branch without parsing JSON:
`0` nothing actionable, `1` a high/critical finding, `2` inconclusive.

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

All sources are free and public, and the exploitation signals (CISA KEV and EPSS)
come directly from authoritative upstreams. They are **not** all cleared for
commercial resale — see [Licensing and commercial use](#licensing-and-commercial-use).

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

**CVEs** are scored so the band always agrees with the exploitation evidence.
Confirmed or predicted exploitation sets a floor that CVSS cannot out-vote:

- **In CISA KEV** → floor at **critical** (80, or 90 if ransomware-linked).
- **EPSS ≥ 0.5** → floor at **high** (55).
- Below those floors, **EPSS 0.1–0.5** adds 10 and **CVSS CRITICAL/HIGH** adds 15/8.

The printed priority is derived from the final band, so the score and the
priority line cannot disagree. CVSS 4.0 is read (not just 3.x/2.0), and if the
CISA KEV feed cannot be reached the CVE is reported **inconclusive**, not scored.

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

**Fail closed, not open.** If every configured source is unreachable (keys
missing, quota exhausted, or network down), the result is **inconclusive** with
exit code 2 — never a clean-looking `INFO 0/100`. A missing answer is reported,
not scored as reassurance.

## Safety and compliance

- **Bring your own keys.** The tool calls providers with *your* API key, so the
  terms of use are between you and the provider (see Licensing below).
- **No internal data leaves your network.** Internal, loopback, link-local,
  reserved, CGNAT and IPv4-mapped IPv6 addresses — and internal hostnames
  (`*.local`, `*.internal`, `*.corp`, single-label names, `localhost`) — are
  refused in code before any third-party call. Emails, URLs and `host:port`
  strings are not treated as indicators; defanged input (`evil[.]com`, `hxxp://`)
  is normalised first.
- **Decision support, not an oracle.** Output assists an analyst's judgement; it
  is not an authoritative verdict. Provided under the MIT licence with no warranty.

## Licensing and commercial use

The tool's own code is MIT. The **data** each source returns is not: some feeds
are free for personal or non-profit use but restrict commercial use. These terms
are between you and each provider (bring-your-own-key). This table is a guide, not
legal advice — confirm with each provider before charging anyone.

| Source | Free tier | Commercial use |
|---|---|---|
| VirusTotal (public API) | 500/day, 4/min | **Not permitted** — commercial users need a VirusTotal Premium key |
| URLhaus (abuse.ch) | free Auth-Key | Non-profit only; commercial use may require a paid Spamhaus subscription |
| AbuseIPDB | 1,000/day | Governed by its Terms of Use; confirm before resale |
| CISA KEV | unlimited | Public domain (CC0) |
| NVD | free (rate-limited) | Public domain, attribution requested (see below) |
| EPSS (FIRST) | free API | Check FIRST's terms |

A commercial deployment can set `require_commercial_use: true` in `config.yaml` to
drop any source not cleared for commercial use (each connector carries a
`commercial_ok` flag). For a commercial-safe build, abuse.ch's Feodo Tracker and
SSL Blocklist (CC0) are good drop-in feeds via the generic REST connector.

> This product uses data from the NVD API but is not endorsed or certified by the
> NVD.

## Tests

```bash
python tests/test_threat_intel.py   # KEV/EPSS/NVD parsing, CVSS 4.0, KEV staleness
python tests/test_ioc.py            # classify/defang, guards, CVE floors, bands, exit codes
python tests/test_connectors.py     # verdict mapping, retries, URL-encoding, config loader
```

All run with **no network and no keys** — they feed captured samples shaped like
the real feeds, so they verify the parsing and the scoring, not your connectivity.
They cover IPv6/mapped/reserved addresses, defanged input, 429 retries,
all-sources-down (inconclusive), and score-vs-priority consistency. CI runs them
on every push (Python 3.10 and 3.12).

## Roadmap

- [x] Multi-source corroboration (VirusTotal + AbuseIPDB + URLhaus)
- [x] Config-driven, vendor-agnostic connectors (`config.yaml` + generic REST)
- [x] Domain corroboration (URLhaus host API)
- [x] Inconclusive/fail-closed handling, exit codes, retry + backoff
- [ ] GreyNoise Community connector (a "known benign / internet noise" signal)
- [ ] Commercial-safe feeds (Feodo Tracker, SSL Blocklist) and a published accuracy benchmark
- [ ] Connectors for full ticket investigation (Splunk / Sentinel / Elastic)
- [ ] CSV / STIX batch mode, stdin, and concurrency
- [ ] Optional LLM narrative summary (BYO provider) over a versioned JSON schema

## License

MIT © 2026 Antonio Misztal
