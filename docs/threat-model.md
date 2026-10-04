# Threat Intelligence Model

> How OpenBOM layers multiple intelligence sources to prioritize supply chain threats.

## The Prioritization Problem

A typical Linux server with Python tooling installed has 3,000–5,000 packages. Scanning all of them against OSV.dev might return 20–80 known vulnerabilities. Patching all of them simultaneously is unrealistic in production. You need to know: **which ones actually matter right now?**

OpenBOM solves this by stacking eight intelligence layers plus context signals (EOL, licenses, delta), each adding information that narrows the actionable set.

## Intelligence Layers

### Layer 1: Vulnerability Existence (OSV.dev)

**Question answered**: Does this package version have a known flaw?

**Source**: [OSV.dev](https://osv.dev) — Google's open, distributed vulnerability database that aggregates GitHub Advisories, PyPI, npm, Go, crates.io, RubyGems, Packagist, NuGet, Maven, Debian, Ubuntu, AlmaLinux, Rocky Linux, Alpine and more.

**Method**: Batch query up to 1,000 packages at once via `POST /v1/querybatch`, then enrich each unique vulnerability ID via `GET /v1/vulns/{id}` to fetch severity data, affected ranges, and references.

**Signal strength**: Necessary but insufficient. Most vulns are theoretical — not all are exploitable in your deployment context.

---

### Layer 2: Severity Classification (CVSS v3)

**Question answered**: How bad is this flaw in theory?

**Source**: CVSS v3 vectors from OSV severity data + `database_specific.severity` fallback from GitHub Advisories.

**Method**: Compute the exact CVSS v3.0/v3.1 base score from every CVSS_V3 vector in the record (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → 9.8) using the specification's formula and Roundup, and keep the highest. Without a usable vector, qualitative ratings are used: GitHub `database_specific.severity` (`MODERATE` → MEDIUM), Ubuntu priority, or RHEL-style summaries (`Important:` → HIGH). CVSS v4-only records fall back to these ratings.

**Classification**:

| Score | Severity |
|-------|----------|
| 9.0–10.0 | CRITICAL |
| 7.0–8.9 | HIGH |
| 4.0–6.9 | MEDIUM |
| 0.1–3.9 | LOW |

---

### Layer 3: Exploit Prediction (FIRST.org EPSS)

**Question answered**: How likely is this CVE to be exploited in the next 30 days?

**Source**: [FIRST.org EPSS](https://www.first.org/epss/) — the Exploit Prediction Scoring System, a machine learning model trained on real-world exploitation data.

**Method**: Extract CVE aliases from OSV vuln data, batch query the EPSS API (100 CVEs per request), and attach the probability score to each VulnDetail.

**Interpretation**:

| EPSS Score | Meaning | OpenBOM Action |
|------------|---------|----------------|
| > 10% | High exploit probability | Highlighted in red, dedicated alert panel |
| 1–10% | Moderate | Highlighted in amber |
| < 1% | Low | Dimmed in CLI/report |

**Why EPSS > CVSS alone**: A CVSS 9.8 vulnerability with 0.01% EPSS is theoretically devastating but practically unlikely to be weaponized. A CVSS 6.5 with 45% EPSS is far more dangerous in practice.

---

### Layer 4: Active Exploitation (CISA KEV)

**Question answered**: Is this CVE being exploited right now, in the wild?

**Source**: [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog — a curated list of CVEs with confirmed active exploitation.

**Method**: Download the full KEV JSON catalog (cached for 24 hours; a stale copy is used if the refresh fails), build a lookup set of CVE IDs, and cross-reference every CVE id attached to a finding — from the advisory id, `aliases`, Debian/Ubuntu `upstream` and Alma/Rocky `related` fields. KEV status is sticky on the backend once set.

**Signal strength**: This is the highest-priority signal. If a CVE is in the KEV catalog, it is being actively weaponized against real organizations. CISA mandates that federal agencies patch KEV entries within their due dates.

**OpenBOM treatment**: KEV matches trigger:
- Blinking bright red `>>> CVE-XXXX` in CLI output
- Dedicated "CISA KEV — ACTIVELY EXPLOITED" alert panel
- Red gradient alert card in HTML/PDF reports
- Included in webhook alerts alongside CRITICAL findings
- Red banner and KEV views in the console; exit code 2 regardless of `--fail-on` (except `never`)

---

### Layer 5: Public Exploit Code (PoC Detection)

**Question answered**: Is exploit code freely available for this vulnerability?

**Source**: OSV vulnerability `references[]` field, scanned for URLs matching known exploit repositories.

**Detected patterns**:
- `exploit-db.com` — Exploit Database
- `packetstormsecurity.com` — PacketStorm Security
- GitHub repositories with `poc`, `exploit`, or `cve-YYYY` in the name/path

**Signal strength**: The existence of a public PoC dramatically lowers the barrier to exploitation. Even unsophisticated attackers can weaponize a published PoC within hours.

---

### Layer 6: Known-Malicious Packages (OpenSSF via OSV)

**Question answered**: Is this exact package version a confirmed piece of malware?

**Source**: The [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) repository,
published through OSV with ids starting `MAL-` (fed by sandboxed dynamic analysis and vendor reports).

**Method**: Returned by the same OSV queries as vulnerabilities. Because MAL advisories carry no CVSS,
OpenBOM forces severity **CRITICAL**, sets `is_malicious`, and also honours GHSA records that alias a
`MAL-` id. Withdrawn advisories are ignored.

**Signal strength**: Highest. A match means the installed artefact is malware — remove it and treat the
host as compromised (rotate credentials, investigate persistence).

---

### Layer 7: Heuristic IOC Detection (zero-day catcher)

**Question answered**: Does a newly installed package contain malware-like code that no advisory knows yet?

**Source**: The installed files of PyPI/npm packages on the host (plus npm install hooks).

**Method**: Strong indicators (obfuscated `exec`/`eval`, reverse shells, miners, `curl | sh` install
hooks) produce a CRITICAL finding on their own; weak indicators (credential paths, chat-webhook
exfiltration, paste/tunnel hosts, shelling out to download tools, `.pth` auto-exec) only produce a HIGH
finding when two different categories co-occur. Scope: changed packages (`--diff`) or all packages
(`--heuristics all`). Full rule list: [Detection Rules](detection-rules.md).

**Signal strength**: Investigation lead. Tuned to zero false positives on a real 565-package
workstation, but findings still need manual review (`MALICIOUS_HEURISTIC`).

---

### Layer 8: Typosquat Suspicion

**Question answered**: Was the wrong package installed because its name is one keystroke away from a
popular one?

**Method**: Optimal-string-alignment distance of exactly 1 to a curated list of popular PyPI/npm names,
names of at least 5 characters, with an allowlist of legitimate look-alikes (`TYPOSQUAT_SUSPECT`, MEDIUM).

---

### Context signals (not vulnerabilities, but risk)

| Signal | Source | Why it matters |
|--------|--------|----------------|
| End-of-life OS / runtime | endoflife.date | No more security fixes — every future CVE stays open |
| License policy violation | package metadata, deps.dev | Legal/compliance risk; enforced with `--license-deny` |
| Delta labels | diff engine | Newly installed or downgraded packages are where supply-chain attacks land |
| Stale asset | backend (`OPENBOM_STALE_DAYS`) | Inventory may no longer reflect reality |
| Package location | agent (dist-info / node_modules / lockfile path) | Shows *which* copy to fix (one repo tree can hold many venvs) and spots packages living in unexpected places |

---

### Suppression with evidence

Findings an analyst has proven irrelevant are suppressed, not deleted: VEX documents and the ignore file
on the agent side (`suppressed` list in the report), triage decisions on the backend (fleet-wide or per
asset, exportable as OpenVEX). See [SBOM, VEX & Triage](sbom-and-vex.md).

## Combined Threat Prioritization

OpenBOM's value is in the combination. Findings are sorted malicious → heuristic → KEV → severity →
EPSS everywhere (CLI, reports, console), and the per-asset risk score weights them the same way.

```
Priority 0 (INCIDENT)
├── is_malicious = true (OSV MAL-*)    → Confirmed malware installed
└── Action: Remove now, isolate host, rotate credentials, investigate

Priority 1 (IMMEDIATE)
├── is_kev = true                      → Actively exploited in the wild
├── MALICIOUS_HEURISTIC (CRITICAL)     → Possible malware, unconfirmed
└── Action: Patch / quarantine within hours

Priority 2 (URGENT)
├── severity = CRITICAL
├── epss_score ≥ 10%
├── poc_links not empty
├── end-of-life OS on an exposed host
└── Action: Patch within 24–48 hours

Priority 3 (HIGH)
├── severity = CRITICAL or HIGH
├── epss_score ≥ 1%
├── MALICIOUS_HEURISTIC (HIGH), TYPOSQUAT_SUSPECT
└── Action: Patch / review within 1 week

Priority 4 (STANDARD)
├── severity = HIGH or MEDIUM, fixed_version available
├── license policy violations
└── Action: Next maintenance window

Priority 5 (MONITOR)
├── severity = LOW or UNKNOWN, epss_score < 0.1%
└── Action: Track; consider triage (not_affected) with justification
```

Risk score per asset: each distinct, non-suppressed vulnerability adds its severity weight
(CRITICAL 10, HIGH 6, MEDIUM 3, LOW/UNKNOWN 1), +15 if KEV, +20 if heuristic, +30 if known-malicious
and +10 × EPSS; the total is mapped to 0–100 with `100·(1−e^(−Σ/200))`.

## Threat Data Flow

```
          Package Installed on Endpoint
                    │
                    v
        ┌─── OSV.dev Query ───┐
        │                      │
        │  "Has known vulns?"  │
        │                      │
        └──────────┬───────────┘
                   │ YES
                   v
    ┌──────────────┼──────────────┐
    │              │              │
    v              v              v
  CVSS           EPSS         KEV Check
  Scoring       Scoring       (CISA)
    │              │              │
    v              v              v
 CRITICAL?    >10% likely?    Active in
   HIGH?       to exploit?    the wild?
    │              │              │
    └──────────────┼──────────────┘
                   │
                   v
            PoC References?
            (exploit-db, etc.)
                   │
                   v
          ┌────────────────┐
          │  PRIORITIZED   │
          │  THREAT LIST   │
          └────────────────┘
```
