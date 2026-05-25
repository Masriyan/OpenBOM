# Threat Intelligence Model

> How OpenBOM layers multiple intelligence sources to prioritize supply chain threats.

## The Prioritization Problem

A typical Linux server with Python tooling installed has 3,000–5,000 packages. Scanning all of them against OSV.dev might return 20–80 known vulnerabilities. Patching all of them simultaneously is unrealistic in production. You need to know: **which ones actually matter right now?**

OpenBOM solves this by stacking six intelligence signals, each adding context that narrows the actionable set.

## Intelligence Layers

### Layer 1: Vulnerability Existence (OSV.dev)

**Question answered**: Does this package version have a known flaw?

**Source**: [OSV.dev](https://osv.dev) — Google's open, distributed vulnerability database that aggregates from PyPI, GitHub Advisories, NVD, and other sources.

**Method**: Batch query up to 1,000 packages at once via `POST /v1/querybatch`, then enrich each unique vulnerability ID via `GET /v1/vulns/{id}` to fetch severity data, affected ranges, and references.

**Signal strength**: Necessary but insufficient. Most vulns are theoretical — not all are exploitable in your deployment context.

---

### Layer 2: Severity Classification (CVSS v3)

**Question answered**: How bad is this flaw in theory?

**Source**: CVSS v3 vectors from OSV severity data + `database_specific.severity` fallback from GitHub Advisories.

**Method**: Parse the CVSS vector string (e.g., `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) and compute an approximate base score using attack vector, complexity, privilege, and impact metrics.

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

**Method**: Download the full KEV JSON catalog (cached for 24 hours), build a lookup set of CVE IDs, and cross-reference every CVE alias found in the scan results.

**Signal strength**: This is the highest-priority signal. If a CVE is in the KEV catalog, it is being actively weaponized against real organizations. CISA mandates that federal agencies patch KEV entries within their due dates.

**OpenBOM treatment**: KEV matches trigger:
- Blinking bright red `>>> CVE-XXXX` in CLI output
- Dedicated "CISA KEV — ACTIVELY EXPLOITED" alert panel
- Red gradient alert card in HTML/PDF reports
- Included in webhook alerts alongside CRITICAL findings

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

### Layer 6: Malware Heuristics (Zero-Day Catcher)

**Question answered**: Does this newly installed package contain suspicious code?

**Source**: Local filesystem scan of the package's installed files (site-packages for Python, node_modules for NPM).

**Method**: Regex-based pattern matching on `.py` and `.js` files, limited to 500 files per package and 512 KB per file.

**Detected patterns**:

| Pattern | Indicator |
|---------|-----------|
| `eval(base64.b64decode(...))` | Obfuscated code execution |
| `exec(__import__('base64')...)` | Dynamic base64 decoding |
| `os.system('https://...')` | Remote payload execution |
| `subprocess.call(['curl', '...'])` | Payload download |
| `pastebin.com/raw`, `ngrok.io` | C2 infrastructure references |
| `__import__('socket')`, `__import__('ctypes')` | Suspicious dynamic imports |

**Scope**: Only runs on packages labeled `[NEW]` by the diff engine. This prevents re-scanning the entire package inventory on every run and focuses analysis on the most recent changes — which is where supply chain attacks are most likely to appear.

**False positive management**: Some legitimate packages trigger heuristic patterns (e.g., `eventlet` uses `__import__('socket')` for monkey-patching). All heuristic findings are labeled `MALICIOUS_HEURISTIC` and flagged for manual review — they are not confirmed malware, they are investigation leads.

## Combined Threat Prioritization

OpenBOM's value is in the combination. Here's how the layers stack to produce actionable priority:

```
Priority 1 (IMMEDIATE)
├── is_kev = true                     → Actively exploited in the wild
├── vuln_id = MALICIOUS_HEURISTIC     → Possible malware on your system
└── Action: Patch/quarantine within hours

Priority 2 (URGENT)
├── severity = CRITICAL
├── epss_score > 10%
├── poc_links not empty
└── Action: Patch within 24-48 hours

Priority 3 (HIGH)
├── severity = CRITICAL or HIGH
├── epss_score > 1%
└── Action: Patch within 1 week

Priority 4 (STANDARD)
├── severity = HIGH or MEDIUM
├── fixed_version available
└── Action: Include in next maintenance window

Priority 5 (MONITOR)
├── severity = LOW or UNKNOWN
├── epss_score < 0.1%
└── Action: Track, no immediate action required
```

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
