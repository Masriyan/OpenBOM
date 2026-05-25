# Architecture

> System design, data flow, and database schema for the OpenBOM platform.

## Overview

OpenBOM follows a **hub-and-spoke model**: lightweight endpoint agents collect data independently, then push structured JSON payloads to a centralized backend for aggregation, correlation, and fleet-wide threat hunting.

```
Endpoints (Spokes)                    Backend (Hub)
+------------------+                  +-------------------+
| openbom_agent.py | ---POST JSON---> | FastAPI Server    |
| (RPM/Deb/PyPI/   |                  | (SQLAlchemy +     |
|  NPM/Podman)     |                  |  PostgreSQL)      |
+------------------+                  +-------------------+
        |                                      |
        v                                      v
  +------------+                        +--------------+
  | Local JSON |                        | Threat Hunt  |
  | HTML / PDF |                        | REST API     |
  | Reports    |                        | /api/v1/*    |
  +------------+                        +--------------+
```

## Agent Architecture

The endpoint agent is a single Python script (~1,400 lines) with no daemon requirements. It runs on-demand or via cron/systemd timer.

### Execution Pipeline

```
1. EXTRACTION
   ├── extract_os_packages()        → RPM or Debian packages
   ├── extract_python_packages()    → pip freeze --all
   ├── extract_npm_packages()       → npm list -g --json
   └── extract_podman_containers()  → podman exec rpm/dpkg inside containers

2. DIFF ANALYSIS (--diff)
   └── compute_diff()               → Compare with /tmp/openbom_last_state.json
                                       Label [NEW], [UPGRADED], [DOWNGRADED]

3. HEURISTIC IOC SCAN (on [NEW] packages only)
   └── scan_heuristics()            → Regex scan .py/.js for malware patterns
                                       eval(base64), os.system(url), pastebin/ngrok

4. OSV VULNERABILITY QUERY (--check-osv)
   ├── query_osv_batch()            → POST /v1/querybatch (batch of up to 1000)
   ├── _enrich_vulns()              → GET /v1/vulns/{id} (20 concurrent)
   └── parse_vuln_details()         → Extract severity, fixed version, PoC links

5. THREAT INTELLIGENCE ENRICHMENT (parallel via asyncio.gather)
   ├── query_epss()                 → GET FIRST.org EPSS API (batch 100)
   └── kev.load()                   → GET CISA KEV JSON catalog (24h cache)
       └── apply_kev()              → Cross-reference CVE aliases → is_kev flag

6. OUTPUT
   ├── render_summary_table()       → Rich CLI tables + alert panels
   ├── write_json_report()          → Structured JSON SBOM
   └── write_enterprise_reports()   → HTML (Jinja2+Tailwind) + PDF (WeasyPrint)

7. ALERTING
   └── send_webhook_alert()         → POST to Slack/Teams if CRITICAL or KEV found
```

### Caching Strategy

| Cache | Path | TTL | Contents |
|-------|------|-----|----------|
| OSV response cache | `/tmp/openbom_osv_cache.json` | 12 hours | Enriched vuln JSON per package (keyed by SHA256 of `name==version`) |
| KEV catalog cache | `/tmp/openbom_kev_cache.json` | 24 hours | Full CISA KEV JSON catalog (~1,600 entries) |
| Diff state | `/tmp/openbom_last_state.json` | Permanent | Previous scan's package list for delta comparison |

### Async Concurrency Model

```
asyncio event loop
├── OSV batch POST (sequential, 1 per 1000 packages)
│   └── Enrich vulns (20 concurrent GET requests via semaphore)
├── asyncio.gather(                        # Parallel execution
│   ├── query_epss()                       # FIRST.org EPSS batch
│   └── kev.load()                         # CISA KEV download
│   )
└── send_webhook_alert()                   # Fire-and-forget POST
```

## Backend Architecture

### Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| API framework | FastAPI 0.110+ | Async REST endpoints with auto-generated OpenAPI |
| ORM | SQLAlchemy 2.0 (async) | Database models with relationship mapping |
| Database | PostgreSQL + asyncpg | Production data store |
| Fallback DB | SQLite + aiosqlite | Zero-config development |
| Validation | Pydantic v2 | Request/response schema validation |

### Database Schema

```
+------------------+         +-------------------+         +----------------------+
|     assets       |         |   asset_package   |         |      packages        |
+------------------+         +-------------------+         +----------------------+
| id (PK)          |<---+    | asset_id (FK)     |    +--->| id (PK)              |
| hostname (UQ)    |    +----| package_id (FK)   |----+    | name                 |
| last_seen        |         | diff_label        |         | version              |
| last_scan_summary|         | scan_ts           |         | ecosystem            |
+------------------+         +-------------------+         +------+---------------+
                                                                  |
                                                    +-------------+-------------+
                                                    | package_vulnerability     |
                                                    +---------------------------+
                                                    | package_id (FK)           |
                                                    | vulnerability_id (FK)     |
                                                    +-------------+-------------+
                                                                  |
                                                    +-------------v-------------+
                                                    |     vulnerabilities       |
                                                    +---------------------------+
                                                    | id (PK)                   |
                                                    | vuln_id (UQ)              |
                                                    | severity                  |
                                                    | summary                   |
                                                    | fixed_version             |
                                                    | recommendation            |
                                                    | epss_score                |
                                                    | epss_percentile           |
                                                    | is_kev                    |
                                                    | kev_description           |
                                                    | is_heuristic              |
                                                    | poc_links (JSON)          |
                                                    | first_seen                |
                                                    +---------------------------+
```

### Relationships

- **Asset <-> Package**: Many-to-many via `asset_package`. A package (e.g., `requests==2.31.0`) can exist on multiple hosts. The junction table carries `diff_label` and `scan_ts` for per-scan context.
- **Package <-> Vulnerability**: Many-to-many via `package_vulnerability`. Multiple packages can share the same CVE, and a single package can have multiple vulnerabilities.

### Ingestion Flow

```
POST /api/v1/ingest (AgentPayload JSON)
│
├── Upsert Asset (by hostname)
│
├── For each package in payload.packages:
│   ├── Get or create Package (unique on name+version+ecosystem)
│   └── Link to Asset via asset_package (with diff_label, scan_ts)
│
└── For each finding in payload.osv_vulnerabilities:
    ├── Get or create Package (for the vuln's affected package)
    └── For each vuln detail:
        ├── Get or create Vulnerability (unique on vuln_id)
        │   - MALICIOUS_HEURISTIC entries get namespaced: "MALICIOUS_HEURISTIC::pkg_name"
        │   - All fields updated on re-ingest (EPSS scores, KEV status, etc.)
        └── Link Package <-> Vulnerability via package_vulnerability
```

### Router Organization

```
server/routers/
├── ingest.py       POST /api/v1/ingest
├── threats.py      GET  /api/v1/threats/{kev,heuristics,critical,high-epss,summary}
└── assets.py       GET  /api/v1/assets, /assets/{hostname}/packages, /assets/{hostname}/vulnerabilities
```

## Data Flow: End-to-End

```
1. Agent runs on endpoint
   $ python3 openbom_agent.py --check-osv --diff -o /tmp/scan.json

2. Agent produces JSON SBOM with embedded threat intel
   {
     "hostname": "web-01",
     "packages": [...3614 items...],
     "osv_vulnerabilities": [...23 findings with EPSS, KEV, PoC data...],
     "diff_summary": {"new": 5, "removed": 0, ...}
   }

3. JSON is POSTed to backend
   $ curl -X POST http://backend:8000/api/v1/ingest -d @/tmp/scan.json

4. Backend upserts all entities into PostgreSQL

5. SOC team queries threat hunting endpoints
   GET /api/v1/threats/kev           → "Which servers have actively exploited CVEs?"
   GET /api/v1/threats/heuristics    → "Which servers have malware IOC detections?"
   GET /api/v1/threats/critical      → "Show me all CRITICAL findings fleet-wide"
   GET /api/v1/threats/high-epss     → "What's most likely to be exploited next?"
```
