# Architecture

> System design, data flow and data model of OpenBOM (agent 5.1, backend 2.1).

## Overview

OpenBOM follows a **hub-and-spoke model**: a single-file agent collects and analyses inventories
wherever it runs (hosts, CI, image builds), then pushes structured JSON to a central backend for fleet
correlation, triage and continuous monitoring. The backend can also ingest SBOMs from other tools and
analyse them itself by importing the agent's engine.

```
 Spokes                                              Hub
┌───────────────────────────┐   POST /api/v1/ingest   ┌──────────────────────────────────┐
│ agent/openbom_agent.py    │ ──────────────────────► │ FastAPI (server/)                │
│ host · --path · --image   │                         │  routers: ingest, threats,       │
│ --rootfs · --sbom         │                         │   assets, hunt, governance       │
│ OSV · MAL · KEV · EPSS    │                         │  analyzer.py ──imports──► agent  │
│ EOL · heuristics · VEX    │                         │  SQLAlchemy (PostgreSQL/SQLite)  │
└────────────┬──────────────┘                         │  /static: Arco Design console    │
             │ local outputs                          └──────────────┬───────────────────┘
             v                                                       │ POST /api/v1/sbom
   JSON · CycloneDX · SPDX · SARIF · HTML/PDF          Syft / Trivy / cdxgen SBOMs ──┘
```

## Agent architecture

The agent is one Python file with no daemon. Importing it has no side effects (logging is configured
in `main()`), which lets the backend reuse it.

### Execution pipeline (`run_scan`)

```
1. COLLECT
   ├── host (default)                 extract_os_packages (rpm | dpkg | apk), extract_python_packages,
   │                                  extract_npm_packages, extract_containers (podman, docker)
   └── targets (replace the host)     collect_target_packages
       ├── --sbom   parse_sbom_document (CycloneDX / SPDX) → package_from_purl
       ├── --image  export_image (podman|docker create + export, safe tar filter) → scan_rootfs
       ├── --rootfs scan_rootfs (dpkg status, apk db, rpm --root) → scan_path
       └── --path   scan_path → LOCKFILE_PARSERS, requirements, dist-info, node_modules, JAR/WAR

2. DIFF (--diff)                      compute_diff → <state>/last_state[_<target hash>].json
                                      [NEW] / [UPGRADED] / [DOWNGRADED] with rpm/dpkg/PEP 440/semver ordering

3. HEURISTICS (--heuristics)          scan_heuristics (installed host packages only; strong/weak indicators)
                                      check_typosquat (any PyPI/npm package)

4. LICENSES                           enrich_licenses_deps_dev (--deps-dev) → check_licenses (--license-deny)

5. VULNERABILITIES (--check-osv)
   ├── query_osv_batch                POST /v1/querybatch (1000/batch, next_page_token followed)
   ├── _enrich_vulns                  GET /v1/vulns/{id} (20 concurrent, retry/backoff)
   └── parse_vuln_details             CVSS 3.1 score, range-aware fix, PoC links, CVE aliases,
                                      alias de-dup, MAL-* → mark_malicious

6. ENRICHMENT (asyncio.gather)        KevCatalog.load ‖ query_epss ‖ check_eol → apply_kev

7. MERGE & SUPPRESS                   merge_results (heuristic findings onto package results)
                                      apply_suppressions (--vex, --ignore) → report.suppressed

8. OUTPUT                             render_summary_table, write_json_report, write_cyclonedx,
                                      to_spdx, to_sarif, write_enterprise_reports (HTML/PDF)

9. DELIVERY                           send_webhook_alert, push_to_server → exit_code_for
```

### Package identity

Each `Package` has a display identity (`name`, `version`, `ecosystem`) and optional OSV query
coordinates (`osv_ecosystem`, `osv_name`, `osv_version`) because distros publish advisories by
**source** package (Debian/Ubuntu), origin (Alpine) and with **epoch** (RPM). Container packages are
displayed as `name [container-id]` but queried by bare name. `package_purl` encodes the same
information in purl qualifiers (`distro`, `upstream`, `epoch`) so exports re-import losslessly.

### State and caching

| File | TTL | Content |
|------|-----|---------|
| `<state>/osv_cache.json` | 12 h | OSV records per `ecosystem\|name\|version`; only complete answers |
| `<state>/kev_cache.json` | 24 h | CISA KEV catalog (stale copy used if refresh fails) |
| `<state>/eol_cache.json` | 24 h | endoflife.date cycles |
| `<state>/depsdev_cache.json` | — | deps.dev license answers |
| `<state>/last_state*.json` | — | diff baselines (host, and one per target) |

`<state>` is `$OPENBOM_STATE_DIR`, else `/var/lib/openbom` (root) or `$XDG_CACHE_HOME/openbom`. The
directory is created `0700`, files are written `0600` via temp file + rename, and symlinked or
foreign-owned files are ignored — never world-writable `/tmp`.

### Concurrency

```
asyncio event loop
├── OSV querybatch (sequential per 1000) → per-advisory enrichment (semaphore 20)
├── gather(KEV download, EPSS batches of 100, EOL lookups)
├── deps.dev lookups (semaphore 20, --deps-dev)
└── webhook + backend push
All HTTP calls: http_request() with 3 attempts, exponential backoff, Retry-After for 429/5xx.
```

## Backend architecture

### Technology stack

| Layer | Technology |
|-------|-----------|
| API | FastAPI (OpenAPI at `/docs`) |
| ORM | SQLAlchemy 2.0 async, relationships `lazy="raise"` (explicit queries only) |
| Database | PostgreSQL + asyncpg (production), SQLite + aiosqlite (WAL, foreign keys, busy timeout) |
| Validation | Pydantic v2 (tolerant inbound models, UTC-normalised outbound timestamps) |
| Console | React 18 + Arco Design UMD + htm, vendored, served from `/static` |

### Data model

```
assets ──< asset_package >── packages ──< package_vulnerability >── vulnerabilities
  │            (diff_label,     (purl, license,   (fixed_version,         (severity, cvss, epss,
  │             scan_ts,         osv_* coords)     recommendation)          is_kev, is_heuristic,
  │             location)                                                     
  │                                                                          is_malicious, cves,
  ├──< scans (history per ingest: counts, source)                            poc_links)
  │                                                                              │
  └──< triage >──────────────────────────────────────────────────────────────────┘
       (vulnerability_id, asset_id NULL = fleet-wide, state, justification, detail, author)
```

| Table | Key columns |
|-------|-------------|
| `assets` | `hostname` (unique), `ip_address`, `os_name`, `agent_version`, `first_seen`, `last_seen`, `last_scan_ts`, `last_scan_summary`, `target_type` (host/image/rootfs/path/sbom), `target_ref`, `eol_json`, `license_violations_json` |
| `packages` | unique (`name`, `version`, `ecosystem`), `purl`, `license`, `osv_ecosystem`, `osv_name`, `osv_version` |
| `vulnerabilities` | `vuln_id` (unique; heuristics namespaced `ID::ecosystem::package`), `severity`, `summary`, `cvss_score`, `epss_score`, `epss_percentile`, `is_kev` (sticky), `kev_description`, `is_heuristic`, `is_malicious`, `poc_links`, `cves`, `first_seen`, `last_updated` |
| `asset_package` | snapshot of what an asset has installed now; `location` = where that asset holds the package (dist-info / node_modules dir, or manifest/lockfile/venv for path/rootfs scans, absolute; several separated by newlines) |
| `package_vulnerability` | per-package `fixed_version` / `recommendation` (one CVE can have different fixes per ecosystem) |
| `scans` | one row per ingest: package/vuln/severity/KEV/IOC/malicious/license counts, diff counts, `source` (agent, sbom-upload, reanalysis) |
| `triage` | analyst decisions; `not_affected` / `false_positive` suppress findings |

A vulnerability is a property of a **package version**, so it applies to every asset that has that
version installed. Schema evolution: `init_db()` runs `create_all` and adds missing **nullable** columns.

### Ingestion (`ingest_payload`)

```
AgentPayload (validated) ─► upsert asset (hostname; ip, OS, agent version, target, EOL, license violations)
                         ─► resolve packages in bulk (chunks of 400) and refresh purl/license/osv_*
                         ─► REPLACE the asset's asset_package rows (snapshot → uninstalled packages disappear),
                            storing each package's location(s); path/rootfs locations are joined with the scan root
                         ─► resolve vulnerabilities in bulk; update non-null fields; KEV/heuristic/malicious sticky
                         ─► upsert package_vulnerability (only changed fixes are updated)
                         ─► insert scans row ─► commit
IntegrityError from a concurrent ingest → rollback and retry (3 attempts, then HTTP 409)
```

The same entry point is used by `POST /ingest` (source `agent`), `POST /sbom` (`sbom-upload`) and
re-analysis (`reanalysis`; does not overwrite the asset's agent version).

### Server-side analysis (`server/analyzer.py`)

`analyzer.agent()` imports `agent/openbom_agent.py` once. `sbom_payload()` parses an uploaded SBOM
and runs OSV/EPSS/KEV; `reanalysis_payload()` rebuilds agent `Package` objects from stored rows
(including OSV coordinates) and re-runs the analysis without cache. An asyncio lock serialises analyses.
With `OPENBOM_REANALYZE_HOURS > 0` the lifespan starts a loop that re-analyses every asset.

### Query layer (`server/queries.py`)

* `findings_query()` joins asset → package → vulnerability and excludes triage-suppressed findings
  (`not_suppressed()`: no `not_affected`/`false_positive` decision fleet-wide or for that asset).
* `asset_stats()` computes package/vulnerability/severity/KEV/IOC/malicious counts, max EPSS, license
  violations, stale flag and the risk score in two aggregate queries for any number of assets.
* `risk_score()` = `100·(1−e^(−Σ/200))`, Σ over distinct exposures of severity weight
  (10/6/3/1/1) + 15 KEV + 20 heuristic + 30 malicious + 10·EPSS.

### Routers

```
server/routers/
├── ingest.py      POST /api/v1/ingest                          (ingest_payload shared entry point)
├── threats.py     GET  /api/v1/threats/{malicious,kev,heuristics,critical,high-epss,summary}
├── assets.py      /api/v1/assets[/{hostname}[/packages|/vulnerabilities|/scans|/sbom]], DELETE asset
├── hunt.py        /api/v1/packages/search, /vulnerabilities[/{id}], POST /maintenance/prune
└── governance.py  /api/v1/triage, /vex, /licenses[/packages], /eol, POST /sbom, POST /reanalyze
```

All `/api/v1` routers depend on `require_api_key` (active when `OPENBOM_API_KEY` is set).

### Console (`server/static/`)

`index.html` loads vendored React, ReactDOM, htm, Arco Design (+ icons, en-US locale) and `app.js`.
The app is a hash-routed SPA: a `MENU` definition drives the sidebar, `App()` switches pages, `useApi()`
+ `<Loader>` handle fetching/errors (401 → Settings prompt). Untrusted data is rendered only through
React. The page is served with `script-src 'self'`; vendor files are cached for 7 days. See the
[Dashboard Guide](dashboard-guide.md).

## End-to-end flow

```
1. Agent scans a host, repo, image or SBOM
   $ python3 openbom_agent.py --check-osv --diff --server-url https://openbom.internal
2. Agent output: packages (+ purls, licenses, OSV coords), findings (CVSS, EPSS, KEV, MAL, PoC),
   delta, EOL, license violations, suppressed findings
3. Backend snapshot-ingests it; a scans row records the run
4. Analysts work in the console: threat views, package hunt, triage (→ OpenVEX), exports
5. Re-analysis (scheduled or on demand) re-matches stored inventories as new advisories appear
6. CI pipelines consume the agent's SARIF / exit codes; OpenVEX from triage feeds back via --vex
```
