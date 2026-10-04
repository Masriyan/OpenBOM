# API Reference

> Complete REST API documentation for the OpenBOM Backend Server.

**Base URL**: `http://localhost:8000`
**Interactive Docs**: `http://localhost:8000/docs` (Swagger UI)
**OpenAPI Spec**: `http://localhost:8000/openapi.json`

---

## System

### GET /health

Health check endpoint.

**Response** `200`

```json
{
  "status": "ok",
  "service": "openbom-backend"
}
```

---

## Ingestion

### POST /api/v1/ingest

Receive and persist an agent scan payload. This endpoint is idempotent — re-submitting the same scan updates existing records without creating duplicates.

**Request Body** — The JSON output of `openbom_agent.py`:

```json
{
  "hostname": "web-server-01",
  "scan_ts": "2026-05-25T12:00:00+00:00",
  "total_packages": 3614,
  "packages": [
    {
      "name": "requests",
      "version": "2.31.0",
      "ecosystem": "PyPI",
      "diff_label": null
    }
  ],
  "osv_summary": {
    "queried": 464,
    "vulnerable": 23,
    "kev_hits": 1,
    "poc_count": 3,
    "total_critical": 10,
    "total_high": 19,
    "total_medium": 2,
    "total_low": 7,
    "total_unknown": 11
  },
  "osv_vulnerabilities": [
    {
      "package": {"name": "aiohttp", "version": "3.13.3", "ecosystem": "PyPI", "diff_label": null},
      "max_severity": "CRITICAL",
      "vulns": [
        {
          "vuln_id": "GHSA-xxxx-xxxx-xxxx",
          "severity": "CRITICAL",
          "summary": "Description of the vulnerability",
          "fixed_version": "3.13.4",
          "recommendation": "Upgrade to version 3.13.4",
          "epss_score": 0.15,
          "epss_percentile": 0.92,
          "is_kev": false,
          "kev_description": null,
          "poc_links": []
        }
      ]
    }
  ],
  "diff_summary": {
    "new": 5,
    "removed": 0,
    "upgraded": 2,
    "downgraded": 0,
    "unchanged": 3607
  }
}
```

**Response** `200`

```json
{
  "status": "ok",
  "hostname": "web-server-01",
  "packages_processed": 3614,
  "vulnerabilities_linked": 49
}
```

**Behavior**:
- Creates or updates the `Asset` record for the given hostname
- Creates `Package` records for each unique (name, version, ecosystem) tuple
- Links packages to the asset via the `asset_package` junction table
- Creates `Vulnerability` records for each unique `vuln_id`
- Heuristic findings (`MALICIOUS_HEURISTIC`, `TYPOSQUAT_SUSPECT`) are namespaced as `<ID>::<ecosystem>::<package>`
- **Snapshot semantics**: the asset's package links are replaced by the payload, so uninstalled or upgraded
  packages stop counting against the host (`packages_unlinked` in the response)
- Non-null fields on existing Vulnerability records are updated on re-ingest; `is_kev` is sticky
- Every ingest adds a row to the asset's scan history (`/assets/{hostname}/scans`)
- Payloads from agent v4 are still accepted; unknown fields are ignored

---

## Threat Hunting

### GET /api/v1/threats/summary

Aggregate threat statistics across all managed assets.

**Response** `200`

```json
{
  "total_assets": 12,
  "total_packages": 42850,
  "total_vulnerabilities": 187,
  "kev_vulnerabilities": 3,
  "heuristic_detections": 1,
  "critical_vulnerabilities": 28,
  "severity_breakdown": {
    "CRITICAL": 28,
    "HIGH": 67,
    "MEDIUM": 34,
    "LOW": 41,
    "UNKNOWN": 17
  }
}
```

---

### GET /api/v1/threats/kev

Assets with packages affected by CISA Known Exploited Vulnerabilities.

**Response** `200` — Array of assets with their KEV findings:

```json
[
  {
    "asset": {
      "id": 1,
      "hostname": "web-server-01",
      "last_seen": "2026-05-25T12:00:00"
    },
    "findings": [
      {
        "vulnerability": {
          "id": 42,
          "vuln_id": "GHSA-xxxx",
          "severity": "CRITICAL",
          "epss_score": 0.85,
          "is_kev": true,
          "kev_description": "Active exploitation of...",
          "is_heuristic": false,
          "poc_links": "[\"https://exploit-db.com/...\"]"
        },
        "affected_packages": [
          {"id": 100, "name": "cryptography", "version": "41.0.0", "ecosystem": "PyPI",
           "fixed_version": "41.0.4",
           "location": "/home/app/.local/lib/python3.12/site-packages/cryptography-41.0.0.dist-info"}
        ]
      }
    ]
  }
]
```

---

### GET /api/v1/threats/heuristics

Assets with heuristic malware detections (`MALICIOUS_HEURISTIC` findings).

**Response** `200` — Same structure as `/threats/kev`, filtered for `is_heuristic = true`.

---

### GET /api/v1/threats/critical

Assets with CRITICAL-severity vulnerabilities.

**Response** `200` — Same structure as `/threats/kev`, filtered for `severity = "CRITICAL"`.

---

### GET /api/v1/threats/high-epss

Assets with vulnerabilities above a given EPSS exploit probability threshold.

**Query Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `min_score` | float | `0.1` | Minimum EPSS score (0.0–1.0) |

**Example**:

```
GET /api/v1/threats/high-epss?min_score=0.5
```

**Response** `200` — Same structure as `/threats/kev`, filtered for `epss_score >= min_score`.

---

## Assets

### GET /api/v1/assets

List all managed assets.

**Query Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | `100` | Max results (1–1000) |
| `offset` | int | `0` | Pagination offset |

**Response** `200`

```json
[
  {
    "id": 1,
    "hostname": "web-server-01",
    "last_seen": "2026-05-25T12:00:00"
  }
]
```

---

### GET /api/v1/assets/{hostname}

Get a single asset by hostname.

**Response** `200` — Single asset object.

**Response** `404` — Asset not found.

```json
{"detail": "Asset 'unknown-host' not found"}
```

---

### GET /api/v1/assets/{hostname}/packages

List packages installed on a specific asset.

**Query Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ecosystem` | string | `null` | Filter by ecosystem (e.g., `PyPI`, `RPM`, `NPM`) |

**Response** `200`

```json
[
  {"id": 1, "name": "requests", "version": "2.31.0", "ecosystem": "PyPI"},
  {"id": 2, "name": "flask", "version": "3.0.0", "ecosystem": "PyPI"}
]
```

---

### GET /api/v1/assets/{hostname}/vulnerabilities

List vulnerabilities affecting a specific asset (de-duplicated across packages).

**Query Parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `severity` | string | `null` | Filter by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`) |

**Response** `200`

```json
[
  {
    "id": 42,
    "vuln_id": "GHSA-xxxx",
    "severity": "CRITICAL",
    "summary": "...",
    "fixed_version": "3.13.4",
    "recommendation": "Upgrade to version 3.13.4",
    "epss_score": 0.15,
    "is_kev": false,
    "is_heuristic": false,
    "poc_links": null,
    "first_seen": "2026-05-25T12:00:00"
  }
]
```

---

## Authentication

When `OPENBOM_API_KEY` is set (comma-separated for several keys), every `/api/v1` route requires
`X-API-Key: <key>` or `Authorization: Bearer <key>`; otherwise it returns `401`. `/health` and the
dashboard shell (`/`) stay public — the dashboard asks for the key in **Settings** and keeps it in
browser `localStorage`.

## Additional Endpoints (backend 2.0)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/assets?q=&sort=risk\|hostname\|last_seen\|packages` | Assets with package/vuln counts, KEV/IOC counts, max EPSS, 0-100 `risk_score`, `stale` flag |
| `DELETE` | `/api/v1/assets/{hostname}` | Decommission an asset (links + scan history) |
| `GET` | `/api/v1/assets/{hostname}/scans` | Per-ingest history (counts, diff new/removed) |
| `GET` | `/api/v1/assets/{hostname}/sbom` | CycloneDX 1.5 JSON for the current snapshot |
| `GET` | `/api/v1/assets/{hostname}/vulnerabilities?severity=&kev=&heuristic=` | Now includes `affected_packages` with per-package `fixed_version` |
| `GET` | `/api/v1/packages/search?name=&version=&ecosystem=&exact=` | Which hosts have package X installed right now; `locations` gives `{hostname, location}` per host |
| `GET` | `/api/v1/vulnerabilities?severity=&kev=&heuristic=&min_epss=&q=` | Vulns present on ≥1 asset, highest risk first; `occurrences` lists the first 5 `{hostname, name, version, ecosystem, fixed_version, location}` |
| `GET` | `/api/v1/vulnerabilities/{vuln_id}` | Detail + every affected host/package |
| `POST` | `/api/v1/maintenance/prune` | Delete packages no asset has and vulns no package references |

`risk_score` = `100·(1−e^(−Σ/200))`, where each distinct vulnerability adds its severity weight
(CRITICAL 10, HIGH 6, MEDIUM 3, LOW/UNKNOWN 1) + 15 if KEV + 20 if heuristic + 30 if known-malicious + 10·EPSS.
Triage-suppressed findings are excluded.

Timestamps are always returned in UTC (`Z`).

## Governance Endpoints (backend 2.1)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/threats/malicious` | Assets with known-malicious packages (OSV `MAL-*`) |
| `GET` | `/api/v1/triage?state=` | List analyst decisions |
| `PUT` | `/api/v1/triage` | Body `{vuln_id, hostname?, state, justification?, detail?, author?}`; states: `in_triage`, `exploitable`, `not_affected`, `false_positive`, `resolved`. Omit `hostname` for a fleet-wide decision |
| `DELETE` | `/api/v1/triage/{id}` | Remove a decision |
| `GET` | `/api/v1/vex` | OpenVEX 0.2.0 document generated from triage (products = affected purls) |
| `POST` | `/api/v1/vex` | Import OpenVEX statements as fleet-wide decisions (matched by id or CVE alias) |
| `GET` | `/api/v1/licenses` | `[{license, packages, assets}]` over installed packages (`UNKNOWN` = no data) |
| `GET` | `/api/v1/licenses/packages?license=` | Packages + hosts for one license |
| `GET` | `/api/v1/eol` | Assets with end-of-life data reported by agents |
| `POST` | `/api/v1/sbom?hostname=&analyze=true` | Body = CycloneDX or SPDX JSON; creates/updates an asset (`target_type=sbom`), optionally analysed server-side |
| `POST` | `/api/v1/assets/{hostname}/reanalyze` | Re-run OSV/EPSS/KEV on the stored inventory |
| `POST` | `/api/v1/reanalyze` | Same for every asset (also scheduled by `OPENBOM_REANALYZE_HOURS`) |

`/api/v1/vulnerabilities` and `/api/v1/assets/{hostname}/vulnerabilities` accept `include_suppressed=true`
to show triaged findings (each item carries `triage_state`). Assets now also report `target_type`,
`target_ref`, `eol`, `malicious_count` and `license_violation_count`; packages carry `license` and `purl`.

## Error Responses

All error responses follow this format:

```json
{"detail": "Human-readable error message"}
```

| Status | Meaning |
|--------|---------|
| `404` | Resource not found |
| `422` | Validation error (malformed request body or query parameters) |
| `500` | Internal server error |

### Package locations

Every per-asset package view (`affected_packages[]` in threat/asset/vulnerability responses, `occurrences[]`,
`/assets/{hostname}/packages`, `locations[]` in package search) carries `location`: where the package was
found on that asset. Host scans report the absolute `*.dist-info` / global `node_modules/<pkg>` directory;
`--path` / `--rootfs` scans report the manifest, lockfile, venv or archive, stored as an absolute path
(joined with the scan root). Several places are newline-separated. OS packages (RPM/dpkg/apk) and container
packages have no location. Scans from older agents leave it `null` until the target is scanned again.
