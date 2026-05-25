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
- Heuristic findings (`MALICIOUS_HEURISTIC`) are namespaced as `MALICIOUS_HEURISTIC::package_name` to avoid collision
- All fields on existing Vulnerability records are updated on re-ingest

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
          {"id": 100, "name": "cryptography", "version": "41.0.0", "ecosystem": "PyPI"}
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
