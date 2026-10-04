# SBOM, VEX & Triage

How OpenBOM exchanges data with other tools and how findings are suppressed in a way that stays
auditable.

## Formats at a glance

| Format | In | Out | Where |
|--------|----|-----|-------|
| OpenBOM native JSON | ✅ backend `/ingest`, agent `--push-file` | ✅ agent `-o` | the backend contract |
| CycloneDX JSON (1.4–1.6) | ✅ agent `--sbom`, backend `POST /api/v1/sbom` | ✅ 1.5 — agent `--cyclonedx`, backend `/assets/{host}/sbom` | |
| SPDX JSON (2.x) | ✅ agent `--sbom`, backend `POST /api/v1/sbom` | ✅ 2.3 — agent `--spdx` | |
| SARIF 2.1.0 | — | ✅ agent `--sarif` | code-scanning dashboards |
| OpenVEX 0.2.0 | ✅ agent `--vex`, backend `POST /api/v1/vex` | ✅ backend `GET /api/v1/vex` | |
| CycloneDX VEX | ✅ agent `--vex` | — | |
| `.openbomignore` | ✅ agent `--ignore` | — | |
| HTML / PDF report | — | ✅ agent `--report` | |
| CSV | — | ✅ console (Vulnerabilities, Reports) | |

XML variants (CycloneDX XML, SPDX tag-value / RDF) are not supported — convert with
`cyclonedx-cli` or `spdx-tools` first.

## Package URLs (purl)

Every exported component carries a purl, and imports rely on purls to know what to query. Components
without a purl are skipped (counted in the log).

| Ecosystem | Example | Notes |
|-----------|---------|-------|
| PyPI | `pkg:pypi/requests@2.31.0` | name PEP 503-normalised |
| npm | `pkg:npm/%40babel/core@7.24.0` | scope percent-encoded |
| Go | `pkg:golang/golang.org/x/net@v0.17.0` | `v` prefix in purl, stripped internally; `stdlib` for the toolchain |
| Cargo / RubyGems / NuGet | `pkg:cargo/tokio@1.38.0` | |
| Composer | `pkg:composer/laravel/framework@10.0.0` | |
| Maven | `pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1` | internally `group:artifact` |
| Debian/Ubuntu | `pkg:deb/debian/libssl3@3.0.11-1~deb12u2?distro=debian-12&upstream=openssl` | `upstream` = source package used for OSV |
| RPM (Alma/Rocky) | `pkg:rpm/almalinux/openssl@3.0.7-27.el9?distro=almalinux-9&epoch=1` | epoch needed for correct OSV matching |
| Alpine | `pkg:apk/alpine/libcrypto3@3.1.4-r5?distro=alpine-3.19&upstream=openssl` | `upstream` = apk origin |

The `distro` qualifier maps back to an OSV ecosystem (`debian-12` → `Debian:12`, `jammy` →
`Ubuntu:22.04:LTS`, `almalinux-9.3` → `AlmaLinux:9`, `rocky-9` → `Rocky Linux:9`, `alpine-3.19.1` →
`Alpine:v3.19`). OpenBOM's own CycloneDX/SPDX exports round-trip through `--sbom` with identical results.
OS packages from distros without an OSV feed (Fedora, RHEL, openSUSE…) are inventoried but not matched.

### Importing SBOMs from other tools

```bash
syft  registry.example/app:1.4 -o cyclonedx-json=app.cdx.json
trivy image --format spdx-json -o app.spdx.json registry.example/app:1.4

python3 agent/openbom_agent.py --sbom app.cdx.json --server-url https://openbom.example --api-key "$KEY"
# or upload directly (server-side analysis):
curl -X POST "https://openbom.example/api/v1/sbom?hostname=app-1.4" \
     -H "X-API-Key: $KEY" -H "Content-Type: application/json" --data @app.cdx.json
```

Uploaded SBOMs become assets with `target_type=sbom` and are included in continuous re-analysis.

## Suppressing findings

There are three mechanisms: VEX documents, the ignore file and backend triage. All of them keep the evidence (`suppressed` list in the agent JSON,
triage records on the backend) — nothing is silently dropped.

### VEX documents

Agent flag `--vex` (repeatable).

**OpenVEX** — statements with status `not_affected` or `fixed` suppress matching findings:

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/2026-10-01",
  "author": "AppSec team",
  "timestamp": "2026-10-01T00:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {"name": "CVE-2018-18074"},
      "products": [{"@id": "pkg:pypi/requests"}],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path"
    }
  ]
}
```

**CycloneDX VEX** — `vulnerabilities[].analysis.state` of `not_affected`, `false_positive` or
`resolved`, with `affects[].ref` pointing at a component `bom-ref`/purl.

Matching rules:

* the vulnerability id matches the finding id **or any of its CVE aliases** (`CVE-…` matches the GHSA finding),
* a product purl **without a version** matches every version of that package; with a version only that version,
* a statement without products applies to every package.

### Ignore file

Agent flag `--ignore`.

One entry per line: `VULN-ID [package-name|purl] [until=YYYY-MM-DD] [# reason]`.

```text
GHSA-x84v-xcm2-53pg requests until=2026-12-31      # accepted risk, SEC-421
TYPOSQUAT_SUSPECT reqeusts                          # internal fork, reviewed 2026-09
CVE-2023-44487                                      # all packages: mitigated at the LB
MALICIOUS_HEURISTIC pkg:pypi/vendored-tool          # false positive, see review notes
```

Expired entries are **not** applied; the agent logs a warning and reports the finding again.

### Triage on the backend

In the console or via `PUT /api/v1/triage`.

| State | Effect | OpenVEX export status |
|-------|--------|-----------------------|
| `in_triage` | informational | `under_investigation` |
| `exploitable` | informational | `affected` |
| `not_affected` | **suppresses** | `not_affected` (+ justification) |
| `false_positive` | **suppresses** | `not_affected` |
| `resolved` | informational | `fixed` |

Scope is either **fleet-wide** or **one asset**; an asset-specific decision overrides the fleet-wide
one for that asset. Suppressed findings disappear from threat views, counts and risk scores; use the
"show suppressed" switch or `include_suppressed=true` to see them with their `triage_state`.

OpenVEX justifications offered in the console: `component_not_present`,
`vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`,
`vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`.

`POST /api/v1/vex` imports OpenVEX statements as fleet-wide decisions (author `vex-import`);
`GET /api/v1/vex` exports every decision with the affected package purls as products — share it with
customers or feed it back into CI with `--vex`.

## Recommended workflow

1. CI scans repositories with `--path . --sarif` and fails on new KEV/critical findings.
2. Analysts triage in the console (fleet-wide `not_affected` with justification).
3. The exported OpenVEX goes into the repository and is passed to CI with `--vex openvex.json`.
4. Short-term risk acceptances go into `.openbomignore` **with an expiry date**.
