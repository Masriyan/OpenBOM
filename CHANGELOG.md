# Changelog

All notable changes to OpenBOM. The agent and the backend are versioned separately
(agent `AGENT_VERSION`, backend `server/main.py: VERSION`). Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Documentation set: configuration reference, dashboard guide, CI/CD integration, SBOM/VEX & triage,
  detection rules, development guide, troubleshooting, roadmap, code of conduct, GitHub templates.

## [Agent 5.1.0 / Backend 2.1.0] — 2026-10-04

Gap-fill release after a comparison with Syft, Grype, Trivy, OSV-Scanner, cdxgen, Dependency-Track and
Socket (see [docs/comparison.md](docs/comparison.md)).

### Added — agent
- Scan targets: `--path` (requirements, Poetry/uv/PDM, Pipfile, npm/yarn/pnpm lockfiles, go.mod incl. Go
  toolchain `stdlib`, Cargo.lock, Gemfile.lock, composer.lock, NuGet packages.lock.json, pom.xml,
  gradle.lockfile, `*.dist-info`, top-level `node_modules`, JAR/WAR/EAR incl. nested fat jars),
  `--rootfs`, `--image` (podman/docker), `--sbom` (CycloneDX/SPDX JSON input).
- Alpine (`apk`) support for hosts, containers, images and rootfs; OSV `Alpine:vX.Y` matching.
- Running Docker containers (`--ecosystems docker`).
- OpenSSF malicious-package advisories (OSV `MAL-*`) flagged CRITICAL with `is_malicious`.
- License extraction (rpm `%{LICENSE}`, apk, Debian copyright, PyPI metadata, npm, lockfiles),
  `--deps-dev` enrichment, `--license-deny` policy gate.
- End-of-life checks (OS, Python, Node.js) via endoflife.date; `--no-eol`.
- `--vex` (OpenVEX, CycloneDX VEX) and `--ignore` (with `until=` expiry) suppressions.
- Outputs: `--spdx` (SPDX 2.3), `--sarif` (SARIF 2.1.0); purls now carry `distro`, `epoch`, `upstream`.
- Interactive menu options: project scan (`p`), image scan (`i`), SBOM analysis (`s`).
- Diff baseline per scan target.

### Added — backend & console
- Console rebuilt with Arco Design (React, vendored, no build step): Overview, Assets, Threat Hunt
  (Malicious/KEV/IOC/Critical/EPSS), Vulnerabilities, Package Search, Licenses, End-of-Life,
  Triage & VEX, SBOM Import, Reports & Export, Agent Setup, Settings. New logo, dark/light theme.
- Triage (fleet-wide or per asset) with VEX semantics; OpenVEX import/export.
- `POST /api/v1/sbom` SBOM upload with server-side analysis; `/reanalyze` endpoints and
  `OPENBOM_REANALYZE_HOURS` continuous monitoring.
- `/threats/malicious`, `/licenses`, `/licenses/packages`, `/eol`; packages store `license`, `purl`, OSV coordinates.

### Changed
- Strict CSP (`script-src 'self'`) — console JavaScript moved to `/static/app.js`.
- Risk score adds +30 per known-malicious package.
- Exit code 2 also on known-malicious packages and license violations.

### Fixed
- `package_purl` used the Debian source name as the purl name.
- Poetry local path dependencies were reported as PyPI packages.
- deps.dev lookups for Go modules (missing `v` prefix).
- Console crash when a drawer closed while data was being cleared; Chinese pagination labels (Arco
  default locale); invisible logo wordmark in dark mode.

## [Agent 5.0.0 / Backend 2.0.0] — 2026-10-04

### Added
- OSV matching for npm, Debian, Ubuntu, AlmaLinux and Rocky Linux (previously PyPI only), including
  source-package and RPM-epoch awareness and Podman container distros.
- Real CVSS v3.1 base-score calculation; qualitative ratings (GHSA `MODERATE`, Ubuntu, RHEL-style).
- Fixed-version selection from the range that contains the installed version.
- GHSA ↔ PYSEC alias de-duplication.
- Ecosystem-aware version ordering (rpmvercmp, dpkg, PEP 440, semver).
- Heuristic IOC strong/weak indicator model, npm install-hook checks, `.pth` auto-exec, typosquat detection.
- CycloneDX 1.5 export, backend push (`--server-url`, `--push-file`), `--fail-on`, `--hostname`,
  `--ecosystems`, interactive menu, retry/backoff for all HTTP calls.
- Backend: API-key auth, web dashboard, scan history, fleet package search, vulnerability list/detail,
  asset decommission, CycloneDX export, prune, risk score, stale assets, security headers.
- pytest suite.

### Changed
- Caches and diff baseline moved from `/tmp` to a private state dir (`0700`, atomic writes, symlink-safe).
- Ingest is snapshot-based and bulk (one round-trip per chunk instead of per package).
- Relationships `lazy="raise"`; explicit queries.

### Fixed
- Failed OSV batches were cached as "no vulnerabilities" for 12 hours.
- Uninstalled / upgraded packages stayed linked to hosts forever.
- CVE extraction ignored Debian/Ubuntu `upstream` and Alma/Rocky `related` fields (no EPSS/KEV for OS packages).
- Multi-version packages (kernel, gpg-pubkey) produced bogus upgrade/downgrade labels.
- SQLite foreign keys were not enforced; API timestamps lacked a timezone.

## [Agent 4.x / Backend 1.x] — 2026-05

Initial public version: RPM/dpkg/pip/npm/Podman inventory, OSV (PyPI), EPSS, CISA KEV, PoC links,
regex heuristics, diff, HTML/PDF reports, webhook alerts, FastAPI backend.
