# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

OpenBOM is a Linux supply-chain threat-hunting platform with two independent parts that share only a JSON contract:

- **Endpoint agent** — `agent/openbom_agent.py`: a single-file CLI (keep it single-file — deployment convention from CONTRIBUTING.md) that builds an SBOM (RPM/dpkg, pip, global npm, Podman containers), checks it against OSV.dev, enriches with EPSS + CISA KEV + PoC links, runs heuristic IOC / typosquat checks, and outputs JSON / HTML / PDF / CycloneDX, optionally pushing to the backend. With no mode flag on a TTY it opens an interactive menu.
- **Backend** — `server/`: async FastAPI + SQLAlchemy 2.0 that ingests agent JSON, exposes `/api/v1` hunting/governance endpoints, and serves the Arco Design console at `/`.

`docs/` has the deep-dives (architecture, API reference, agent guide, threat model, deployment) and `docs/comparison.md` (feature matrix vs. Syft/Grype/Trivy/OSV-Scanner/Dependency-Track/Socket + known remaining gaps).

## Commands

```bash
pip install -r requirements.txt                  # agent + server + test deps (weasyprint/asyncpg optional)
python3 -m pytest                                # full suite (~5s, no network)
python3 -m pytest tests/test_server.py -k snapshot   # single test
python3 -m pyflakes agent server tests           # lint (no other linter configured)

python3 agent/openbom_agent.py                   # interactive menu
python3 agent/openbom_agent.py --scan-only
python3 agent/openbom_agent.py --check-osv --diff --report --cyclonedx bom.json
python3 agent/openbom_agent.py --check-osv --diff --server-url http://127.0.0.1:8000 --api-key KEY
python3 agent/openbom_agent.py --path . --sarif r.sarif --license-deny AGPL   # repo / CI (target ⇒ --check-osv)
python3 agent/openbom_agent.py --image alpine:3.16                         # podman/docker image
python3 agent/openbom_agent.py --sbom app.cdx.json --spdx app.spdx.json    # analyse a foreign SBOM

uvicorn server.main:app --reload --port 8000     # SQLite ./openbom.db; dashboard at /, Swagger at /docs
```

Agent exit codes: `0` clean, `1` no packages / push failed / bad VEX, `2` findings at/above `--fail-on` (KEV, malicious packages and license violations always count), `130` Ctrl+C.

When manually exercising the agent, set `OPENBOM_STATE_DIR` to a scratch dir so you don't touch the user's real caches/diff baseline, and use `--output-dir` (output paths are relative to CWD).

## Architecture notes

**Agent pipeline** (`run_scan`): collect (host extractors, or `collect_target_packages` for `--path/--rootfs/--image/--sbom` — any target replaces the host scan) → `compute_diff` (baseline per target via `diff_state_path(target)`) → heuristics (`scan_heuristics` only for installed host packages; `check_typosquat` for any PyPI/npm) → licenses (`enrich_licenses_deps_dev`, `check_licenses`) → `query_osv_batch` → `KevCatalog.load` ‖ `query_epss` ‖ `check_eol` → `apply_kev` → `merge_results` → `apply_suppressions` (VEX/ignore) → render/JSON/CycloneDX/SPDX/SARIF/HTML → webhook → `push_to_server`.

- Sources: `scan_path` walks a tree and dispatches `LOCKFILE_PARSERS` (+ requirements*.txt, `*.dist-info/METADATA`, top-level `node_modules/*/package.json`, nested JARs). `scan_rootfs` reads dpkg status / apk db / `rpm --root`, then `scan_path` with `ROOTFS_SKIP_TOP`. `export_image` unpacks `podman|docker export` with `_safe_tar_filter` (skips traversal/absolute links instead of aborting). Malformed manifests are logged at debug and skipped — never abort a scan.
- `package_purl` ⇄ `package_from_purl` must round-trip (distro/epoch/upstream qualifiers map back to OSV ecosystems); `test_purl_roundtrip_through_our_own_exports` guards it. Lang ecosystems' OSV names live in `LANG_OSV_ECOSYSTEM`.
- `MAL-*` advisories (or GHSA aliasing one) go through `mark_malicious` → CRITICAL + `is_malicious`; they sort first everywhere.

- **OSV coordinates differ from display identity.** `Package.osv_ecosystem/osv_name/osv_version` hold what OSV is queried with (Debian *source* package + source version, RPM `epoch:version-release`, bare name for container packages that display as `name [cid]`). `osv_ecosystem_for_os()` maps `/etc/os-release`; distros without an OSV feed (Fedora, RHEL, …) get `None` and are inventoried only.
- Version ordering is ecosystem-aware (`compare_versions`: rpmvercmp, dpkg, PEP 440, semver). It's used for diff labels and for picking the fixed version from the range that contains the installed version — never recommend a fix older than installed.
- `parse_vuln_details` collapses advisories that alias each other (GHSA ↔ PYSEC ↔ CVE). CVEs for EPSS/KEV come from `aliases`, `upstream` (Debian/Ubuntu) and `related` (Alma/Rocky).
- Heuristics: rules are `strong` (alone → CRITICAL) or weak (only reported as HIGH when ≥2 different weak categories co-occur; weak hits under test dirs ignored). This was tuned against real installed packages (botocore, pandas, torch, tqdm…) — re-check false positives on a real `--heuristics all` run when touching rules or the typosquat allowlist.
- State (`osv_cache.json`, `kev_cache.json`, `last_state.json`) lives in `state_dir()` — never `/tmp`. Writes go through `_atomic_write`, reads through `_read_private_json` (rejects symlinks/foreign owners). Failed OSV lookups must not be cached.
- Importing the module has no side effects; logging is configured in `main()`. Rich console log handler has `markup=False` — escape untrusted strings with `rich.markup.escape` when building markup yourself.

**Agent ↔ backend contract**: `ScanReport.to_dict()` must validate against `AgentPayload` in `server/schemas.py` (tested in `test_report_roundtrip_and_contract`). Inbound schemas ignore unknown fields and still accept agent v4 payloads. Changing a field usually touches the agent dataclasses, `schemas.py`, `models.py`, and `routers/ingest.py`.

**Backend** (`server/analyzer.py` imports `agent/openbom_agent.py` via importlib so SBOM uploads and re-analysis use the exact agent matching code — keep agent functions importable/side-effect free):
- Ingest is **snapshot-based**: an asset's `asset_package` links are deleted and re-inserted from the payload, so removed/upgraded packages stop counting. Packages/vulns are resolved in bulk (chunks of 400 for SQLite's parameter limit); IntegrityError from concurrent ingests triggers a retry.
- Vulnerabilities are properties of a package *version* (shared across hosts). Per-package fix/recommendation lives on `package_vulnerability`. Heuristic IDs are namespaced `ID::ecosystem::name`. `is_kev` is sticky.
- Relationships are `lazy="raise"` — always query explicitly; shared joins and risk scoring live in `server/queries.py` (`findings_query`, `asset_stats`, `risk_score`).
- Triage (`Triage` model): `not_affected`/`false_positive` suppress findings fleet-wide (`asset_id NULL`) or per asset. Every exposure query must include `not_suppressed()` (already inside `findings_query` unless `include_suppressed=True`) — summary, asset stats and vuln listing do this explicitly.
- `ingest_payload(db, payload, ip, source)` is the shared entry point (agent `/ingest`, `/sbom` upload, re-analysis); `source != "agent"` must not overwrite the asset's agent_version. Package attributes (purl, license, osv_*) are refreshed from payloads.
- No migration framework: `init_db()` runs `create_all` plus `_add_missing_columns` (adds new **nullable** columns only). New columns must be nullable or they won't upgrade existing DBs.
- SQLite needs the per-connection pragmas in `database.py` (`foreign_keys=ON` for cascades). It returns naive datetimes — response schemas re-tag them UTC via `as_utc`.
- Auth: `OPENBOM_API_KEY` (comma-separated) gates every `/api/v1` router via `require_api_key`; `/health` and `/` stay public. Settings are read from env per request (`server/config.py`), so tests can monkeypatch env.
- Console: React 18 + **Arco Design** (`@arco-design/web-react` UMD) written with `htm` tagged templates in `server/static/app.js` — no build step. Libraries are vendored in `server/static/vendor/` (see `LICENSES.md`; English locale is a wrapped `lib/locale/en-US.js`). CSP is `script-src 'self'` → no inline scripts, no eval. Render agent data only through React (never raw HTML). Hash routes are in `App()`'s switch; every sidebar entry in `MENU` needs a route (`tests/test_ui_assets.py`). Data fetching goes through `useApi()` + `<Loader>` (which must never pass `null` data to renderers — closing drawers do that).

**Tests**: `tests/conftest.py` points `DATABASE_URL` at a temp SQLite file before importing `server`, loads the agent via importlib as `tests.conftest.AGENT`, and the `agent` fixture redirects `OPENBOM_STATE_DIR`. HTTP is mocked by swapping `httpx.AsyncClient` (`patch_httpx` in `test_agent_pipeline.py`); `test_agent_push_end_to_end` routes the agent's push into the real ASGI app.
