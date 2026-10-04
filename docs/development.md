# Development Guide

## Setup

```bash
git clone https://github.com/Masriyan/OpenBOM.git && cd OpenBOM
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # agent, server and test dependencies
pip install weasyprint                    # optional, PDF reports
```

Python 3.12+ is required (the agent uses `tomllib`, PEP 604 types, `tarfile` extraction filters).
Node.js is optional — only used by the test suite to syntax-check `server/static/app.js`.

## Everyday commands

```bash
python3 -m pytest                                   # whole suite, ~6 s, no network
python3 -m pytest tests/test_agent_sources.py -k purl   # a subset
python3 -m pyflakes agent server tests              # lint (the only linter in use)
uvicorn server.main:app --reload --port 8000        # backend + console
OPENBOM_STATE_DIR=/tmp/ob-dev python3 agent/openbom_agent.py --scan-only --output-dir /tmp/ob-out
```

Use a throwaway `OPENBOM_STATE_DIR` and `--output-dir` while developing so you don't overwrite your
real caches and diff baseline.

## Repository layout

```
agent/openbom_agent.py      single-file agent (keep it single-file — deployment convention)
agent/templates/            Jinja2 HTML report template
server/main.py              FastAPI app, lifespan (init_db, optional re-analysis loop), static mount, CSP
server/config.py            env settings (read per request)        server/security.py  API-key dependency
server/database.py          async engine, SQLite pragmas, init_db + nullable-column migration
server/models.py            Asset, Package, Vulnerability, ScanRecord, Triage + association tables
server/schemas.py           Pydantic in/out models (agent contract)
server/queries.py           shared joins, triage suppression, stats, risk score
server/analyzer.py          imports the agent to analyse SBOM uploads / re-analysis
server/sbom.py              CycloneDX export          server/routers/  ingest, threats, assets, hunt, governance
server/static/              console: index.html, app.js, app.css, logos, vendor/ (Arco, React, htm)
tests/                      pytest suite (see below)
docs/                       documentation
```

## Tests

| File | Covers |
|------|--------|
| `tests/test_agent_core.py` | version comparison (rpm, dpkg, PEP 440, semver), CVSS 3.1, severity, OSV parsing, OS mapping, rpm/dpkg parsers |
| `tests/test_agent_pipeline.py` | diff, state-dir safety, heuristics, typosquat, OSV/EPSS/KEV with mocked HTTP, reports, CycloneDX, menu |
| `tests/test_agent_sources.py` | lockfile parsers, rootfs/apk/dpkg, image export safety, purl round-trip, SBOM input, licenses, VEX/ignore, EOL, SARIF/SPDX, MAL handling |
| `tests/test_server.py` | ingest, snapshot semantics, threats, search, auth, migration, concurrency, end-to-end agent push |
| `tests/test_server_governance.py` | malicious, triage/VEX, licenses, EOL, SBOM upload, re-analysis |
| `tests/test_ui_assets.py` | console static checks: JS parses, no raw-HTML/eval, assets exist, every menu entry is routed |

Conventions:

* `tests/conftest.py` sets `DATABASE_URL` to a temp SQLite file **before** importing `server`, and loads
  the agent via importlib as `tests.conftest.AGENT`. Use the `agent` fixture — it redirects `OPENBOM_STATE_DIR`.
* No test touches the network. Mock outbound HTTP with `patch_httpx(monkeypatch, httpx.MockTransport(handler))`
  from `tests/test_agent_pipeline.py`; `osv_handler()` fakes OSV, EPSS, KEV.
* To exercise the agent against the real backend in-process, patch httpx with
  `httpx.ASGITransport(app=app)` (see `test_agent_push_end_to_end`).
* `asyncio_mode = "auto"`: write `async def test_…` without decorators.

## Common changes

### Add a lockfile / manifest parser

1. Write `parse_<format>(text, loc) -> list[Package]` in the "Project / lockfile scanning" section using
   `_lang_pkg(eco, name, version, loc, license)`.
2. Register it in `LOCKFILE_PARSERS` (exact filename) or in `scan_path` (patterns).
3. New ecosystem? Add it to `LANG_OSV_ECOSYSTEM`, `PURL_TYPES`, `package_purl`, `compare_versions` and
   (if deps.dev supports it) `DEPS_DEV_SYSTEMS`.
4. Add a fixture to `build_repo()` in `tests/test_agent_sources.py` and verify the OSV ecosystem name with a
   live `curl -X POST https://api.osv.dev/v1/query …` first.

### Add an OS distribution

Map `/etc/os-release` in `osv_ecosystem_for_os`, purl namespace/qualifier in `_OSV_DISTRO_PURL` /
`_distro_osv_ecosystem`, the EOL product in `EOL_PRODUCTS`, and add parametrised cases in
`test_osv_ecosystem_for_os` and `test_package_from_purl`.

### Add a heuristic rule

See [Detection Rules → Tuning](detection-rules.md#tuning). Always add a legitimate-code negative test.

### Change the agent JSON

Update the dataclasses (`Package`, `VulnDetail`, `ScanReport.to_dict/from_dict`), the inbound schemas in
`server/schemas.py`, the model/ingest if it is persisted, and keep `test_report_roundtrip_and_contract`
green. Inbound schemas must stay tolerant (old agents keep working, unknown fields are ignored).

### Change the database schema

There is no migration framework. `init_db()` creates tables and **adds missing nullable columns**.
New columns must therefore be nullable (or the upgrade of existing databases fails silently for them).
Add an assertion to `test_schema_upgrade_adds_missing_columns` when you add columns to old tables.

### Add a backend endpoint

Put it in the matching router, depend on `require_api_key` via the router, and build exposure queries
on `findings_query()` (it already excludes triage-suppressed findings) or add `not_suppressed()` yourself.

### Work on the console

* No build step: edit `server/static/app.js` (React + Arco via `htm` tagged templates) and reload.
* Arco components come from the global `arco`, icons from `arcoicon` (check an icon exists before using it).
* Fetch with `useApi(path)` and render through `<Loader q=…>`; never pass `null` data to renderers.
* Never inject raw HTML; the CSP forbids inline scripts and eval.
* New sidebar entry → add it to `MENU` **and** a `case` in `App()` (enforced by `tests/test_ui_assets.py`).
* Updating vendored libraries: `npm pack <pkg>@<version>`, copy the UMD builds listed in
  `server/static/vendor/LICENSES.md`, regenerate the en-US locale wrapper, update the table and checksums.

## Releasing

1. Bump `AGENT_VERSION` (agent) and `VERSION` (server/main.py) as needed; the OpenBOM version in
   `server/sbom.py` metadata follows the server version.
2. Update [CHANGELOG.md](../CHANGELOG.md) and the README/docs.
3. Run `python3 -m pytest` and `python3 -m pyflakes agent server tests`, then a live smoke test:
   agent `--check-osv --diff`, push to a local backend, click through the console.
