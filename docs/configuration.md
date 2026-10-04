# Configuration Reference

Every knob OpenBOM exposes — agent CLI flags, environment variables, files and built-in limits.
Values are taken from the source (`agent/openbom_agent.py` 5.1.0, `server/` 2.1.0).

## Agent CLI

```
python3 agent/openbom_agent.py [MODE] [TARGETS] [OUTPUTS] [ANALYSIS] [OTHER]
```

### Modes (mutually exclusive)

| Flag | Behaviour |
|------|-----------|
| *(none, on a TTY)* | Opens the interactive menu |
| `--menu` | Opens the interactive menu explicitly |
| `--scan-only` | Inventory only — no network calls (heuristics/typosquat still run if enabled) |
| `--check-osv` | Inventory + OSV (incl. OpenSSF malicious packages) + EPSS + CISA KEV + EOL |
| `--push-file JSON` | Upload an existing scan JSON to `--server-url`, then exit |

Without a mode and without a TTY (cron, CI) the agent exits with code 2 and a usage error — unless a
scan target is given, which implies `--check-osv`.

### Scan targets

Any target **replaces** the host scan.

| Flag | Scans |
|------|-------|
| `--path DIR` (repeatable) | Lockfiles/manifests, `*.dist-info/METADATA`, top-level `node_modules/*/package.json`, JAR/WAR/EAR (nested jars two levels deep) |
| `--rootfs DIR` | Unpacked root filesystem: dpkg status, apk db, rpm db (needs `rpm` on the host), then a path scan |
| `--image REF` | Container image via `podman` (preferred) or `docker`: `create` + `export` into a temp dir, scanned as a rootfs, then removed |
| `--sbom FILE` | CycloneDX or SPDX **JSON** document; components need a purl |
| `--ecosystems LIST` | Host-scan sources only: `os,pypi,npm,podman,docker` (default: all) |

### Outputs

| Flag | Default | Notes |
|------|---------|-------|
| `-o, --output PATH` | `<output-dir>/sbom_<UTC timestamp>.json` | Native JSON (the backend ingest format) |
| `--output-dir DIR` | `./output` (relative to CWD) | Also receives HTML/PDF reports |
| `--report` | off | `report_openbom_<ts>.html` (+ `.pdf` if WeasyPrint is installed) |
| `--cyclonedx PATH` | off | CycloneDX 1.5 JSON with vulnerabilities |
| `--spdx PATH` | off | SPDX 2.3 JSON |
| `--sarif PATH` | off | SARIF 2.1.0 |

### Analysis & policy

| Flag | Default | Notes |
|------|---------|-------|
| `--diff` | off | Labels `[NEW]` / `[UPGRADED]` / `[DOWNGRADED]`, counts removed packages. Baseline is kept per target |
| `--heuristics new\|all\|off` | `new` | `new` = only changed PyPI/npm packages (requires `--diff`); IOC source scanning applies to installed host packages, typosquat checks to any PyPI/npm package |
| `--vex FILE` (repeatable) | — | OpenVEX or CycloneDX VEX; `not_affected`/`fixed` (OpenVEX) and `not_affected`/`false_positive`/`resolved` (CycloneDX) suppress findings |
| `--ignore FILE` | — | See [ignore file format](sbom-and-vex.md#ignore-file) |
| `--license-deny LIST` | — | Comma list of SPDX id prefixes (`GPL-3.0,AGPL,SSPL`). A package violates only if **every** OR-alternative is denied |
| `--deps-dev` | off | Fills missing licenses from deps.dev (PyPI, npm, Go, Cargo, Maven, NuGet). Online modes only |
| `--no-eol` | off | Skip endoflife.date checks |
| `--no-cache` | off | Bypass the OSV cache for this run |
| `--fail-on LEVEL` | `any` | `any`, `critical`, `high`, `medium`, `low`, `never` |

### Other

| Flag | Notes |
|------|-------|
| `--hostname NAME` | Override the asset name (defaults: hostname, `image:<ref>`, `rootfs:<dir>`, `path:<dir>`, SBOM metadata name). `/` is replaced with `_` |
| `--webhook-url URL` | Slack/Teams/Mattermost (`text`) and Discord (`content`) compatible JSON POST |
| `--server-url URL` | Push the result to the backend after the scan |
| `--api-key KEY` | Sent as `X-API-Key` |
| `-v, --verbose` | Debug logging on the console |
| `--version` | Print the agent version |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Completed, nothing at/above the `--fail-on` threshold |
| `1` | No packages found, target collection failed, unreadable VEX/ignore file, or `--push-file` failed |
| `2` | Findings at/above `--fail-on`, **or** any CISA KEV match, known-malicious package, or license-policy violation (unless `--fail-on never`) |
| `130` | Interrupted (Ctrl+C) |

## Agent environment variables

| Variable | Purpose |
|----------|---------|
| `OPENBOM_STATE_DIR` | Directory for caches and diff baselines (overrides the defaults below) |
| `XDG_CACHE_HOME` | Base for the default non-root state dir (`$XDG_CACHE_HOME/openbom`) |
| `OPENBOM_SERVER_URL` | Default for `--server-url` |
| `OPENBOM_API_KEY` | Default for `--api-key` |
| `OPENBOM_WEBHOOK_URL` | Default for `--webhook-url` |

## Agent files

| Path | Content |
|------|---------|
| `<state>/osv_cache.json` | OSV records per `ecosystem\|name\|version`, 12 h TTL, only complete answers |
| `<state>/kev_cache.json` | CISA KEV catalog, 24 h TTL (stale copy used if refresh fails) |
| `<state>/eol_cache.json` | endoflife.date answers, 24 h TTL |
| `<state>/depsdev_cache.json` | deps.dev license answers |
| `<state>/last_state.json` | Host diff baseline |
| `<state>/last_state_<hash>.json` | Diff baseline for a `--path/--rootfs/--image/--sbom` target |
| `/var/log/openbom_agent.log`, else `./logs/openbom_agent.log` | Debug log |

`<state>` defaults to `/var/lib/openbom` (root) or `~/.cache/openbom`. It is created `0700`; files are
written `0600` via atomic rename. Symlinked or foreign-owned state files are ignored.

## Built-in limits

| Constant | Value | Applies to |
|----------|-------|------------|
| OSV batch size | 1000 queries | `querybatch` requests (pagination tokens are followed) |
| OSV enrichment concurrency | 20 | `GET /v1/vulns/{id}` |
| EPSS batch size | 100 CVEs | FIRST.org API |
| HTTP retries | 3 (exponential backoff, honours `Retry-After`) | 429 / 5xx / transport errors |
| Heuristic files per package | 800 | source files scanned |
| Heuristic max file size | 512 KiB | larger files skipped |
| Path scan max files | 400 000 | per `scan_path` walk |
| Archive max size | 200 MiB (nested jars 50 MiB) | JAR/WAR/EAR parsing |
| Skipped directories | `.git .hg .svn __pycache__ .tox .nox .mypy_cache .pytest_cache .ruff_cache .gradle .idea .vscode .cache` | path scans |
| Rootfs skipped top-level dirs | `proc sys dev run tmp var/tmp var/cache boot lost+found mnt media` | rootfs/image scans |

## Backend environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `DATABASE_URL` | `sqlite+aiosqlite:///openbom.db` (CWD) | `postgresql://`/`postgres://` are rewritten to `postgresql+asyncpg://` |
| `OPENBOM_API_KEY` | unset (auth off, warning logged) | Comma-separated keys; required as `X-API-Key` or `Authorization: Bearer` on every `/api/v1` route |
| `OPENBOM_CORS_ORIGINS` | `*` | Comma-separated allowed origins |
| `OPENBOM_STALE_DAYS` | `7` | Days without a scan before an asset is flagged stale |
| `OPENBOM_MAX_PACKAGES` | `200000` | Max packages per ingest payload (HTTP 413 above) |
| `OPENBOM_REANALYZE_HOURS` | `0` (off) | Re-match every stored inventory against OSV/EPSS/KEV every N hours |
| `OPENBOM_STATE_DIR` | as agent | OSV/KEV cache used by server-side analysis (SBOM upload, re-analysis) |

## Backend paths

| Path | Content |
|------|---------|
| `/` and `/dashboard` | Console (`server/static/index.html`) with a strict CSP |
| `/static/*` | Console assets; `/static/vendor/*` cached for 7 days (`immutable`) |
| `/docs`, `/openapi.json` | Swagger UI / OpenAPI schema |
| `/health` | Unauthenticated health + `auth_required` flag |
