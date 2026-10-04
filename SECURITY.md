# Security Policy

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately by e-mail to **riyan.pratama@security-life.org**, or through a GitHub security advisory:
<https://github.com/Masriyan/OpenBOM/security/advisories/new>

Please include a description, reproduction steps, affected component and version, impact, and a
suggested fix if you have one. We acknowledge reports within 48 hours and agree on a disclosure
timeline with you. Credit is given in the changelog unless you prefer otherwise.

## Supported versions

| Component | Version | Supported |
|-----------|---------|-----------|
| Agent | 5.1.x | ✅ |
| Agent | 5.0.x | security fixes only |
| Agent | ≤ 4.x | ❌ (cached vulnerability data in `/tmp`, PyPI-only matching) |
| Backend | 2.1.x | ✅ |
| Backend | 2.0.x | security fixes only |
| Backend | ≤ 1.x | ❌ (no authentication) |

## Scope

* Endpoint agent — `agent/openbom_agent.py`, `agent/templates/`
* Backend — `server/` including the console in `server/static/`
* Vendored front-end libraries are in scope for how we ship them; vulnerabilities in the libraries
  themselves should also be reported upstream (see `server/static/vendor/LICENSES.md`).

Out of scope: findings that require an already-compromised host or a malicious backend administrator,
missing hardening of third-party infrastructure (your reverse proxy, database), and the accuracy of
upstream intelligence feeds (OSV, CISA KEV, EPSS, endoflife.date, deps.dev).

## Security design

### Agent

* Runs unprivileged for user-level scans; root is only needed to read root-owned package metadata.
* Makes outbound HTTPS requests only: `api.osv.dev`, `api.first.org`, `www.cisa.gov`, `endoflife.date`,
  `api.deps.dev` (only with `--deps-dev`), plus the backend and webhook URLs you configure. Never listens on a port.
* Sends package names, versions, licenses, OS name and findings — never file contents, credentials or
  environment variables.
* Heuristic scanning reads package source as text; nothing is imported or executed. Symlinks are not followed.
* Caches and diff baselines live in a private state dir (`~/.cache/openbom` or `/var/lib/openbom`,
  mode `0700`, files `0600`), written atomically. Symlinked or foreign-owned state files are ignored —
  a local attacker cannot poison the cache to hide findings or redirect writes.
* Image extraction uses `tarfile` data filters: path traversal, absolute symlinks and device files are
  skipped. The temporary rootfs is deleted after the scan.
* Webhook URLs (which embed secrets) are never logged; only the host name is.
* HTML reports are rendered with Jinja2 autoescaping (package metadata is untrusted).

### Backend

* API-key authentication on every `/api/v1` route when `OPENBOM_API_KEY` is set (constant-time
  comparison, multiple keys supported). Without it the server logs a warning at startup.
* Pydantic validation of every payload with size limits (`OPENBOM_MAX_PACKAGES`, field lengths);
  hostnames cannot contain `/`.
* SQLAlchemy parameterised queries only.
* Security headers on every response (`X-Content-Type-Options`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`).
* Console: `Content-Security-Policy` with `script-src 'self'` (no inline script, no eval), `object-src
  'none'`, `frame-ancestors 'none'`; all libraries vendored (no third-party origins); untrusted data
  rendered as text by React.
* CORS is configurable with `OPENBOM_CORS_ORIGINS` (default `*`; the API uses header auth, not cookies).

### Deployment recommendations

* Always set `OPENBOM_API_KEY` and put the backend behind TLS (see [docs/deployment.md](docs/deployment.md)).
* Use PostgreSQL with TLS for fleets; restrict database access to the backend host.
* Restrict `OPENBOM_CORS_ORIGINS` to the console origin if browsers on other origins should not call the API.
* Treat the agent log (`/var/log/openbom_agent.log`) as internal: it contains host and package names.
