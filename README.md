<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/banner.svg">
    <source media="(prefers-color-scheme: light)" srcset="assets/banner.svg">
    <img src="assets/banner.svg" alt="OpenBOM — Supply Chain Threat Hunter" width="100%">
  </picture>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.12+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/FastAPI-0.110+-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT License">
  <img src="https://img.shields.io/badge/platform-Linux-FCC624?style=flat-square&logo=linux&logoColor=black" alt="Linux">
  <img src="https://img.shields.io/badge/OSV.dev-Integrated-4285F4?style=flat-square" alt="OSV.dev">
  <img src="https://img.shields.io/badge/CISA%20KEV-Integrated-cc0000?style=flat-square" alt="CISA KEV">
  <img src="https://img.shields.io/badge/EPSS-Integrated-ff6b35?style=flat-square" alt="EPSS">
</p>

# OpenBOM

**Open-source supply chain threat detection platform for Linux infrastructure.**

<p align="center"><img src="assets/dashboard-overview.jpg" alt="OpenBOM console (Arco Design) — fleet overview" width="100%"></p>

<p align="center"><img src="assets/dashboard-vulnerabilities.jpg" alt="OpenBOM console — vulnerabilities with the package, fix and the path where each copy was found" width="100%"></p>

> How OpenBOM compares to Syft, Grype, Trivy, OSV-Scanner, cdxgen, Dependency-Track and Socket:
> **[docs/comparison.md](docs/comparison.md)**.

OpenBOM continuously inventories every package on your endpoints — OS packages, Python libraries, NPM modules, and container images — then cross-references them against vulnerability databases, exploit intelligence feeds, and behavioral heuristics to surface the threats that actually matter: actively exploited CVEs, packages with public proof-of-concept exploits, and newly installed code exhibiting malware patterns.

---

## The Problem

Modern infrastructure runs on thousands of open-source dependencies. A single compromised package in PyPI or NPM can give an attacker code execution across your entire fleet. Traditional vulnerability scanners tell you what *could* be exploited. OpenBOM tells you what *is being* exploited — right now, on your systems.

The software supply chain is under siege:

- **Dependency confusion** attacks inject malicious packages into private registries
- **Typosquatting** campaigns publish near-identical package names with embedded backdoors
- **Compromised maintainer accounts** push silent updates to trusted libraries
- **Known exploited vulnerabilities** remain unpatched for months across production systems

OpenBOM was built to close the gap between vulnerability discovery and threat response.

## The Mission

> Make the software supply chain ecosystem more secure by giving defenders real-time visibility into what's installed, what's vulnerable, and what's actively under attack — across every endpoint, in every ecosystem.

OpenBOM is not another vulnerability scanner. It is a **threat hunting platform** that combines:

1. **Software Bill of Materials (SBOM)** generation across OS, language, and container ecosystems
2. **Vulnerability intelligence** from OSV.dev with severity classification and remediation guidance
3. **Exploit prediction** via EPSS scores to prioritize what's likely to be weaponized
4. **Active exploitation tracking** through CISA's Known Exploited Vulnerabilities catalog
5. **Proof-of-concept monitoring** by detecting exploit-db, PacketStorm, and GitHub PoC references
6. **Zero-day heuristic detection** that scans newly installed packages for malware IOC patterns
7. **Centralized fleet management** with a FastAPI backend that aggregates findings from all endpoints

## How OpenBOM Works

```
                          +-----------------------+
                          |    OpenBOM Backend     |
                          |    (FastAPI Server)    |
                          |                        |
                          |  PostgreSQL / SQLite   |
                          |  Asset ←M:N→ Package   |
                          |  Package ←M:N→ Vuln    |
                          +-----------+------------+
                                      |
                            POST /api/v1/ingest
                                      |
         +----------------------------+----------------------------+
         |                            |                            |
+--------+--------+        +---------+---------+        +---------+---------+
|  Endpoint Agent  |       |  Endpoint Agent    |       |  Endpoint Agent    |
|  (web-server-01) |       |  (db-server-01)    |       |  (ci-runner-03)    |
|                  |       |                    |       |                    |
|  RPM + PyPI +    |       |  Debian + PyPI +   |       |  RPM + NPM +      |
|  NPM + Podman   |       |  Podman            |       |  PyPI              |
+------------------+       +--------------------+       +--------------------+
         |                            |                            |
    +---------+                 +---------+                 +---------+
    | OSV.dev |                 | EPSS    |                 | CISA    |
    | API     |                 | API     |                 | KEV     |
    +---------+                 +---------+                 +---------+
```

### The Idea Behind OpenBOM

OpenBOM started from a simple observation: **security teams don't need more CVE numbers — they need signal**.

When a scan returns 500 vulnerabilities, what do you patch first? CVSS scores alone don't answer that. OpenBOM layers multiple intelligence sources to produce a prioritized, actionable threat picture:

| Signal | Source | What It Tells You |
|--------|--------|-------------------|
| Vulnerability exists | OSV.dev | This package version has a known flaw |
| Severity classification | CVSS v3 + database_specific | How bad the flaw is in theory |
| Exploit probability | FIRST.org EPSS | How likely it is to be weaponized in the next 30 days |
| Active exploitation | CISA KEV catalog | It **is** being exploited right now in the wild |
| Public exploit code | PoC link detection | Exploit code is freely available to attackers |
| Malware indicators | Heuristic IOC scan | The package itself contains suspicious code patterns |
| Change detection | Delta/diff scanning | This package was just installed or downgraded |

By fusing these signals, OpenBOM transforms a wall of CVEs into a short list of things that demand immediate action.

## Features

### Endpoint Agent (`agent/openbom_agent.py`)

| Feature | Description |
|---------|-------------|
| **Multi-ecosystem SBOM** | Host RPM / dpkg / apk, global pip & npm, running Podman/Docker containers |
| **Scan targets** | `--path` repos (requirements, Poetry/uv/Pipfile, npm/yarn/pnpm, go.mod, Cargo, Gemfile, Composer, NuGet, Maven/Gradle, venvs, node_modules, nested JAR/WAR), `--rootfs`, `--image` (podman/docker), `--sbom` (CycloneDX/SPDX from Syft, Trivy, cdxgen…) |
| **Known-malicious packages** | OpenSSF malicious-package advisories (OSV `MAL-*`) flagged CRITICAL with "treat host as compromised" guidance |
| **License compliance** | Licenses from rpm/apk/Debian copyright/PyPI/npm/lockfiles, optional deps.dev enrichment, `--license-deny` policy gate |
| **End-of-life** | OS, Python and Node.js EOL via endoflife.date |
| **VEX & ignore** | `--vex` (OpenVEX / CycloneDX VEX) and `--ignore` (with expiry dates) suppress triaged findings |
| **SPDX / SARIF** | `--spdx` (SPDX 2.3) and `--sarif` (GitHub/GitLab code scanning) alongside CycloneDX |
| **OSV.dev integration** | PyPI, npm, **Debian, Ubuntu, AlmaLinux, Rocky Linux** (OS + container packages, source-package/epoch aware). Async batch + enrichment with retry/backoff |
| **Accurate scoring** | Real CVSS v3.1 base-score calculation, GHSA/Ubuntu/RHEL qualitative ratings, fix version chosen from the range that contains the installed version, GHSA↔PYSEC alias de-duplication |
| **EPSS scoring** | Queries FIRST.org for exploit prediction probability on every CVE |
| **CISA KEV cross-reference** | Downloads the KEV catalog (24h cache) and flags actively exploited CVEs |
| **PoC/exploit detection** | Scans OSV references for exploit-db, PacketStorm, and GitHub PoC links |
| **Heuristic IOC scanner** | Strong indicators (`exec(base64)`, reverse shells, miners, `curl \| sh` npm install hooks) → CRITICAL; co-occurring weak indicators (credential paths + Discord/Telegram exfil, `.pth` auto-exec…) → HIGH. Scope: `--heuristics new\|all\|off` |
| **Typosquat detection** | Flags PyPI/npm packages one edit away from popular names (`reqeusts`, `lodahs`) with a curated allowlist of legitimate look-alikes |
| **Package locations** | Every package records where it lives: `*.dist-info` / `node_modules` dir on hosts, lockfile/venv/manifest for `--path` and `--rootfs` scans. It is shown in the CLI, HTML report, JSON and console, so you know *which* copy to fix |
| **Delta/diff scanning** | Labels `[NEW]`, `[UPGRADED]`, `[DOWNGRADED]` with rpm/dpkg/PEP 440/semver ordering; lists removed packages |
| **CycloneDX 1.5 export** | `--cyclonedx PATH` writes a standard SBOM with purls and vulnerabilities |
| **Backend push** | `--server-url` / `--push-file` upload results directly (API-key aware) |
| **Interactive menu** | Run with no flags on a terminal for a guided menu (scan, hunt, view, push, export, cache management) |
| **CI gating** | `--fail-on critical\|high\|…` controls exit code 2 |
| **Rich CLI output** | Progress bars, severity tables, KEV/IOC alert panels (with "found in" paths) |
| **HTML/PDF reporting** | Professional dark-theme reports via Jinja2 + Tailwind CSS + WeasyPrint |
| **Safe caching** | 12h OSV / 24h KEV caches in a private `0700` state dir (never `/tmp`), atomic writes, failed lookups never cached as "clean" |
| **Webhook alerting** | POST to Slack/Teams/Discord when CRITICAL, KEV or IOC findings are detected |

### Backend Server (`server/`)

| Feature | Description |
|---------|-------------|
| **Async FastAPI** | Fully async with SQLAlchemy 2.0 + asyncpg/aiosqlite |
| **Flexible database** | PostgreSQL for production, SQLite for development — auto-detected |
| **Snapshot ingestion** | Idempotent bulk upsert; uninstalled/upgraded packages are unlinked so findings reflect what is installed *now* |
| **Web console (Arco Design)** | `http://server:8000/` — Overview, Assets, Threat Hunt (Malicious/KEV/IOC/Critical/EPSS), Vulnerabilities, Package Search, Licenses, End-of-Life, Triage & VEX, SBOM Import, Reports & Export, Agent Setup, Settings. Shows the path of every affected package. Dark/light theme with smooth motion (respects reduced-motion), offline (vendored assets), strict CSP |
| **Triage & VEX** | Fleet-wide or per-asset decisions (not_affected, false_positive, …) suppress findings; `resolved` findings that are still detected are flagged; OpenVEX import/export |
| **SBOM import & continuous monitoring** | Upload CycloneDX/SPDX from any tool; re-match stored inventories against fresh OSV/EPSS/KEV on demand or every `OPENBOM_REANALYZE_HOURS` |
| **Threat hunting API** | KEV, heuristic IOC, severity, EPSS, fleet-wide package search ("who has xz 5.6.0, and where?"), vuln → affected hosts and paths |
| **Risk scoring & history** | Per-asset 0-100 risk score, stale-asset detection, per-scan history |
| **API-key auth** | `OPENBOM_API_KEY` protects all `/api/v1` routes |
| **CycloneDX export** | `/api/v1/assets/{host}/sbom` |
| **OpenAPI docs** | Auto-generated Swagger UI at `/docs` |

## Supported Operating Systems

OpenBOM auto-detects the package manager at runtime and adapts its extraction strategy accordingly. No configuration needed — just run the agent.

> **Vulnerability coverage of OS packages** depends on OSV.dev advisory feeds: **Debian, Ubuntu, AlmaLinux,
> Rocky Linux and Alpine** packages (host and Podman containers) are checked. Fedora, RHEL, CentOS Stream,
> openSUSE and Amazon Linux packages are inventoried and diffed, but OSV publishes no advisories for them.
> PyPI and npm packages are checked on every distribution.

### Tier 1 — Fully Tested

These distributions are actively tested and used in development. All features work out of the box.

| Distribution | Versions | Package Manager | Container Engine |
|---|---|---|---|
| **Fedora** | 39, 40, 41, 42 | `rpm` / `dnf` | Podman (native) |
| **RHEL** | 8, 9 | `rpm` / `dnf` | Podman (native) |
| **CentOS Stream** | 8, 9 | `rpm` / `dnf` | Podman (native) |
| **Ubuntu** | 22.04, 24.04 | `dpkg-query` / `apt` | Podman / Docker |
| **Debian** | 11 (Bullseye), 12 (Bookworm) | `dpkg-query` / `apt` | Podman / Docker |

### Tier 2 — Expected to Work

These distributions use the same package managers and should work without modification, but receive less frequent testing.

| Distribution | Package Manager | Notes |
|---|---|---|
| **AlmaLinux** 8, 9 | `rpm` / `dnf` | RHEL binary-compatible |
| **Rocky Linux** 8, 9 | `rpm` / `dnf` | RHEL binary-compatible |
| **Oracle Linux** 8, 9 | `rpm` / `dnf` | RHEL binary-compatible |
| **openSUSE** Leap 15.x, Tumbleweed | `rpm` / `zypper` | RPM extraction works; `zypper` not used directly |
| **SUSE Linux Enterprise** 15 | `rpm` / `zypper` | Same as openSUSE |
| **Amazon Linux** 2, 2023 | `rpm` / `dnf` / `yum` | Common on AWS EC2 |
| **Linux Mint** 21, 22 | `dpkg-query` / `apt` | Ubuntu-based |
| **Pop!_OS** 22.04 | `dpkg-query` / `apt` | Ubuntu-based |
| **Kali Linux** | `dpkg-query` / `apt` | Debian-based |
| **Arch Linux** | Not supported (pacman) | Contribution welcome |
| **Alpine Linux** 3.x | `apk` (`/lib/apk/db/installed`) | OS packages OSV-checked (`Alpine:vX.Y`); also in images/containers |

### Ecosystem Coverage

Package extraction is independent of the host OS — these work on any supported distribution:

| Ecosystem | Detection Method | Requirement |
|---|---|---|
| **Python (PyPI)** | `pip3 freeze --all` | Python 3.12+ with pip |
| **Node.js (NPM)** | `npm list -g --depth=0 --json` | npm installed globally |
| **Containers (Podman)** | `podman exec <id> rpm -qa` or `dpkg-query` | Podman with running containers |
| **Containers (Docker)** | `docker exec <id> rpm -qa` / `dpkg-query` / apk db | Docker with running containers |
| **Container images** | `--image REF` → `podman/docker create` + `export` → rootfs scan | podman or docker |
| **Project lockfiles** | `--path DIR` — Python, npm/yarn/pnpm, Go, Cargo, RubyGems, Composer, NuGet, Maven/Gradle, JAR/WAR | none (pure parsing) |

### Backend Server

The backend server runs on any OS with Python 3.12+, but is tested on:

| Platform | Database | Status |
|---|---|---|
| **Linux** (any distribution) | PostgreSQL 14+ / SQLite | Fully supported |
| **macOS** | PostgreSQL / SQLite | Works (development use) |
| **Windows (WSL2)** | PostgreSQL / SQLite | Works (development use) |

## Quick Start

### Prerequisites

- Python 3.12+
- Linux (any Tier 1 or Tier 2 distribution above)
- `pip`, `rpm` or `dpkg-query` (auto-detected)

### Installation

```bash
git clone https://github.com/Masriyan/OpenBOM.git
cd OpenBOM

# Agent + backend + test dependencies
pip install -r requirements.txt

# Optional: PDF reports / PostgreSQL
pip install weasyprint asyncpg

# Run the test suite
python3 -m pytest
```

### Run the Agent

```bash
# Interactive menu (on a terminal, no flags)
python3 agent/openbom_agent.py

# Scan only — generate SBOM (no network calls)
python3 agent/openbom_agent.py --scan-only

# Full threat hunt — OSV + EPSS + KEV + reporting
python3 agent/openbom_agent.py --check-osv --report --diff

# With webhook alerts
python3 agent/openbom_agent.py --check-osv --report --diff \
  --webhook-url https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Hunt and push straight to the backend
OPENBOM_API_KEY=... python3 agent/openbom_agent.py --check-osv --diff --server-url http://openbom:8000
```

### Run the Backend

```bash
# Development (SQLite)
uvicorn server.main:app --reload --host 0.0.0.0 --port 8000

# Production (PostgreSQL + API key)
export DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/openbom
export OPENBOM_API_KEY=$(openssl rand -hex 24)
uvicorn server.main:app --host 0.0.0.0 --port 8000 --workers 4
```

Open `http://localhost:8000/` for the dashboard (enter the API key under **Settings**) and `/docs` for the API.

### Ingest Agent Data

```bash
# Run agent and pipe output to backend
python3 agent/openbom_agent.py --check-osv --diff -o scan.json
python3 agent/openbom_agent.py --push-file scan.json --server-url http://your-backend:8000 --api-key "$OPENBOM_API_KEY"
# or: curl -X POST http://your-backend:8000/api/v1/ingest -H "Content-Type: application/json" \
#          -H "X-API-Key: $OPENBOM_API_KEY" -d @scan.json
```

## CLI Reference

```
usage: openbom_agent [--scan-only | --check-osv | --push-file JSON | --menu] [options]

Modes (none on a terminal = interactive menu; a scan target alone implies --check-osv):
  --scan-only            Collect SBOM only (no network calls)
  --check-osv            Full scan: OSV + MAL + EPSS + KEV + EOL
  --push-file JSON       Upload an existing scan JSON to --server-url
  --menu                 Interactive menu

Scan targets (default: this host):
  --path DIR             Repository / build tree (repeatable)
  --rootfs DIR           Unpacked root filesystem
  --image REF            Container image via podman or docker
  --sbom FILE            Existing CycloneDX / SPDX JSON SBOM
  --ecosystems LIST      Host sources: os,pypi,npm,podman,docker

Outputs:
  -o, --output PATH      JSON report path         --output-dir DIR   (default ./output)
  --report               HTML + PDF report        --cyclonedx PATH   CycloneDX 1.5
  --spdx PATH            SPDX 2.3                 --sarif PATH       SARIF 2.1.0

Analysis & policy:
  --diff                 Delta vs. previous scan of the same target
  --heuristics MODE      new (default; needs --diff) | all | off
  --vex FILE             OpenVEX / CycloneDX VEX suppressions (repeatable)
  --ignore FILE          'VULN-ID [package|purl] [until=YYYY-MM-DD] # reason'
  --license-deny LIST    e.g. GPL-3.0,AGPL,SSPL (fails the run)
  --deps-dev             Fill missing licenses from deps.dev
  --no-eol               Skip end-of-life checks
  --fail-on LEVEL        any | critical | high | medium | low | never
  --no-cache             Bypass the 12-hour OSV cache

Other:
  --hostname NAME  --webhook-url URL  --server-url URL  --api-key KEY  -v  --version
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan complete, no vulnerabilities found |
| `1` | No packages found (empty system) |
| `2` | Findings at/above `--fail-on`, any KEV / malicious package, or a license-policy violation |
| `130` | Interrupted by user (Ctrl+C) |

## API Reference

See [docs/api-reference.md](docs/api-reference.md) for complete endpoint documentation.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Service health check |
| `POST` | `/api/v1/ingest` | Receive agent scan payload |
| `GET` | `/api/v1/threats/summary` | Fleet-wide threat statistics |
| `GET` | `/api/v1/threats/kev` | Assets with actively exploited CVEs |
| `GET` | `/api/v1/threats/heuristics` | Assets with malware IOC detections |
| `GET` | `/api/v1/threats/critical` | Assets with CRITICAL vulnerabilities |
| `GET` | `/api/v1/threats/high-epss` | Assets above EPSS exploit probability threshold |
| `GET` | `/api/v1/assets` | List all managed assets |
| `GET` | `/api/v1/assets/{hostname}` | Single asset detail |
| `GET` | `/api/v1/assets/{hostname}/packages` | Packages installed on an asset |
| `GET` | `/api/v1/assets/{hostname}/vulnerabilities` | Vulnerabilities affecting an asset (with per-package fix) |
| `GET` | `/api/v1/assets/{hostname}/scans` | Scan history |
| `GET` | `/api/v1/assets/{hostname}/sbom` | CycloneDX 1.5 export |
| `DELETE` | `/api/v1/assets/{hostname}` | Decommission an asset |
| `GET` | `/api/v1/packages/search` | Which hosts have package X (version Y) |
| `GET` | `/api/v1/vulnerabilities` | Fleet vulnerability list with filters |
| `GET` | `/api/v1/vulnerabilities/{vuln_id}` | Vulnerability detail + affected hosts |
| `POST` | `/api/v1/maintenance/prune` | Remove orphaned packages/vulns |
| `GET` | `/api/v1/threats/malicious` | Assets with known-malicious packages |
| `GET/PUT/DELETE` | `/api/v1/triage` | Analyst decisions (fleet-wide or per asset) |
| `GET/POST` | `/api/v1/vex` | Export / import OpenVEX |
| `GET` | `/api/v1/licenses`, `/api/v1/licenses/packages` | License inventory |
| `GET` | `/api/v1/eol` | Assets running end-of-life software |
| `POST` | `/api/v1/sbom` | Import a CycloneDX/SPDX SBOM (optionally analysed server-side) |
| `POST` | `/api/v1/reanalyze`, `/api/v1/assets/{hostname}/reanalyze` | Continuous monitoring: re-match stored inventories |

## Project Structure

```
OpenBOM/
├── agent/
│   ├── openbom_agent.py              # Endpoint agent (single file by design)
│   └── templates/
│       └── report_template.html      # Jinja2 + Tailwind HTML report template
├── server/
│   ├── main.py                       # FastAPI app, dashboard route, security headers
│   ├── config.py / security.py       # Env settings, API-key auth
│   ├── database.py                   # Async engine, SQLite pragmas, init + column migration
│   ├── models.py                     # ORM models (Asset, Package, Vulnerability, ScanRecord, Triage)
│   ├── schemas.py                    # Pydantic request/response schemas
│   ├── queries.py / sbom.py          # Shared joins, triage suppression, risk score, CycloneDX export
│   ├── analyzer.py                   # Reuses the agent engine for SBOM uploads + re-analysis
│   ├── static/                       # Arco Design console: index.html, app.js, app.css, logos, vendor/
│   └── routers/
│       ├── ingest.py                 # POST /api/v1/ingest
│       ├── threats.py                # GET /api/v1/threats/*
│       ├── assets.py                 # /api/v1/assets/*
│       ├── hunt.py                   # packages/search, vulnerabilities, maintenance
│       └── governance.py             # triage, VEX, licenses, EOL, SBOM import, re-analysis
├── tests/                            # pytest suite (agent, API, governance, console checks)
├── .github/                          # issue + pull request templates
├── docs/
│   ├── architecture.md               # System architecture deep-dive
│   ├── agent-guide.md                # Endpoint agent deployment guide
│   ├── api-reference.md              # Backend API documentation
│   ├── threat-model.md               # Threat intelligence methodology
│   ├── deployment.md                 # Production deployment guide
│   └── …                             # configuration, dashboard, CI, SBOM/VEX, detection rules,
│                                     # development, troubleshooting, comparison (see docs/README.md)
├── CHANGELOG.md · ROADMAP.md · SECURITY.md · CONTRIBUTING.md · CODE_OF_CONDUCT.md
├── output/                           # Generated reports (JSON, HTML, PDF) — git-ignored
├── logs/                             # Agent log files — git-ignored
└── README.md
```

## Documentation

Full index: **[docs/README.md](docs/README.md)**

| Document | Description |
|----------|-------------|
| [Agent Guide](docs/agent-guide.md) | Scan modes, targets (host, repo, image, rootfs, SBOM), outputs, menu, scheduling |
| [Dashboard Guide](docs/dashboard-guide.md) | Every console menu, triage workflow, SBOM import, exports |
| [Configuration Reference](docs/configuration.md) | All CLI flags, environment variables, files and limits |
| [CI/CD Integration](docs/ci-integration.md) | GitHub Actions, GitLab CI, Jenkins, SARIF upload, build gating |
| [SBOM, VEX & Triage](docs/sbom-and-vex.md) | CycloneDX/SPDX/OpenVEX exchange, purls, suppression semantics |
| [Detection Rules](docs/detection-rules.md) | Heuristic IOC, typosquat and malicious-package logic, tuning |
| [Architecture](docs/architecture.md) | Agent pipeline, data model, ingestion, console |
| [API Reference](docs/api-reference.md) | REST API |
| [Threat Model](docs/threat-model.md) | How intelligence layers become priorities |
| [Deployment Guide](docs/deployment.md) | PostgreSQL, systemd, TLS, fleet rollout, alerting |
| [Troubleshooting](docs/troubleshooting.md) | Common problems and fixes |
| [Development Guide](docs/development.md) | Dev setup, tests, extending parsers/rules/console |
| [Market Comparison](docs/comparison.md) | OpenBOM vs. Syft, Grype, Trivy, OSV-Scanner, Dependency-Track, Socket |
| [Changelog](CHANGELOG.md) · [Roadmap](ROADMAP.md) · [Security](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Code of Conduct](CODE_OF_CONDUCT.md) | Project policies |

## Intelligence Sources

| Source | URL | Usage |
|--------|-----|-------|
| OSV.dev | https://osv.dev | Vulnerability database (batch + individual queries) |
| FIRST.org EPSS | https://www.first.org/epss/ | Exploit Prediction Scoring System |
| CISA KEV | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | Known Exploited Vulnerabilities catalog |
| Exploit-DB | https://www.exploit-db.com | PoC reference detection |
| PacketStorm | https://packetstormsecurity.com | PoC reference detection |

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request at https://github.com/Masriyan/OpenBOM/pulls

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments

- [OSV.dev](https://osv.dev) by Google for the open vulnerability database
- [FIRST.org](https://www.first.org/epss/) for the EPSS exploit prediction model
- [CISA](https://www.cisa.gov) for the Known Exploited Vulnerabilities catalog
- The open-source security community for building the tools that make this possible

---

<p align="center">
  <strong>OpenBOM</strong> — Because knowing what's installed is the first line of defense.<br>
  <a href="https://github.com/Masriyan/OpenBOM">https://github.com/Masriyan/OpenBOM</a>
</p>
