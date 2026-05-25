<p align="center">
  <img src="https://img.shields.io/badge/OpenBOM-Supply%20Chain%20Defense-0ea5e9?style=for-the-badge&logo=shield&logoColor=white" alt="OpenBOM">
  <br>
  <img src="https://img.shields.io/badge/python-3.12+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/FastAPI-0.110+-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT License">
  <img src="https://img.shields.io/badge/platform-Linux-FCC624?style=flat-square&logo=linux&logoColor=black" alt="Linux">
</p>

# OpenBOM

**Open-source supply chain threat detection platform for Linux infrastructure.**

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
| **Multi-ecosystem SBOM** | Extracts packages from RPM, Debian/dpkg, PyPI (pip), NPM (global), and Podman containers |
| **OSV.dev integration** | Async batch queries + individual vuln enrichment for full severity/remediation data |
| **EPSS scoring** | Queries FIRST.org for exploit prediction probability on every CVE |
| **CISA KEV cross-reference** | Downloads the KEV catalog (24h cache) and flags actively exploited CVEs |
| **PoC/exploit detection** | Scans OSV references for exploit-db, PacketStorm, and GitHub PoC links |
| **Heuristic IOC scanner** | Regex-based detection of `eval(base64)`, `os.system(url)`, `pastebin/ngrok`, and more — runs only on `[NEW]` packages |
| **Delta/diff scanning** | Compares against previous scan state to label `[NEW]`, `[UPGRADED]`, `[DOWNGRADED]` packages |
| **Rich CLI output** | Progress bars, severity tables, KEV/IOC alert panels with blinking red indicators |
| **HTML/PDF reporting** | Professional dark-theme reports via Jinja2 + Tailwind CSS + WeasyPrint |
| **OSV response caching** | 12-hour file cache to avoid redundant API calls |
| **Webhook alerting** | POST to Slack/Teams when CRITICAL or KEV findings are detected |

### Backend Server (`server/`)

| Feature | Description |
|---------|-------------|
| **Async FastAPI** | Fully async with SQLAlchemy 2.0 + asyncpg/aiosqlite |
| **Flexible database** | PostgreSQL for production, SQLite for development — auto-detected |
| **Idempotent ingestion** | Re-submitting the same scan upserts without duplication |
| **Threat hunting API** | Query assets by KEV status, heuristic IOC, severity, or EPSS threshold |
| **Fleet-wide visibility** | Aggregate statistics across all managed endpoints |
| **OpenAPI docs** | Auto-generated Swagger UI at `/docs` |

## Supported Operating Systems

OpenBOM auto-detects the package manager at runtime and adapts its extraction strategy accordingly. No configuration needed — just run the agent.

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
| **Alpine Linux** | Not supported (apk) | Contribution welcome |

### Ecosystem Coverage

Package extraction is independent of the host OS — these work on any supported distribution:

| Ecosystem | Detection Method | Requirement |
|---|---|---|
| **Python (PyPI)** | `pip3 freeze --all` | Python 3.12+ with pip |
| **Node.js (NPM)** | `npm list -g --depth=0 --json` | npm installed globally |
| **Containers (Podman)** | `podman exec <id> rpm -qa` or `dpkg-query` | Podman with running containers |
| **Containers (Docker)** | Not yet supported | Contribution welcome — Docker CLI is similar to Podman |

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

# Install agent dependencies
pip install httpx rich jinja2

# Optional: PDF reports and backend
pip install weasyprint
pip install fastapi uvicorn sqlalchemy aiosqlite
```

### Run the Agent

```bash
# Scan only — generate SBOM (no network calls)
python3 agent/openbom_agent.py --scan-only

# Full threat hunt — OSV + EPSS + KEV + reporting
python3 agent/openbom_agent.py --check-osv --report --diff

# With webhook alerts
python3 agent/openbom_agent.py --check-osv --report --diff \
  --webhook-url https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

### Run the Backend

```bash
# Development (SQLite)
uvicorn server.main:app --reload --host 0.0.0.0 --port 8000

# Production (PostgreSQL)
export DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/openbom
uvicorn server.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Ingest Agent Data

```bash
# Run agent and pipe output to backend
python3 agent/openbom_agent.py --check-osv --diff -o /tmp/scan.json
curl -X POST http://your-backend:8000/api/v1/ingest \
  -H "Content-Type: application/json" \
  -d @/tmp/scan.json
```

## CLI Reference

```
usage: openbom_agent [-h] (--scan-only | --check-osv) [-o OUTPUT] [--report]
                     [--no-cache] [--diff] [--webhook-url WEBHOOK_URL] [-v]

Options:
  --scan-only            Collect SBOM only (no network calls)
  --check-osv            Full scan: OSV + EPSS + KEV + PoC detection
  -o, --output PATH      JSON report output path
  --report               Generate HTML and PDF enterprise reports
  --diff                 Compare against previous scan state
  --no-cache             Bypass 12-hour OSV response cache
  --webhook-url URL      POST alerts to Slack/Teams webhook
  -v, --verbose          Debug-level console logging
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan complete, no vulnerabilities found |
| `1` | No packages found (empty system) |
| `2` | Vulnerabilities detected |
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
| `GET` | `/api/v1/assets/{hostname}/vulnerabilities` | Vulnerabilities affecting an asset |

## Project Structure

```
OpenBOM/
├── agent/
│   ├── openbom_agent.py              # Endpoint agent (1,378 lines)
│   └── templates/
│       └── report_template.html      # Jinja2 + Tailwind HTML report template
├── server/
│   ├── main.py                       # FastAPI application entry point
│   ├── database.py                   # Async SQLAlchemy engine + session
│   ├── models.py                     # ORM models (Asset, Package, Vulnerability)
│   ├── schemas.py                    # Pydantic request/response schemas
│   └── routers/
│       ├── ingest.py                 # POST /api/v1/ingest
│       ├── threats.py                # GET /api/v1/threats/*
│       └── assets.py                 # GET /api/v1/assets/*
├── docs/
│   ├── architecture.md               # System architecture deep-dive
│   ├── agent-guide.md                # Endpoint agent deployment guide
│   ├── api-reference.md              # Backend API documentation
│   ├── threat-model.md               # Threat intelligence methodology
│   └── deployment.md                 # Production deployment guide
├── output/                           # Generated reports (JSON, HTML, PDF)
├── logs/                             # Agent log files
└── README.md
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | System design, data flow, and database schema |
| [Agent Guide](docs/agent-guide.md) | Deploying and configuring the endpoint agent |
| [API Reference](docs/api-reference.md) | Complete REST API documentation |
| [Threat Model](docs/threat-model.md) | How OpenBOM layers intelligence sources for threat prioritization |
| [Deployment Guide](docs/deployment.md) | Production deployment with PostgreSQL, systemd, and fleet management |

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
