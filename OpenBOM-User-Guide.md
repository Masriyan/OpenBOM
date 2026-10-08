---
title: "OpenBOM: Complete User Guide"
subtitle: "Installation, endpoint agent, web console, features and operations"
author:
  - "Riyan Pratama"
  - "https://github.com/Masriyan/OpenBOM"
date: "October 2026 · Agent 5.1.0 · Backend 2.2.0"
---

# Contents

- [Foreword](#foreword)
- [Background](#background)
    - [Why OpenBOM exists](#why-openbom-exists)
    - [The idea](#the-idea)
    - [Design principles](#design-principles)
- [About this guide](#about-this-guide)
- [1. Introduction](#1-introduction)
    - [1.1 What OpenBOM is](#11-what-openbom-is)
    - [1.2 Components](#12-components)
    - [1.3 Architecture](#13-architecture)
    - [1.4 Intelligence signals](#14-intelligence-signals)
- [2. Installation](#2-installation)
    - [2.1 Requirements](#21-requirements)
    - [2.2 Get the code and install dependencies](#22-get-the-code-and-install-dependencies)
    - [2.3 Verify the installation](#23-verify-the-installation)
    - [2.4 Start the backend (quick start)](#24-start-the-backend-quick-start)
    - [2.5 Your first scan](#25-your-first-scan)
    - [2.6 Production deployment](#26-production-deployment)
    - [2.7 Rolling the agent out to a fleet](#27-rolling-the-agent-out-to-a-fleet)
    - [2.8 Upgrading](#28-upgrading)
- [3. The endpoint agent](#3-the-endpoint-agent)
    - [3.1 Modes](#31-modes)
    - [3.2 Interactive menu](#32-interactive-menu)
    - [3.3 Scan targets](#33-scan-targets)
    - [3.4 Analysis features](#34-analysis-features)
    - [3.5 Outputs](#35-outputs)
    - [3.6 Exit codes](#36-exit-codes)
    - [3.7 Suppressing accepted findings](#37-suppressing-accepted-findings)
    - [3.8 Command-line reference](#38-command-line-reference)
- [4. The web console](#4-the-web-console)
    - [4.1 First login and layout](#41-first-login-and-layout)
    - [4.2 Overview](#42-overview)
    - [4.3 Assets](#43-assets)
    - [4.4 Asset detail](#44-asset-detail)
    - [4.5 Trends](#45-trends)
    - [4.6 Threat Hunt](#46-threat-hunt)
    - [4.7 Vulnerabilities](#47-vulnerabilities)
    - [4.8 Package Search](#48-package-search)
    - [4.9 Licenses](#49-licenses)
    - [4.10 End-of-Life](#410-end-of-life)
    - [4.11 Triage & VEX](#411-triage--vex)
    - [4.12 Audit Log](#412-audit-log)
    - [4.13 SBOM Import](#413-sbom-import)
    - [4.14 Reports & Export](#414-reports--export)
    - [4.15 Agent Setup](#415-agent-setup)
    - [4.16 Settings](#416-settings)
    - [4.17 Themes and small screens](#417-themes-and-small-screens)
- [5. Common workflows](#5-common-workflows)
    - [5.1 Onboard a server](#51-onboard-a-server)
    - [5.2 Respond to a CISA KEV finding](#52-respond-to-a-cisa-kev-finding)
    - [5.3 Handle a known-malicious package](#53-handle-a-known-malicious-package)
    - [5.4 Accept a finding that does not apply](#54-accept-a-finding-that-does-not-apply)
    - [5.5 Gate a CI pipeline](#55-gate-a-ci-pipeline)
    - [5.6 Import a third-party SBOM](#56-import-a-third-party-sbom)
    - [5.7 Continuous monitoring between scans](#57-continuous-monitoring-between-scans)
    - [5.8 Review exposure trends for management](#58-review-exposure-trends-for-management)
- [6. Concepts](#6-concepts)
    - [6.1 Assets and targets](#61-assets-and-targets)
    - [6.2 Snapshot ingestion and partial scans](#62-snapshot-ingestion-and-partial-scans)
    - [6.3 Vulnerabilities belong to package versions](#63-vulnerabilities-belong-to-package-versions)
    - [6.4 Finding history and MTTR](#64-finding-history-and-mttr)
    - [6.5 Heuristic detection and typosquatting](#65-heuristic-detection-and-typosquatting)
    - [6.6 Package URLs (purl)](#66-package-urls-purl)
    - [6.7 Stale assets](#67-stale-assets)
- [7. REST API](#7-rest-api)
- [8. Configuration reference](#8-configuration-reference)
    - [8.1 Backend environment variables](#81-backend-environment-variables)
    - [8.2 Built-in limits](#82-built-in-limits)
- [9. Security notes](#9-security-notes)
- [10. Troubleshooting](#10-troubleshooting)
    - [10.1 Agent](#101-agent)
    - [10.2 Backend and console](#102-backend-and-console)
- [11. Glossary](#11-glossary)


# Foreword

Every system you run is built from code you did not write.

Thousands of packages. Most of them you have never read, written by people you will never meet,
pulled in by tools that never asked for permission. Somewhere in that pile sits the version an
attacker is already using. The question is never whether it exists. The question is whether you find
it first.

Attackers do not respect your patch cycle. They read the same advisories you do, on the day they are
published, and they do not wait for a change window. A malicious package does not announce itself. It
installs quietly, runs once, and leaves nothing for you to notice.

OpenBOM was built for that silence. It does not guess and it does not reassure. It records what is
installed, where it lives, what is known about it, and what is being exploited right now. Nothing
more. Nothing softer.

Read the numbers. Then act on them.

**Riyan Pratama**\
*Author of OpenBOM*

# Background

## Why OpenBOM exists

Modern Linux infrastructure runs on thousands of open-source dependencies: operating-system packages,
Python and npm libraries, container images, and the lockfiles of every service you deploy. A single
compromised package can hand an attacker code execution across an entire fleet, and the supply chain
has become a preferred way in:

* **Dependency confusion** pushes malicious packages into the resolution path of private projects.
* **Typosquatting** publishes near-identical names (`reqeusts`, `colourama`) with a payload inside.
* **Compromised maintainers** ship silent backdoors in trusted libraries, as the xz-utils backdoor
  (CVE-2024-3094) showed in 2024.
* **Known exploited vulnerabilities** stay unpatched for months because nobody can see where they are.

Traditional scanners answer the question "what could be exploited?". They return hundreds of CVE
numbers, and a security team still has to work out what to patch first, on which machine, and in which
copy of the package. OpenBOM started from a simple observation: **defenders do not need more CVE
numbers, they need signal.**

## The idea

OpenBOM layers several independent intelligence sources on top of a precise inventory, so that a wall
of vulnerabilities becomes a short list of actions:

1. **Know what is installed**, on every host, image, repository and SBOM, and **where** each copy lives.
2. **Know what is wrong with it** from OSV.dev, with the fixed version that applies to the installed one.
3. **Know what attackers are doing**: CISA KEV for active exploitation, EPSS for likely exploitation,
   public proof-of-concept links, and the OpenSSF malicious-package feed.
4. **Know what looks wrong even without an advisory**: heuristic IOC scanning and typosquat detection
   for newly installed code.
5. **Know what changed**, scan after scan, and how fast the fleet fixes what it finds.

## Design principles

* **One file to deploy.** The agent is a single Python file with four dependencies, so it runs on a
  server, a laptop, a CI runner or an air-gapped box without packaging work.
* **Precision over volume.** Advisories that alias each other are merged, severity comes from real CVSS
  scores, the fix shown never points to an older version, and every finding carries the path of the
  copy that needs fixing.
* **Never report "clean" by accident.** Failed lookups are never cached as clean, inventory-only runs
  are labelled as unchecked, and partial scans cannot erase what they did not look at.
* **Self-hosted and offline-friendly.** The backend and console run on your own infrastructure; the
  console ships every library locally and enforces a strict Content-Security-Policy.
* **Open formats.** CycloneDX, SPDX, SARIF and OpenVEX in and out, so OpenBOM fits next to the tools
  you already use instead of replacing them.

# About this guide

This guide explains everything you need to install, run and use **OpenBOM**: the endpoint agent, the
backend server and its web console, every menu and feature, day-to-day workflows, the REST API,
configuration, security and troubleshooting.

| Item | Value |
|------|-------|
| Agent version | 5.1.0 (`agent/openbom_agent.py`) |
| Backend version | 2.2.0 (`server/`) |
| Project home | <https://github.com/Masriyan/OpenBOM> |
| Licence | MIT |

> **About the screenshots.** All console screenshots in this guide were taken from a *synthetic demo
> fleet* (hosts such as `web-prod-01`, `db-prod-01`, `ws-analyst-07`, an `nginx:1.25` image, a
> `payments-api` repository and an imported vendor SBOM). Host names, IP addresses and paths are
> examples, not real systems. The CLI screenshots come from a real agent run against a small demo
> repository.

**Conventions.** Commands are shown in `monospace`. Menu names in the console are shown in **bold**
(e.g. **Threat Hunt → CISA KEV**). Paths are relative to the OpenBOM checkout unless stated otherwise.

# 1. Introduction

## 1.1 What OpenBOM is

OpenBOM is an open-source **supply-chain threat-hunting platform for Linux infrastructure**. It
continuously inventories every package on your endpoints (operating-system packages, Python and npm
libraries, containers, container images, source repositories and third-party SBOMs) and correlates
them with vulnerability and threat intelligence to show what actually needs attention:

* vulnerabilities that are **being exploited in the wild** (CISA KEV),
* vulnerabilities that are **likely to be exploited** (FIRST EPSS),
* advisories with **public exploit code** (Exploit-DB, PacketStorm, GitHub PoC references),
* **known-malicious packages** (OpenSSF malicious-packages advisories, `MAL-*`),
* packages whose code **looks like malware** (heuristic IOC scanning) or whose name **imitates a
  popular package** (typosquatting),
* **licence-policy** violations and **end-of-life** software.

Traditional scanners answer "what could be exploited?". OpenBOM is built to answer "what is installed
right now, where exactly, and which of it is under attack?".

## 1.2 Components

OpenBOM has two independent parts that share one JSON contract:

| Component | What it is | Where it runs |
|-----------|-----------|---------------|
| **Endpoint agent** | A single Python file (`agent/openbom_agent.py`) that builds the SBOM, checks it against OSV.dev, enriches it with EPSS, CISA KEV and PoC links, runs heuristic and typosquat checks, and writes JSON / HTML / PDF / CycloneDX / SPDX / SARIF. It can push results to the backend. | Every Linux host, CI runners, analyst workstations |
| **Backend server** | An async FastAPI + SQLAlchemy application that ingests agent results, keeps fleet-wide history, exposes a REST API and serves the **web console**. | One server (SQLite for labs, PostgreSQL for fleets) |
| **Web console** | A React + Arco Design single-page application served by the backend at `/`. Works offline (all libraries are vendored). | Any modern browser |

The agent is fully usable on its own (CLI and reports). The backend adds the fleet view, triage,
history, trends, auditing and server-side re-analysis.

## 1.3 Architecture

```
                         +--------------------------------+
                         |        OpenBOM Backend         |
   analysts (browser) -->|  FastAPI API + web console     |---> api.osv.dev, api.first.org,
                         |  SQLite / PostgreSQL           |     www.cisa.gov (re-analysis)
                         +---------------+----------------+
                                         ^  POST /api/v1/ingest
            +----------------------------+----------------------------+
            |                            |                            |
   +--------+---------+       +----------+---------+       +----------+---------+
   | Agent: web-01    |       | Agent: CI runner   |       | Agent: analyst PC  |
   | dpkg + PyPI +    |       | --path . / --image |       | rpm + PyPI + npm   |
   | npm + Podman     |       | SARIF, CycloneDX   |       | heuristics         |
   +--------+---------+       +----------+---------+       +----------+---------+
            |                            |                            |
       OSV.dev · EPSS · CISA KEV · endoflife.date · deps.dev (optional)
```

The agent pipeline for one run is:

1. **Collect** packages (host sources, or a target: `--path`, `--rootfs`, `--image`, `--sbom`).
2. **Diff** against the previous scan of the same target (`--diff`).
3. **Heuristics**: IOC source scanning of installed PyPI/npm packages and typosquat checks.
4. **Licences**: from package metadata, optionally deps.dev; enforce `--license-deny`.
5. **OSV** batch query → enrichment of each advisory (severity, CVSS, fix, references).
6. **CISA KEV**, **EPSS** and **end-of-life** lookups in parallel.
7. **Suppressions** from VEX documents and the ignore file.
8. **Outputs** (console summary, JSON, reports, SBOM formats), **webhook**, **push** to the backend.

## 1.4 Intelligence signals

| Signal | Source | What it tells you |
|--------|--------|-------------------|
| Vulnerability exists | OSV.dev | The installed version has a known flaw (with the fixed version) |
| Severity | CVSS v3.x base score, else qualitative rating | How bad the flaw is in theory |
| Exploit probability | FIRST.org EPSS | Probability of exploitation in the next 30 days |
| Active exploitation | CISA KEV catalog | It **is** being exploited in the wild |
| Public exploit code | PoC references in advisories | Attackers have ready-made exploit code |
| Known malware | OpenSSF malicious packages (OSV `MAL-*`) | The package is malicious; treat the host as compromised |
| Malware indicators | Heuristic IOC scan | Package code contains malware-like patterns |
| Typosquatting | Edit distance to popular names | The name imitates a popular package |
| Change | Diff scanning | The package was just installed, upgraded or downgraded |
| Licence / EOL | Package metadata, endoflife.date | Compliance and lifecycle risk |

# 2. Installation

## 2.1 Requirements

| Requirement | Details |
|-------------|---------|
| Operating system (agent) | Linux. Tier 1: Fedora 39+, RHEL 8/9, CentOS Stream 8/9, Ubuntu 22.04/24.04, Debian 11/12. Tier 2 (expected to work): AlmaLinux, Rocky, Oracle Linux, openSUSE/SLES, Amazon Linux, Linux Mint, Pop!_OS, Kali, Alpine. Arch Linux (pacman) is not supported. |
| Operating system (backend) | Any OS with Python 3.12+ (Linux recommended; macOS and WSL2 work for development). |
| Python | 3.12 or newer, with `pip`. |
| Package tools | Auto-detected: `rpm`/`dnf`, `dpkg-query`, apk database; `pip`, `npm` (for host sources); `podman` or `docker` for containers and `--image`. |
| Database | SQLite (built in, default) or PostgreSQL 14+ (with `asyncpg`). |
| Outbound HTTPS | `api.osv.dev`, `api.first.org`, `www.cisa.gov`, `endoflife.date` (and `api.deps.dev` if `--deps-dev` is used). `--scan-only` needs no network. |
| Browser | Any current Chromium, Firefox or Safari for the console. |

**What is vulnerability-checked.** PyPI, npm, Go, Cargo, RubyGems, Composer, NuGet and Maven packages
are checked on every distribution. OS packages are checked for **Debian, Ubuntu, AlmaLinux, Rocky
Linux and Alpine**. OSV.dev publishes no advisories for Fedora, RHEL, CentOS Stream, openSUSE and
Amazon Linux, so their OS packages are inventoried (diff, licences, EOL) but not matched.

## 2.2 Get the code and install dependencies

```bash
git clone https://github.com/Masriyan/OpenBOM.git
cd OpenBOM

# Recommended: a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Agent + backend + test dependencies
pip install -r requirements.txt

# Optional extras
pip install weasyprint      # PDF reports from the agent (--report)
pip install asyncpg         # PostgreSQL support for the backend
```

`requirements.txt` installs: `httpx`, `rich`, `jinja2`, `packaging` (agent); `fastapi`, `starlette`,
`uvicorn`, `sqlalchemy`, `aiosqlite`, `pydantic` (backend); `pytest`, `pytest-asyncio`, `pyflakes`
(development).

**Agent-only hosts** do not need the backend dependencies. The agent needs just four packages:

```bash
pip install httpx rich jinja2 packaging
```

## 2.3 Verify the installation

```bash
python3 agent/openbom_agent.py --version     # prints the agent version
python3 -m pytest                            # full test suite (no network needed)
python3 -m pyflakes agent server tests       # lint
```

## 2.4 Start the backend (quick start)

```bash
# Development: SQLite file ./openbom.db, auto-reload on code changes
uvicorn server.main:app --reload --host 127.0.0.1 --port 8000
```

Then open:

* `http://127.0.0.1:8000/`: the web console,
* `http://127.0.0.1:8000/docs`: interactive API documentation (Swagger UI),
* `http://127.0.0.1:8000/health`: health check.

On first start the backend creates its tables. Without `OPENBOM_API_KEY` it logs a warning that the
API is unauthenticated. That is fine on a laptop, never acceptable on a network.

**Protect the API with a key** (recommended even in a lab):

```bash
export OPENBOM_API_KEY=$(openssl rand -hex 24)
uvicorn server.main:app --host 127.0.0.1 --port 8000
```

Enter the same key in the console under **Settings → API key** and pass it to agents with
`--api-key` or the `OPENBOM_API_KEY` environment variable.

## 2.5 Your first scan

```bash
# 1. Interactive menu (on a terminal, no flags)
python3 agent/openbom_agent.py

# 2. Or directly: full threat hunt of this host, pushed to the backend
python3 agent/openbom_agent.py --check-osv --diff \
    --server-url http://127.0.0.1:8000 --api-key "$OPENBOM_API_KEY"
```

Refresh the console: the host appears under **Assets** and its findings on the **Overview**.

> **Tip.** When you try the agent manually on a production machine, set `OPENBOM_STATE_DIR` to a
> scratch directory and use `--output-dir`, so you do not touch the real caches and diff baseline.

## 2.6 Production deployment

### 2.6.1 Database

```bash
sudo -u postgres createuser openbom --pwprompt
sudo -u postgres createdb openbom --owner=openbom
```

Tables are created on first start. Upgrades add new (nullable) columns automatically and log
`Schema upgrade: added column …`. Back up the database before every upgrade.

### 2.6.2 Application

```bash
sudo useradd --system --home /opt/OpenBOM --shell /usr/sbin/nologin openbom
sudo git clone https://github.com/Masriyan/OpenBOM.git /opt/OpenBOM
cd /opt/OpenBOM
sudo python3 -m venv venv
sudo venv/bin/pip install -r requirements.txt asyncpg
sudo install -d -o openbom -g openbom -m 0700 /var/lib/openbom
```

### 2.6.3 Configuration file

```bash
# /etc/openbom/backend.env   (chmod 600, owned by root)
DATABASE_URL=postgresql+asyncpg://openbom:CHANGE_ME@localhost:5432/openbom
OPENBOM_API_KEY=<output of: openssl rand -hex 32>   # comma-separate several keys to rotate
OPENBOM_CORS_ORIGINS=https://openbom.internal
OPENBOM_STALE_DAYS=7
OPENBOM_REANALYZE_HOURS=24                           # continuous monitoring (0 = off)
OPENBOM_STATE_DIR=/var/lib/openbom                   # OSV/KEV cache for server-side analysis
```

### 2.6.4 systemd service

```ini
# /etc/systemd/system/openbom-backend.service
[Unit]
Description=OpenBOM backend
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=exec
User=openbom
Group=openbom
WorkingDirectory=/opt/OpenBOM
EnvironmentFile=/etc/openbom/backend.env
ExecStart=/opt/OpenBOM/venv/bin/uvicorn server.main:app --host 127.0.0.1 --port 8000 --workers 1 --proxy-headers
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/openbom
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now openbom-backend
curl -s http://127.0.0.1:8000/health     # {"status":"ok", ..., "auth_required":true}
```

**Workers and re-analysis.** With `OPENBOM_REANALYZE_HOURS` set, each uvicorn worker runs its own
schedule. Keep `--workers 1` (enough for most fleets), or run several workers with
`OPENBOM_REANALYZE_HOURS=0` and trigger re-analysis from cron:

```bash
0 4 * * * curl -sf -X POST -H "X-API-Key: $KEY" https://openbom.internal/api/v1/reanalyze >/dev/null
```

### 2.6.5 TLS reverse proxy (Nginx)

```nginx
server {
    listen 443 ssl http2;
    server_name openbom.internal;
    ssl_certificate     /etc/pki/tls/certs/openbom.crt;
    ssl_certificate_key /etc/pki/tls/private/openbom.key;
    client_max_body_size 64m;              # large hosts / SBOM uploads

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;            # fleet re-analysis can take minutes
    }
}
```

Serve OpenBOM at the root of a (sub)domain; sub-path deployments are not supported. The backend sets
its own Content-Security-Policy and security headers; do not replace them with a weaker policy.

### 2.6.6 Production security checklist

* `OPENBOM_API_KEY` is set; keys come from a secret manager. Rotate by adding the new key
  (comma-separated), rolling it out to agents, then removing the old one.
* TLS terminates at the proxy; the backend listens on `127.0.0.1` only.
* PostgreSQL is reachable only from the backend host (TLS or a local socket).
* `OPENBOM_CORS_ORIGINS` is restricted to the console origin.
* `/etc/openbom/*.env` files are mode `0600`.
* Agent logs (`/var/log/openbom_agent.log`) are treated as internal data because they contain package paths.
* Outbound HTTPS is allowed to the intelligence sources listed in section 2.1.

## 2.7 Rolling the agent out to a fleet

The agent is one file plus a report template. Copy `agent/openbom_agent.py` and
`agent/templates/report_template.html` to `/opt/OpenBOM/agent/` on each host and install the four
agent dependencies.

### 2.7.1 Environment file

```bash
# /etc/openbom/agent.env   (mode 0600)
OPENBOM_SERVER_URL=https://openbom.internal
OPENBOM_API_KEY=<agent key>
# OPENBOM_WEBHOOK_URL=https://hooks.slack.com/services/...   (optional)
```

### 2.7.2 systemd timer (recommended)

```ini
# /etc/systemd/system/openbom-scan.service
[Unit]
Description=OpenBOM endpoint scan
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/opt/OpenBOM
EnvironmentFile=/etc/openbom/agent.env
ExecStart=/usr/bin/python3 /opt/OpenBOM/agent/openbom_agent.py --check-osv --diff --output-dir /var/lib/openbom/output
SuccessExitStatus=2              # exit code 2 = findings present, not a failure
```

```ini
# /etc/systemd/system/openbom-scan.timer
[Unit]
Description=Run OpenBOM every 6 hours

[Timer]
OnCalendar=*-*-* 00/6:00:00
RandomizedDelaySec=30m           # spread load across the fleet
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl enable --now openbom-scan.timer
```

### 2.7.3 cron (alternative)

```bash
# /etc/cron.d/openbom: daily full hunt pushed to the backend
0 2 * * * root OPENBOM_API_KEY=... /usr/bin/python3 /opt/OpenBOM/agent/openbom_agent.py \
  --check-osv --diff --server-url https://openbom.internal --output-dir /var/lib/openbom/output >/dev/null 2>&1
```

### 2.7.4 Ansible

```yaml
- name: Deploy OpenBOM agent
  hosts: linux
  become: true
  vars:
    openbom_server: https://openbom.internal
    openbom_api_key: "{{ vault_openbom_api_key }}"
  tasks:
    - ansible.builtin.pip: {name: [httpx, rich, jinja2, packaging]}
    - ansible.builtin.file: {path: /opt/OpenBOM/agent/templates, state: directory, mode: "0755"}
    - ansible.builtin.copy: {src: agent/openbom_agent.py, dest: /opt/OpenBOM/agent/openbom_agent.py, mode: "0755"}
    - ansible.builtin.copy: {src: agent/templates/report_template.html, dest: /opt/OpenBOM/agent/templates/, mode: "0644"}
    - ansible.builtin.copy:
        dest: /etc/openbom/agent.env
        mode: "0600"
        content: |
          OPENBOM_SERVER_URL={{ openbom_server }}
          OPENBOM_API_KEY={{ openbom_api_key }}
    - ansible.builtin.copy: {src: "files/{{ item }}", dest: "/etc/systemd/system/{{ item }}"}
      loop: [openbom-scan.service, openbom-scan.timer]
    - ansible.builtin.systemd: {name: openbom-scan.timer, enabled: true, state: started, daemon_reload: true}
```

### 2.7.5 Recommended scan frequency

| Asset type | Recommendation |
|------------|----------------|
| Internet-facing servers | Every 6 h with `--diff` (new packages get heuristic checks quickly) |
| Internal servers | Daily |
| Developer workstations | Daily, `--heuristics new` |
| CI pipelines | Every build (`--path` / `--image`) |
| Images in a registry | On push, plus nightly backend re-analysis |

## 2.8 Upgrading

1. Back up the database (`pg_dump`, or copy the SQLite file while the backend is stopped).
2. `git pull` (or deploy the new release) and `pip install -r requirements.txt`.
3. Restart the backend. New nullable columns and tables are created automatically.
4. Hard-reload the console in the browser.
5. Roll out the new agent file. Some features need a scan from the new agent (for example the
   distribution version in **System & scan details** and partial-scan protection need agent 5.1).

> The console's static files are picked up immediately, but Python code is only reloaded when the
> backend restarts. If new console columns are empty after an upgrade, restart `uvicorn`.

# 3. The endpoint agent

## 3.1 Modes

| Mode | Command | Behaviour |
|------|---------|-----------|
| Interactive menu | `python3 agent/openbom_agent.py` (on a terminal) or `--menu` | Guided menu (see 3.2) |
| Inventory only | `--scan-only` | Builds the SBOM; no network calls (heuristics and typosquat checks still run if enabled) |
| Full threat hunt | `--check-osv` | Inventory + OSV (incl. malicious packages) + EPSS + CISA KEV + end-of-life |
| Push a saved scan | `--push-file scan.json --server-url URL` | Uploads an existing JSON result, then exits |

Without a mode and without a terminal (cron, CI) the agent exits with a usage error, unless a scan
target is given, which implies `--check-osv`.

## 3.2 Interactive menu

Run the agent without flags on a terminal to open the menu:

![Agent interactive menu](img/cli-menu.png){width=70%}

| Key | Action | Notes |
|-----|--------|-------|
| **1** | Quick SBOM inventory (offline) | `--scan-only --heuristics off`: fast, no network, **no vulnerability matching** |
| **2** | Full threat hunt | OSV + EPSS + KEV + diff + heuristics; offers to push to a server |
| **3** | Full threat hunt + reports | Option 2 plus HTML/PDF report and a CycloneDX SBOM |
| **4** | Deep heuristic IOC + typosquat scan | Scans **all** installed Python and npm packages for malware indicators. Inventory-only and limited to PyPI/npm |
| **p** | Scan a project / repository directory | Prompts for a directory (`~` is expanded): lockfiles, manifests, venvs, JARs |
| **i** | Scan a container image | Prompts for an image reference such as `alpine:3.19` |
| **s** | Analyse an existing SBOM file | CycloneDX or SPDX JSON from Syft, Trivy, cdxgen, … |
| **5** | View latest scan result | Re-prints the summary of the newest JSON in the output directory |
| **6** | Push latest scan to an OpenBOM server | Asks for the server URL and API key if not configured |
| **7** | Export latest scan as CycloneDX | Writes `cyclonedx_<timestamp>.json` next to the scan |
| **8** | Show cache / baseline status | OSV/KEV cache age and diff baseline location |
| **9** | Clear caches & diff baseline | Asks for confirmation |
| **0** | Exit | |

> **Important: options 1 and 4 are inventory-only.** They do not query OSV, so "0 vulnerabilities"
> after these options does **not** mean the host is clean. When such a run is pushed, the console
> marks the asset **OSV not checked**. Because agent 5.1 reports which sources a run covered, the
> backend keeps the OS/container packages that option 4 never looked at instead of removing them.
> Use option 2 or 3 for a complete picture.

## 3.3 Scan targets

By default the agent inventories **this host**: OS packages (RPM, dpkg or apk), global pip and npm
packages, and packages inside running Podman and Docker containers. Restrict host sources with
`--ecosystems os,pypi,npm,podman,docker`.

Any of the following targets **replaces** the host scan (and implies `--check-osv`):

```bash
python3 agent/openbom_agent.py --path ./my-repo            # repository / build tree (repeatable)
python3 agent/openbom_agent.py --image nginx:1.25           # container image via podman or docker
python3 agent/openbom_agent.py --rootfs /mnt/vm-disk        # unpacked root filesystem / chroot
python3 agent/openbom_agent.py --sbom syft-output.cdx.json  # CycloneDX or SPDX JSON from another tool
```

### What `--path` understands

| Ecosystem | Files |
|-----------|-------|
| PyPI | `requirements*.txt` (pinned `==` only), `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`, `*.dist-info/METADATA`, `*.egg-info/PKG-INFO` |
| npm | `package-lock.json` (v1 to v3), `npm-shrinkwrap.json`, `yarn.lock` (classic + berry), `pnpm-lock.yaml`, top-level `node_modules/*/package.json` |
| Go | `go.mod` (`require` blocks; `toolchain go1.x` → Go standard library) |
| Cargo | `Cargo.lock` |
| RubyGems | `Gemfile.lock` |
| Packagist | `composer.lock` |
| NuGet | `packages.lock.json` |
| Maven | `pom.xml` (explicit versions), `gradle.lockfile`, `*.jar/*.war/*.ear` (nested fat jars) |

Local path/workspace dependencies are skipped; malformed files are logged at debug level and skipped,
so a broken manifest never aborts a scan. A directory that does not exist is reported as an error.

### Package locations ("found in")

Every package records where it was found, so you know **which copy** to fix:

| Target | Location recorded |
|--------|-------------------|
| Host pip | The `*.dist-info` directory (or site-packages directory) |
| Host global npm | `<npm root -g>/<package>` |
| `--path`, `--rootfs` | Manifest / lockfile / `METADATA` / archive, relative to the target (stored as an absolute path by the backend) |
| `--image` | Path inside the image |
| OS and container packages | None, because they live in the package-manager database |

### OS package coverage

| Distribution | Inventory | OSV matching |
|--------------|-----------|--------------|
| Debian, Ubuntu (hosts, containers, images) | dpkg | Yes, by source package |
| AlmaLinux, Rocky Linux | rpm | Yes, epoch aware |
| Alpine | apk | Yes, by origin package |
| Fedora, RHEL, CentOS Stream, openSUSE, Amazon Linux | rpm | No OSV feed: inventory, diff, licences and EOL only |

## 3.4 Analysis features

| Feature | How it works |
|---------|--------------|
| Vulnerabilities | OSV `querybatch` (1000 per request) + per-advisory enrichment (20 concurrent). Severity from the highest CVSS v3.x base score, else qualitative ratings. The fix shown is the one for the version range that contains the installed version, and never a version older than the installed one. |
| Known-malicious packages | OSV `MAL-*` advisories become CRITICAL, are flagged *malicious* and sort first everywhere, with "treat the host as compromised" guidance. |
| CISA KEV | Catalog cached 24 h; matched through CVE ids from `aliases`, `upstream` (Debian/Ubuntu) and `related` (Alma/Rocky). |
| EPSS | FIRST.org scores for every CVE (100 per request). |
| PoC links | Exploit-DB, PacketStorm and GitHub PoC references found in advisories. |
| De-duplication | GHSA / PYSEC / CVE aliases of the same issue are merged into one finding. |
| Heuristic IOC scan | Strong indicators (e.g. `exec(base64…)`, reverse shells, crypto miners, `curl \| sh` npm install hooks) → CRITICAL. Weak indicators (credential paths, Discord/Telegram exfiltration, paste/tunnel C2, `.pth` auto-exec, …) → HIGH only when two different weak categories occur in one package. See section 6.5. |
| Typosquatting | PyPI/npm names exactly one edit away from a popular package (e.g. `reqeusts`, `colourama`), with an allowlist of legitimate look-alikes. |
| Licences | rpm, apk, Debian copyright, PyPI and npm metadata, lockfiles; `--deps-dev` fills gaps; `--license-deny` enforces policy. |
| End-of-life | OS (and, for host scans, the agent's Python and Node.js) via endoflife.date. |
| Diff | `--diff` labels `[NEW]`, `[UPGRADED]`, `[DOWNGRADED]` (rpm, dpkg, PEP 440 and semver ordering) and lists removed packages; one baseline per target. |
| Suppressions | `--vex` (OpenVEX / CycloneDX VEX) and `--ignore` (with expiry dates). See section 3.7. |

## 3.5 Outputs

| Output | Flag | Notes |
|--------|------|-------|
| Console summary | always | Asset, target, OS, ecosystems, delta, EOL, licence violations, malicious/KEV/IOC panels with "found in" paths, metrics and findings (highest risk first) |
| Native JSON | `-o PATH` (default `output/sbom_<timestamp>.json`) | The backend ingest format |
| HTML / PDF report | `--report` | Dark-theme report in `--output-dir`; PDF requires WeasyPrint |
| CycloneDX 1.5 | `--cyclonedx PATH` | Components with purls + vulnerabilities (ratings, EPSS, KEV) |
| SPDX 2.3 | `--spdx PATH` | Packages with purls and declared licences |
| SARIF 2.1.0 | `--sarif PATH` | One rule per advisory, results located at the lockfile that introduced the package (GitHub/GitLab code scanning) |
| Webhook | `--webhook-url URL` | Slack/Teams/Mattermost (`text`) and Discord (`content`) JSON, sent when malicious, KEV, IOC, critical or EOL findings exist. The URL is never logged. |
| Backend push | `--server-url URL` (+ `--api-key`) | `POST /api/v1/ingest` with retries |

### Example: scanning a repository

The screenshot below is a real run against a small demo repository containing a Python
`requirements.txt`, an npm `package-lock.json` and a Maven `pom.xml`:

```bash
python3 agent/openbom_agent.py --path ./demo-repo --cyclonedx demo.cdx.json \
    --license-deny AGPL --fail-on critical
```

![Agent run: log, scan summary and the CISA KEV panel](img/cli-scan-1.png)

![Agent run: vulnerable packages table and the high-EPSS panel](img/cli-scan-2.png)

The summary lists the target, ecosystems, the CISA KEV panel (with the file that introduced the
package), severity metrics and every finding with the installed version, the fixed version and the
location. Exit code `2` tells CI that findings at or above `--fail-on` (or KEV / malicious / licence
violations) exist.

## 3.6 Exit codes

| Code | Meaning |
|------|---------|
| `0` | Completed, nothing at/above the `--fail-on` threshold |
| `1` | No packages found, target collection failed (e.g. missing directory), unreadable VEX/ignore file, or `--push-file` failed |
| `2` | Findings at/above `--fail-on`, **or** any CISA KEV match, known-malicious package or licence-policy violation (unless `--fail-on never`) |
| `130` | Interrupted (Ctrl+C) |

## 3.7 Suppressing accepted findings

There are three mechanisms. All keep the evidence; nothing is silently dropped.

**VEX documents** (`--vex FILE`, repeatable). OpenVEX statements with status `not_affected` or `fixed`,
and CycloneDX VEX analyses `not_affected` / `false_positive` / `resolved`, suppress matching findings.
The OpenVEX document exported by the backend (**Reports & Export → OpenVEX**) can be fed straight back
into CI.

**Ignore file** (`--ignore FILE`). One entry per line:
`VULN-ID [package-name|purl] [until=YYYY-MM-DD] [# reason]`

```text
GHSA-x84v-xcm2-53pg requests until=2026-12-31      # accepted risk, SEC-421
TYPOSQUAT_SUSPECT reqeusts                          # internal fork, reviewed 2026-09
CVE-2023-44487                                      # all packages: mitigated at the load balancer
MALICIOUS_HEURISTIC pkg:pypi/vendored-tool          # false positive, see review notes
```

Expired entries are not applied: the agent warns and reports the finding again.

**Backend triage**: decisions recorded in the console (section 4.13).

## 3.8 Command-line reference

![Agent --help](img/cli-help.png){width=72%}

| Group | Flag | Description |
|-------|------|-------------|
| Mode | `--scan-only` | Inventory only, no network |
| | `--check-osv` | Full analysis (OSV + MAL + EPSS + KEV + EOL) |
| | `--push-file JSON` | Upload an existing scan JSON to `--server-url` |
| | `--menu` | Interactive menu |
| Targets | `--path DIR` | Repository / build tree (repeatable; `~` expanded) |
| | `--rootfs DIR` | Unpacked root filesystem |
| | `--image REF` | Container image via podman or docker |
| | `--sbom FILE` | CycloneDX / SPDX JSON SBOM |
| | `--ecosystems LIST` | Host sources: `os,pypi,npm,podman,docker` (default all) |
| Outputs | `-o, --output PATH` | JSON path (default `<output-dir>/sbom_<ts>.json`) |
| | `--output-dir DIR` | Default `./output` (relative to the current directory) |
| | `--report` | HTML (+ PDF with WeasyPrint) |
| | `--cyclonedx PATH` / `--spdx PATH` / `--sarif PATH` | SBOM / code-scanning formats |
| Analysis | `--diff` | Delta against the previous scan of the same target |
| | `--heuristics new\|all\|off` | `new` (default) scans only changed packages and needs `--diff` |
| | `--vex FILE` / `--ignore FILE` | Suppressions |
| | `--license-deny LIST` | e.g. `GPL-3.0,AGPL,SSPL` (fails the run) |
| | `--deps-dev` | Fill missing licences from deps.dev |
| | `--no-eol` / `--no-cache` | Skip EOL checks / bypass the 12 h OSV cache |
| | `--fail-on LEVEL` | `any` (default), `critical`, `high`, `medium`, `low`, `never` |
| Other | `--hostname NAME` | Asset name override (`/` is replaced by `_`) |
| | `--server-url URL` / `--api-key KEY` | Push to the backend |
| | `--webhook-url URL` | Chat alerting |
| | `-v, --verbose` / `--version` | Debug output / print version |

### Environment variables and files (agent)

| Variable | Purpose |
|----------|---------|
| `OPENBOM_SERVER_URL`, `OPENBOM_API_KEY`, `OPENBOM_WEBHOOK_URL` | Defaults for `--server-url`, `--api-key`, `--webhook-url` |
| `OPENBOM_STATE_DIR` | Directory for caches and diff baselines |
| `XDG_CACHE_HOME` | Base of the default non-root state dir |

| File | Content |
|------|---------|
| `<state>/osv_cache.json` | OSV answers, 12 h TTL (failed lookups are never cached as clean) |
| `<state>/kev_cache.json`, `eol_cache.json` | CISA KEV and endoflife.date, 24 h TTL |
| `<state>/last_state*.json` | Diff baselines (one per target) |
| `/var/log/openbom_agent.log` (else `./logs/`) | Debug log |

`<state>` defaults to `/var/lib/openbom` (root) or `~/.cache/openbom`; it is created `0700`, files are
written atomically with mode `0600`, and symlinked or foreign-owned state files are refused.

# 4. The web console

The console is served by the backend at `http://<server>:8000/`. Every view has its own URL (for
example `#/asset/web-prod-01?tab=packages`), so you can bookmark and share views.

## 4.1 First login and layout

1. Open the console. If the server has `OPENBOM_API_KEY` set, pages show **API key required**.
2. Open **Settings → API key**, paste the key and click **Save & test**. The key is stored only in
   this browser and sent as `X-API-Key`.
3. The status dot in the header is **green** when authentication is on, **orange** when the API is
   unauthenticated and **red** when the backend is unreachable.

The **sidebar** groups the menus:

| Group | Menus |
|-------|-------|
| Monitor | Overview, Assets, Trends |
| Hunt | Threat Hunt (Malicious packages, CISA KEV, IOC & typosquat, Critical, High EPSS), Vulnerabilities, Package Search |
| Govern | Licenses, End-of-Life, Triage & VEX, Audit Log |
| Data | SBOM Import, Reports & Export, Agent Setup, Settings |

The **header** has a collapse button for the sidebar, the breadcrumb, a **global search** box, the
status dot, the dark/light theme switch and a link to the API docs. In the global search, an advisory
id (`CVE-`, `GHSA-`, `MAL-`, `PYSEC-`, `GO-`, `RUSTSEC-`, `DEBIAN-`, `UBUNTU-`, `ALSA-`, `RLSA-`,
`ALPINE-`) opens the vulnerability list filtered to it; anything else searches packages across the
fleet.

## 4.2 Overview

![Overview (dark theme)](img/01-overview.png)

The fleet dashboard. It answers "how exposed are we right now?".

* **Hero banners** appear when known-malicious packages (red) or CISA KEV vulnerabilities (orange) are
  installed anywhere, with a button to investigate.
* **KPI cards**: Assets, Packages, Vulnerabilities, Critical, CISA KEV, Malicious, IOC / Typosquat,
  End-of-life, License violations and Stale assets. Every card is clickable and opens the matching view.
* **Severity distribution**: a stacked bar plus one tile per severity (click to filter the vulnerability list).
* **Coverage**: scan targets by type (host, image, repo, rootfs, SBOM), suppressing triage decisions
  and the stale threshold.
* **Highest-risk assets**: top assets by risk score with KEV, malware and critical counts.
* **Packages by ecosystem** and **Recent scans** (source, packages, critical, high, KEV).

![Overview, full page](img/02-overview-full.png){width=80%}

## 4.3 Assets

![Assets list](img/03-assets.png)

Every host, container image, repository, root filesystem and imported SBOM.

* **Filter** by name and **type**; **sort** by risk, name, last seen or package count.
* Columns: asset (type tag, **STALE** and **EOL** tags, OS or target path), **OS · version**, **risk
  score** (with an **OSV not checked** tag when the last scan did not match packages), packages,
  critical, high, KEV, malware, IOC, licence violations, last seen and agent version.
* Click a row to open the asset page.

## 4.4 Asset detail

![Asset detail with System & scan details](img/04-asset-detail.png)

The asset page shows everything OpenBOM knows about one target.

**Header actions**

| Action | What it does |
|--------|-------------|
| **Re-analyze** | Re-matches the stored inventory against fresh OSV/EPSS/KEV data on the server and picks up advisories published since the last scan |
| **CycloneDX** | Downloads a CycloneDX 1.5 SBOM (with vulnerabilities) of the current inventory |
| **Decommission** | Deletes the asset, its package links, scan history and finding history (asks for confirmation; shared packages stay for other assets) |

**KPI cards**: risk score, packages, vulnerabilities, critical, KEV, malware, IOC and licence violations.

**Severity distribution** with **packages by ecosystem**.

**System & scan details**: the identity and coverage of the asset:

| Field | Meaning |
|-------|---------|
| Target | Type (HOST, IMAGE, REPO, ROOTFS, SBOM) and reference |
| Operating system | Pretty name from `/etc/os-release` |
| Distribution · version | Distribution id and version (e.g. `debian 12`, `fedora 44`) |
| OS vulnerability feed | The OSV ecosystem used for OS packages (e.g. `OSV · Debian:12`), or *none (OS packages inventory-only)* for distributions OSV does not cover |
| IP address, Agent version, First seen | As reported by the last push |
| Last scan | Time, whether it was **OSV checked**, the heuristics mode and the source (agent, sbom-upload, reanalysis) |
| Sources scanned | Host sources covered by the last scan; skipped sources are struck through |
| Scans recorded | Number of scans (opens the Scan history tab) |

**Coverage warning.** When the last scan was inventory-only, an orange banner says
**Vulnerabilities were not checked in the last scan** and offers **Re-analyze now**:

![Asset whose last scan was not OSV-checked](img/07-asset-not-checked.png)

**Tabs**

* **Vulnerabilities**: severity filter, "show suppressed" switch, and per finding: id, severity,
  CVSS, EPSS, intel tags (MALWARE, KEV, IOC/TYPOSQUAT, PoC count, triage state), **package → fixed
  version · path** and summary, with a **Triage** button.
* **Packages**: search and ecosystem filter; licence, **found in** path and purl of every package.

![Packages tab of a repository asset](img/05-asset-packages.png)

* **Licenses**: licence-policy violations reported by the agent (`--license-deny`).
* **End-of-life**: OS/runtime cycles with their end-of-life date and status.
* **Scan history**: a bar chart of critical + high findings per scan and a table of every scan:
  received time, source, packages, vulnerable packages, severity counts, KEV, malware, IOC, diff
  (+new / −removed), **OSV checked** and the **sources** the scan covered.

![Scan history tab](img/06-asset-scans.png)

**Risk score.** A saturating score from 0 to 100. Each distinct (non-suppressed) vulnerability adds its
severity weight (CRITICAL 10, HIGH 6, MEDIUM 3, LOW/UNKNOWN 1), +15 if KEV, +20 if heuristic, +30 if
known-malicious and +10 × EPSS; the sum Σ is mapped through `100 · (1 − e^(−Σ/200))`. A handful of KEV
or malware findings therefore outweighs hundreds of LOW findings.

## 4.5 Trends

![Trends & analytics](img/08-trends.png){width=75%}

Answers "is our exposure going up or down?".

* **Window**: 30, 90, 180 or 365 days (UTC, ending today).
* **KPIs**: open findings (with the change since the start of the window), new and fixed findings in
  the window, **median time to fix** (all findings and CISA KEV) and the median age of findings still open.
* **Open findings** per day, **Critical, malware & KEV** per day (each line is labelled at its end;
  hover any chart for the values of that day) and **New vs fixed** per day (new above the baseline,
  fixed below).
* **Top movers**: assets whose open findings changed most (click to open).
* **Scans by source**: agent pushes, SBOM uploads and server re-analysis.
* **Daily data**: the numbers behind every chart, with **CSV** export.

Trends are computed from *finding history*: every ingest opens an episode when a vulnerability appears
on an asset and closes it when it disappears. Triage suppression is applied when the page is computed,
so a `not_affected` decision also removes the finding from past points. History starts with the first
ingest after upgrading to backend 2.2; a blue banner says when recording started, and the charts start there.

## 4.6 Threat Hunt

Five focused views, each listing affected assets and their findings with the package, the fixed version
and **where the package was found**. Each asset card shows when it was last scanned; hover it to see
the exact agent command that rescans that target.

| Tab | Shows |
|-----|-------|
| **Malicious packages** | Packages matching OpenSSF malicious-package advisories (OSV `MAL-*`). Treat the host as compromised. |
| **CISA KEV** | Vulnerabilities in CISA's Known Exploited Vulnerabilities catalog |
| **IOC & typosquat** | Agent heuristic detections: malware indicators and look-alike names |
| **Critical** | All CRITICAL findings |
| **High EPSS** | Findings above an EPSS probability threshold (slider) |

![Threat Hunt: Malicious packages](img/09-threat-malicious.png)

![Threat Hunt: CISA KEV](img/10-threat-kev.png)

![Threat Hunt: IOC & typosquat](img/11-threat-ioc.png)

![Threat Hunt: High EPSS](img/12-threat-epss.png)

## 4.7 Vulnerabilities

![Vulnerabilities](img/13-vulns.png)

Every advisory present on at least one asset, highest risk first (malicious → heuristic → KEV →
severity → EPSS).

* Filter by text (id, CVE, summary), severity and intel (malicious, KEV, IOC, EPSS ≥ 10 %), and
  optionally show suppressed findings.
* The **Affected package · asset · path** column lists the first five exposures (package, installed →
  fixed version, asset, path).
* **Export CSV** respects the filters and includes a `found_in` column.

Clicking a row opens the **vulnerability drawer**: summary, CVE links (NVD), CVSS, EPSS with
percentile, KEV description, PoC/exploit links, triage state, first-seen date, and **every affected
asset** with installed version, fix and full path. **OSV.dev** opens the advisory; **Triage** records a decision.

![Vulnerability drawer](img/14-vuln-drawer.png)

## 4.8 Package Search

![Package Search](img/16-packages.png)

"Which assets have X installed right now, and where?" Search by name (contains or exact), optional
version and ecosystem. Results show licence, vulnerability count and maximum severity, and every asset
with the path where it holds the package. Use it during incident response (e.g. "who has
`xz-utils 5.6.0`?").

## 4.9 Licenses

![Licenses](img/17-licenses.png)

Licence inventory of installed packages grouped into **permissive**, **weak copyleft**, **strong
copyleft**, **unknown** and **other**. Click a category card to filter, click a licence to see its
packages and the assets that use them. Enforce policy in the agent with `--license-deny`; violations
appear on the asset page and count on the Overview.

## 4.10 End-of-Life

![End-of-Life](img/18-eol.png)

Assets running operating systems or runtimes that are past (or within 180 days of) end of life, as
reported by agents during `--check-osv` scans (data from endoflife.date).

## 4.11 Triage & VEX

![Triage & VEX](img/19-triage.png)

All analyst decisions with scope (fleet or one asset), state, justification, notes, author and time.
**Import OpenVEX** applies statements fleet-wide; **Export OpenVEX** downloads every decision with the
affected package purls. Decisions can be deleted.

| State | Effect | OpenVEX export status |
|-------|--------|-----------------------|
| `in_triage` | Informational tag | `under_investigation` |
| `exploitable` | Informational tag | `affected` |
| `not_affected` | **Hides the finding** (views, counts, risk) | `not_affected` + justification |
| `false_positive` | **Hides the finding** | `not_affected` |
| `resolved` | Informational (see note below) | `fixed` |

### Recording a decision

1. Click **Triage** in a vulnerability table or in the vulnerability drawer.
2. Choose a **state**. For `not_affected`, choose an OpenVEX **justification**
   (`component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`,
   `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`).
3. Choose the **scope**: whole fleet, or only this asset (available from an asset page). An
   asset-specific decision overrides the fleet-wide one for that asset.
4. Add **analyst notes** and click **Save decision**.

![Triage dialog](img/15-triage-modal.png){width=80%}

> **`resolved` does not hide a finding.** If the latest scan still contains the vulnerable version,
> the tag reads **resolved · still detected**. Upgrade the copy at the path shown, then re-run the
> agent on the same target; the finding disappears because ingest is snapshot-based.

## 4.12 Audit Log

![Audit Log](img/20-audit.png)

An append-only timeline of every change: **ingest** (source IP, agent version, packages, findings
opened/resolved, packages kept from a partial scan), **triage.set / triage.delete**, **vex.import /
vex.export**, **reanalyze** (manual or scheduled), **asset.decommission** and **maintenance.prune**.

* Filter by action, actor or target; **CSV** exports the filtered events.
* Targets link to the asset or vulnerability when it still exists.
* **Actors** are API-key fingerprints (`key:` + the first 8 hex characters of the key's SHA-256),
  never the key itself. `anonymous` means the API is unauthenticated; `system` is the scheduled re-analysis.
* There is no way to edit or delete events through the API.

## 4.13 SBOM Import

![SBOM Import](img/21-sbom-import.png)

Bring in SBOMs produced by any tool (Syft, Trivy, cdxgen, Microsoft sbom-tool, …):

1. Drag a **CycloneDX** or **SPDX** JSON file onto the upload area.
2. Confirm the **asset name** (defaults to the SBOM's metadata name).
3. Choose whether the server should **analyse** it (OSV/EPSS/KEV) or store the inventory only.

The SBOM becomes an asset of type **SBOM**. Components need a purl to be matched.
**Re-analyse entire fleet now** re-matches every stored inventory; automate it with
`OPENBOM_REANALYZE_HOURS`.

## 4.14 Reports & Export

![Reports & Export](img/22-reports.png)

| Export | Content |
|--------|---------|
| Asset SBOM (CycloneDX 1.5) | Components + vulnerabilities for one asset |
| OpenVEX statements | Every triage decision as an OpenVEX 0.2.0 document |
| Fleet inventory (CSV) | Risk, counts, EOL and licence status for every asset |
| Vulnerabilities (CSV) | Use **Export CSV** on the Vulnerabilities page (respects filters) |
| Threat summary (JSON) | Raw fleet statistics for SIEM / ticketing pipelines |

Agents additionally write SPDX 2.3, SARIF and HTML/PDF reports locally.

## 4.15 Agent Setup

![Agent Setup](img/23-agent-setup.png)

Copy-ready commands, pre-filled with this server's URL: installation, interactive menu, hunting this
host and pushing, scanning an image, a repository (CI) and a third-party SBOM, suppressions, and a
cron schedule, plus a coverage summary (OS packages, OSV distributions, languages, intelligence
sources, detection, input and output formats).

## 4.16 Settings

![Settings](img/24-settings.png)

* **API key**: stored only in this browser; **Save & test** verifies it against the server.
* **Server**: status, version and a link to the API documentation (`/docs`).
* **Prune orphaned records**: deletes packages no asset has installed and vulnerabilities no package
  references (useful after decommissioning many assets). Finding history is kept for Trends.

## 4.17 Themes and small screens

The sun/moon button switches between dark and light themes (remembered per browser). The layout adapts
to tablets and phones: the sidebar collapses to icons, cards stack, and wide tables scroll
horizontally. All motion is disabled when the operating system requests reduced motion.

![Overview in the light theme](img/25-overview-light.png)

![Asset page on a phone (390 px)](img/26-mobile.png){width=35%}

# 5. Common workflows

## 5.1 Onboard a server

1. Install the agent dependencies and copy the agent (section 2.7).
2. Run a full hunt and push: `python3 agent/openbom_agent.py --check-osv --diff --server-url URL --api-key KEY`.
3. Open **Assets → <host>**. Check **System & scan details**: OS, version, OSV feed, sources scanned.
4. Install the systemd timer so the host is rescanned automatically.

## 5.2 Respond to a CISA KEV finding

1. **Overview** shows the orange KEV banner → **View**, or open **Threat Hunt → CISA KEV**.
2. Open the finding: the drawer lists every affected asset, the fixed version and the exact path.
3. Record **Triage → exploitable** (fleet-wide) with a note such as the change ticket.
4. Patch the package at the path shown on each asset.
5. Re-run the agent **on the same target** (`--path`, `--image` … as before). The finding disappears
   from the asset; Trends records it as fixed and updates the KEV time-to-fix.

## 5.3 Handle a known-malicious package

1. The red banner on the Overview → **Investigate** (or **Threat Hunt → Malicious packages**).
2. Treat every affected host as compromised: isolate, remove the package (path shown), rotate
   credentials that were present on the host, and investigate according to your incident process.
3. Use **Package Search** to check whether any other asset has the package.
4. Rescan the hosts after clean-up.

## 5.4 Accept a finding that does not apply

1. Open the finding → **Triage** → `not_affected` with a justification, or `false_positive`.
2. Choose fleet-wide or asset scope and save. The finding disappears from counts and risk scores
   (use "show suppressed" to review it).
3. Export the OpenVEX document (**Reports & Export**) and commit it to your repositories; pass it to
   CI with `--vex openvex.json` so pipelines stop failing on it.

## 5.5 Gate a CI pipeline

```yaml
# GitHub Actions: scan the checkout, upload SARIF, fail on critical findings
- name: OpenBOM scan
  run: |
    git clone --depth 1 https://github.com/Masriyan/OpenBOM.git /tmp/openbom
    pip install httpx rich jinja2 packaging
    python3 /tmp/openbom/agent/openbom_agent.py --path . --no-eol \
      --sarif openbom.sarif --cyclonedx sbom.cdx.json \
      --license-deny AGPL,SSPL --fail-on critical --output-dir openbom-out
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: {sarif_file: openbom.sarif, category: openbom}
```

| Need | Flags |
|------|-------|
| Scan the checkout / built image | `--path .` / `--image "$IMAGE"` |
| Code-scanning annotations | `--sarif openbom.sarif` |
| SBOM artefacts | `--cyclonedx sbom.cdx.json --spdx sbom.spdx.json` |
| Gate on severity | `--fail-on critical` (KEV, malicious and licence violations always fail) |
| Accepted risks | `--vex .openbom/openvex.json --ignore .openbomignore` |
| Report to the fleet console | `--server-url "$OPENBOM_URL" --api-key "$OPENBOM_API_KEY"` |
| Faster repeat runs | Cache `$OPENBOM_STATE_DIR` between jobs |

In GitLab CI or Jenkins, run the same command in a `python:3.12` job; exit code `2` fails the job and
`1` means the scan itself could not run.

## 5.6 Import a third-party SBOM

```bash
syft nginx:1.25 -o cyclonedx-json > nginx.cdx.json
# Option A: analyse locally with the agent
python3 agent/openbom_agent.py --sbom nginx.cdx.json --spdx nginx.spdx.json
# Option B: upload to the backend (server-side analysis)
curl -X POST "http://openbom:8000/api/v1/sbom?hostname=nginx-1.25" \
     -H "X-API-Key: $KEY" -H "Content-Type: application/json" -d @nginx.cdx.json
```

Or drag the file onto **SBOM Import** in the console.

## 5.7 Continuous monitoring between scans

New advisories are published every day. Set `OPENBOM_REANALYZE_HOURS=24` (or call
`POST /api/v1/reanalyze` from cron) so the server re-matches every stored inventory against fresh
OSV, EPSS and KEV data even when no agent runs. Re-analysis appears as source *reanalysis* in the scan
history and Trends, and as a `reanalyze` event in the Audit Log.

## 5.8 Review exposure trends for management

Open **Trends**, choose the 90-day window and export **Daily data** as CSV. The KPIs give open
findings and their change, new versus fixed, median time to fix (overall and KEV) and the age of open
findings; **Top movers** shows which assets drove the change.

# 6. Concepts

## 6.1 Assets and targets

An *asset* is whatever one scan describes: a host (`HOST`), a container image (`IMAGE`, named
`image:<ref>`), a repository (`REPO`, `path:<dir>`), a root filesystem (`ROOTFS`) or an imported SBOM
(`SBOM`). Re-scanning the same target updates the same asset.

## 6.2 Snapshot ingestion and partial scans

Each ingest replaces the asset's package list with the scan's list, so uninstalled or upgraded
packages stop counting immediately, so findings always reflect what is installed **now**.

A **host** scan that covered only some sources (for example menu option 4, or `--ecosystems pypi,npm`)
is *partial*: agent 5.1 reports the sources it covered, and the backend keeps the asset's packages from
the sources that were not scanned. Repository, image, rootfs and SBOM scans always describe the whole
target. Scans from older agents (which do not report coverage) are treated as full snapshots.

## 6.3 Vulnerabilities belong to package versions

A vulnerability is linked to a package **version**, not to a host. When two assets have the same
version installed, both show the finding, and fixing it on one asset does not change the other.

## 6.4 Finding history and MTTR

The backend records an *episode* for every vulnerability on every asset: when it first appeared and
when it disappeared. A finding that comes back after being fixed opens a new episode. Trends, the
new/fixed counts and the median time to fix (MTTR) are computed from these episodes. Episodes survive
pruning and are removed together with a decommissioned asset.

## 6.5 Heuristic detection and typosquatting

Heuristics are **investigation leads, not verdicts**.

| Finding | Severity | Trigger |
|---------|----------|---------|
| `MAL-*` (from OSV) | CRITICAL | OpenSSF malicious-packages advisory for the installed version |
| `MALICIOUS_HEURISTIC` | CRITICAL (strong indicator) or HIGH (≥ 2 weak categories) | Source scan of installed PyPI/npm packages |
| `TYPOSQUAT_SUSPECT` | MEDIUM | Name one edit away from a popular package |

**Strong indicators** (CRITICAL on their own): `eval(base64…)`, `exec(base64…)` / `exec(zlib…)` /
`exec(marshal…)`, `os.system("curl …")`, reverse shells (`/dev/tcp/…`, `pty.spawn("/bin/sh")`),
crypto miners (`stratum+tcp://`, `xmrig`), npm install hooks piping `curl`/`wget` into a shell.

**Weak indicators** (reported only when two different categories co-occur): `subprocess`/
`child_process` downloads, paste/tunnel C2 domains, Discord/Telegram exfiltration webhooks, credential
paths (`.ssh/id_rsa`, `.aws/credentials`, browser login data), suspicious imports, `.pth` auto-exec,
other install-hook commands. Weak hits in test directories are ignored.

When they run: `--heuristics new` (default) scans only packages labelled `[NEW]`, `[UPGRADED]` or
`[DOWNGRADED]` by `--diff`; `all` scans every installed PyPI/npm package; `off` disables them. The IOC
source scan needs files on disk, so it applies to installed host packages; for targets only the
typosquat check runs. Files are read as text and never executed.

## 6.6 Package URLs (purl)

Every exported component carries a purl, and imports rely on purls to know what to query:
`pkg:pypi/requests@2.31.0`, `pkg:npm/%40babel/core@7.24.0`, `pkg:golang/golang.org/x/net@v0.17.0`,
`pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1`,
`pkg:deb/debian/libssl3@3.0.11-1~deb12u2?distro=debian-12&upstream=openssl`,
`pkg:rpm/almalinux/openssl@3.0.7-27.el9?distro=almalinux-9&epoch=1`,
`pkg:apk/alpine/libcrypto3@3.1.4-r5?distro=alpine-3.19&upstream=openssl`.

## 6.7 Stale assets

An asset is **stale** when it has not been scanned for `OPENBOM_STALE_DAYS` (default 7). Stale assets
are tagged in the asset list and counted on the Overview, because their data may be outdated.

# 7. REST API

All `/api/v1` routes require an API key when `OPENBOM_API_KEY` is set, sent as `X-API-Key: <key>` or
`Authorization: Bearer <key>`. `/health` and the console stay public. Interactive documentation is at
`/docs` (Swagger UI) and the schema at `/openapi.json`. Timestamps are returned in UTC.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health, version and whether authentication is required |
| POST | `/api/v1/ingest` | Receive an agent scan payload |
| GET | `/api/v1/threats/summary` | Fleet KPIs, breakdowns, top risky assets, recent scans |
| GET | `/api/v1/threats/{malicious,kev,heuristics,critical}` | Assets with the matching findings |
| GET | `/api/v1/threats/high-epss?min_score=0.1` | Assets above an EPSS threshold |
| GET | `/api/v1/assets?q=&sort=risk\|hostname\|last_seen\|packages` | Assets with counts, risk score, stale flag, OS fields, `osv_checked` |
| GET | `/api/v1/assets/{hostname}` | Asset detail incl. ecosystem counts, last scan, scan count |
| GET | `/api/v1/assets/{hostname}/packages` | Installed packages with location |
| GET | `/api/v1/assets/{hostname}/vulnerabilities` | Findings with per-package fix (`include_suppressed=true` to show triaged) |
| GET | `/api/v1/assets/{hostname}/scans` | Scan history (incl. `osv_checked` and `scope`) |
| GET | `/api/v1/assets/{hostname}/sbom` | CycloneDX 1.5 export |
| DELETE | `/api/v1/assets/{hostname}` | Decommission an asset |
| POST | `/api/v1/assets/{hostname}/reanalyze` · `/api/v1/reanalyze` | Server-side re-matching of one / all assets |
| GET | `/api/v1/packages/search?name=&version=&ecosystem=&exact=` | Which assets have a package, and where |
| GET | `/api/v1/vulnerabilities` · `/api/v1/vulnerabilities/{id}` | Fleet vulnerability list / detail with affected assets |
| GET, PUT, DELETE | `/api/v1/triage` · `/api/v1/triage/{id}` | Analyst decisions |
| GET, POST | `/api/v1/vex` | Export / import OpenVEX |
| GET | `/api/v1/licenses` · `/api/v1/licenses/packages?license=` | Licence inventory |
| GET | `/api/v1/eol` | Assets with end-of-life data |
| POST | `/api/v1/sbom?hostname=&analyze=true` | Import a CycloneDX/SPDX SBOM |
| GET | `/api/v1/trends/fleet?days=90` | Daily exposure series, MTTR, sources, top movers |
| GET | `/api/v1/audit?action=&actor=&target=&since=&until=` · `/api/v1/audit/facets` | Audit trail and filter values |
| POST | `/api/v1/maintenance/prune` | Delete orphaned packages and vulnerabilities |

Errors use `{"detail": "..."}` with status `401` (missing/invalid key), `404` (not found), `409`
(concurrent ingest conflict, retry), `413` (payload above `OPENBOM_MAX_PACKAGES`) or `422` (validation).

**Example: list assets with a KEV finding**

```bash
curl -s -H "X-API-Key: $KEY" https://openbom.internal/api/v1/threats/kev | python3 -m json.tool
```

# 8. Configuration reference

## 8.1 Backend environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `DATABASE_URL` | `sqlite+aiosqlite:///openbom.db` | Database; `postgresql://` is rewritten to `postgresql+asyncpg://` |
| `OPENBOM_API_KEY` | unset (auth off, warning) | Comma-separated keys required on every `/api/v1` route |
| `OPENBOM_CORS_ORIGINS` | `*` | Allowed browser origins |
| `OPENBOM_STALE_DAYS` | `7` | Days without a scan before an asset is stale |
| `OPENBOM_MAX_PACKAGES` | `200000` | Maximum packages per ingest (HTTP 413 above) |
| `OPENBOM_REANALYZE_HOURS` | `0` (off) | Re-match all inventories every N hours |
| `OPENBOM_STATE_DIR` | as agent | OSV/KEV cache used by server-side analysis |

## 8.2 Built-in limits

| Limit | Value |
|-------|-------|
| OSV batch size / enrichment concurrency | 1000 queries / 20 requests |
| EPSS batch size | 100 CVEs |
| HTTP retries | 3, exponential backoff, honours `Retry-After` |
| Heuristic scan | 800 files per package, 512 KiB per file |
| Path scan | 400 000 files per walk; archives up to 200 MiB (nested jars 50 MiB) |
| Skipped directories | `.git`, `.hg`, `.svn`, `__pycache__`, `.tox`, `.nox`, tool caches, `.idea`, `.vscode` |

# 9. Security notes

* Agent-supplied data (package names, summaries, paths) is untrusted and rendered only as text.
* The console runs under a strict Content-Security-Policy (`script-src 'self'`, no inline scripts, no
  eval, no third-party origins) and refuses to be framed.
* API keys are compared in constant time; the audit log stores only a key fingerprint.
* Agent state files are private (`0700` directory, `0600` files, atomic writes, symlinks refused);
  failed OSV lookups are never cached as "clean".
* Webhook URLs (which embed secrets) are never written to logs.
* Package paths in scans and logs reveal directory layouts; treat them as internal data.

# 10. Troubleshooting

## 10.1 Agent

| Symptom | Cause / fix |
|---------|-------------|
| `one of --scan-only, --check-osv, --push-file or --menu is required` | No mode and no terminal (cron/CI). Add `--check-osv` / `--scan-only`, or pass a target |
| Exit code 1, "No packages found" | The target has no recognised packages. `--path` reads only **pinned** requirements (`==`). For host scans check `--ecosystems` |
| `--path …: no such directory` | The directory does not exist (check typing; `~` is expanded) |
| Host shows only PyPI/npm packages | The run used menu option 4 or `--ecosystems pypi,npm`. Run option 2/3 or `--check-osv` without `--ecosystems` |
| OS packages but no OS findings on Fedora/RHEL | Expected: OSV has no feed for these distributions; PyPI/npm are still checked |
| "OSV batch query failed …" | Network or OSV outage; those packages are reported unchecked (never cached as clean). Re-run later |
| Heuristic scan never runs | `--heuristics new` needs `--diff`. Use `--heuristics all` for a full sweep |
| Every package is `[NEW]` | First `--diff` run for this target, or a different state directory (root vs. user) |
| "Ignoring untrusted state file" | A cache/baseline file is a symlink or owned by another user; delete it |
| `--image` fails | Install podman or docker, check the image reference and registry login |
| PDF report missing | `pip install weasyprint` (needs Pango); the HTML report is still written |
| Push fails with 401 / 413 / 422 | Wrong API key / payload above the server limit / hand-edited JSON |

Reset the agent state with menu option **9**, or `rm -f ~/.cache/openbom/*.json`
(`/var/lib/openbom/*.json` as root).

## 10.2 Backend and console

| Symptom | Cause / fix |
|---------|-------------|
| "API key required" on every page | Enter the key in **Settings** (stored per browser) |
| New console fields are empty after upgrading | The backend still runs old code; restart `uvicorn` |
| Asset tagged **OSV not checked** | The last scan was inventory-only; click **Re-analyze** or rescan with `--check-osv` |
| "I fixed it but it still shows" | Check which asset reports it and the **found in** path; another copy may still pin the old version. Rescan **the same target** |
| Finding tagged **resolved · still detected** | `resolved` is a note, not a suppression; rescan after fixing, or use `not_affected` / `false_positive` |
| Trends empty or starting recently | History is recorded from the first ingest on backend 2.2; push a scan or run Re-analyze |
| `database is locked` (SQLite) | Many agents pushing at once; use PostgreSQL for fleets |
| HTTP 409 "Concurrent ingest conflict" | Retry the push |
| Re-analysis checks 0 packages | Stored packages have no OSV ecosystem (e.g. Fedora RPMs) |
| Blank page | Check the browser console; a reverse proxy must forward `/static/*`; sub-paths are not supported |

# 11. Glossary

| Term | Meaning |
|------|---------|
| SBOM | Software Bill of Materials: the list of packages in a system |
| OSV | Open Source Vulnerabilities database (osv.dev) |
| CVE / GHSA / PYSEC / MAL | Advisory identifiers (MITRE, GitHub, PyPA, OpenSSF malicious packages) |
| CVSS | Common Vulnerability Scoring System (severity from 0 to 10) |
| EPSS | Exploit Prediction Scoring System: probability of exploitation in 30 days |
| KEV | CISA Known Exploited Vulnerabilities catalog |
| PoC | Proof-of-concept exploit code |
| IOC | Indicator of compromise |
| VEX | Vulnerability Exploitability eXchange: statements that a product is (not) affected |
| purl | Package URL: a standard package identifier |
| MTTR | Mean/median time to remediate (OpenBOM reports the median) |
| EOL | End of life: no more security updates |
| Snapshot ingest | Each scan replaces the asset's package list |
