# Endpoint Agent Guide

> Deploying, configuring and operating the OpenBOM agent (v5.1). Every flag and default is listed in
> the [Configuration Reference](configuration.md).

## Overview

The agent is a single Python file (`agent/openbom_agent.py`). It builds a Software Bill of Materials,
matches it against OSV.dev (including OpenSSF malicious-package advisories), enriches findings with
CISA KEV, FIRST EPSS, PoC links and end-of-life data, runs heuristic malware and typosquat checks, and
writes JSON/CycloneDX/SPDX/SARIF/HTML/PDF — optionally pushing everything to the OpenBOM backend. It
needs no daemon, no database and (for user-level scans) no root.

## Requirements

| Requirement | Needed for |
|-------------|-----------|
| Python 3.12+ | always |
| `httpx`, `rich`, `jinja2`, `packaging` (`pip install -r requirements.txt`) | always (`jinja2` only for `--report`) |
| `weasyprint` | PDF reports (optional) |
| `rpm` / `dpkg-query` / apk database | host OS packages (auto-detected) |
| `pip`, `npm` | host PyPI / global npm packages |
| `podman` or `docker` | running containers and `--image` |
| `rpm` binary | `--rootfs`/`--image` of RPM-based systems |
| outbound HTTPS | `api.osv.dev`, `api.first.org`, `www.cisa.gov`, `endoflife.date`, `api.deps.dev` (`--deps-dev`) |

## Quick start

```bash
python3 agent/openbom_agent.py                         # interactive menu (on a terminal)
python3 agent/openbom_agent.py --scan-only             # inventory only, no network
python3 agent/openbom_agent.py --check-osv --diff      # full threat hunt of this host
python3 agent/openbom_agent.py --check-osv --diff --report --cyclonedx bom.json --spdx bom.spdx.json
python3 agent/openbom_agent.py --check-osv --diff --server-url https://openbom.example --api-key "$KEY"
```

### Interactive menu

Running the agent without a mode on a terminal opens a menu:

| Key | Action |
|-----|--------|
| 1 | Quick SBOM inventory (offline) |
| 2 | Full threat hunt — OSV + EPSS + KEV + diff + heuristics (optionally push to a server) |
| 3 | Full threat hunt + HTML/PDF report + CycloneDX |
| 4 | Deep heuristic IOC + typosquat scan of all Python/npm packages |
| p | Scan a project / repository directory |
| i | Scan a container image |
| s | Analyse an existing SBOM file |
| 5 | View the latest scan result |
| 6 | Push the latest scan to an OpenBOM server |
| 7 | Export the latest scan as CycloneDX |
| 8 | Show cache / baseline status |
| 9 | Clear caches and diff baselines |
| 0 | Exit |

## Scan targets

By default the agent inventories **this host**: OS packages (RPM, dpkg or apk), global pip and npm
packages, and packages inside running Podman and Docker containers (limit with `--ecosystems`).
Any of the following targets **replaces** the host scan and implies `--check-osv`:

```bash
python3 agent/openbom_agent.py --path ./my-repo            # lockfiles, manifests, venvs, JARs (repeatable)
python3 agent/openbom_agent.py --image nginx:1.25           # pulls if needed, scans, deletes the temp copy
python3 agent/openbom_agent.py --rootfs /mnt/vm-disk        # unpacked filesystem / chroot
python3 agent/openbom_agent.py --sbom syft-output.cdx.json  # CycloneDX or SPDX JSON from another tool
```

### What `--path` understands

| Ecosystem | Files |
|-----------|-------|
| PyPI | `requirements*.txt` (pinned `==` only), `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`, `*.dist-info/METADATA`, `*.egg-info/PKG-INFO` |
| npm | `package-lock.json` (v1–v3), `npm-shrinkwrap.json`, `yarn.lock` (classic + berry), `pnpm-lock.yaml`, top-level `node_modules/*/package.json` |
| Go | `go.mod` (`require` blocks; `toolchain go1.x` → Go standard library) |
| Cargo | `Cargo.lock` (registry crates) |
| RubyGems | `Gemfile.lock` |
| Packagist | `composer.lock` |
| NuGet | `packages.lock.json` |
| Maven | `pom.xml` (explicit versions), `gradle.lockfile`, `*.jar/*.war/*.ear` (`pom.properties`, nested fat jars) |

Local path/workspace dependencies are skipped. Malformed files are logged at debug level and skipped.

### OS package coverage

| Distribution | Inventory | OSV matching |
|--------------|-----------|--------------|
| Debian, Ubuntu (and their containers/images) | dpkg | ✅ by source package |
| AlmaLinux, Rocky Linux | rpm | ✅ with epoch |
| Alpine | apk | ✅ by origin package |
| Fedora, RHEL, CentOS Stream, openSUSE, Amazon Linux | rpm | ❌ no OSV feed — inventory, diff, licenses, EOL only |

## Analysis

| Feature | How it works |
|---------|--------------|
| Vulnerabilities | OSV `querybatch` (1000 per request, pagination followed) + per-advisory enrichment (20 concurrent). Severity from the highest CVSS v3.x base score, else qualitative ratings. The fix shown is the one for the range containing the installed version |
| Known-malicious packages | OSV `MAL-*` advisories → CRITICAL, `is_malicious`, "treat host as compromised" |
| CISA KEV | Catalog cached 24 h; matched via CVE ids from `aliases`, `upstream` (Debian/Ubuntu) and `related` (Alma/Rocky) |
| EPSS | FIRST.org, 100 CVEs per request |
| PoC links | exploit-db, PacketStorm and GitHub PoC references in advisories |
| De-duplication | GHSA/PYSEC/CVE aliases of the same issue are merged into one finding |
| Heuristics & typosquats | See [Detection Rules](detection-rules.md) (`--heuristics new|all|off`) |
| Licenses | rpm, apk, Debian copyright, PyPI metadata, npm, lockfiles; `--deps-dev` fills gaps; `--license-deny` enforces policy |
| End-of-life | OS (and, for host scans, the agent's Python and Node.js) via endoflife.date; `--no-eol` to skip |
| Suppressions | `--vex` and `--ignore` — see [SBOM, VEX & Triage](sbom-and-vex.md) |
| Delta | `--diff` labels `[NEW]`/`[UPGRADED]`/`[DOWNGRADED]` and lists removed packages; one baseline per target |

## Outputs

| Output | Flag | Notes |
|--------|------|-------|
| Console summary | always | Asset, target, OS, ecosystems, delta, EOL, license violations, malicious/KEV/IOC panels, metrics, findings (highest risk first) |
| Native JSON | `-o` (default `output/sbom_<ts>.json`) | Backend ingest format |
| CycloneDX 1.5 | `--cyclonedx PATH` | components with purls + vulnerabilities (ratings, EPSS, KEV properties) |
| SPDX 2.3 | `--spdx PATH` | packages with purls and declared licenses (`LicenseRef-*` for non-SPDX strings) |
| SARIF 2.1.0 | `--sarif PATH` | one rule per advisory, results located at the lockfile that introduced the package |
| HTML / PDF | `--report` | dark-theme report in `--output-dir`; PDF needs WeasyPrint |
| Webhook | `--webhook-url` | sent when malicious, KEV, IOC, critical or EOL findings exist |
| Backend | `--server-url` (+ `--api-key`) | POST to `/api/v1/ingest` with retries |

### JSON structure (abridged)

```json
{
  "hostname": "web-01",
  "scan_ts": "2026-10-04T05:49:23+00:00",
  "agent_version": "5.1.0",
  "os": {"id": "debian", "version_id": "12", "pretty_name": "Debian GNU/Linux 12 (bookworm)", "osv_ecosystem": "Debian:12"},
  "scan_target": {"type": "host", "ref": "web-01"},
  "total_packages": 1834,
  "packages": [
    {"name": "libssl3", "version": "3.0.11-1~deb12u1", "ecosystem": "Debian", "diff_label": null,
     "osv_ecosystem": "Debian:12", "osv_name": "openssl", "license": "Apache-2.0",
     "purl": "pkg:deb/debian/libssl3@3.0.11-1~deb12u1?distro=debian-12&upstream=openssl"}
  ],
  "diff_summary": {"new": 2, "removed": 0, "upgraded": 5, "downgraded": 0, "unchanged": 1827},
  "removed_packages": [],
  "eol": [{"product": "debian", "cycle": "12", "label": "Debian GNU/Linux 12", "eol": "2028-06-30", "is_eol": false, "days_left": 633}],
  "license_violations": [],
  "suppressed": [{"vuln_id": "GHSA-…", "package": "requests", "version": "2.19.0", "status": "not_affected", "justification": "…", "source": "openvex.json"}],
  "osv_summary": {"queried": 1834, "vulnerable": 41, "kev_hits": 1, "poc_count": 3, "heuristic_hits": 0,
                  "malicious_hits": 0, "total_critical": 7, "total_high": 97, "total_medium": 82, "total_low": 7, "total_unknown": 0},
  "osv_vulnerabilities": [
    {"package": {"name": "libssl3", "version": "3.0.11-1~deb12u1", "ecosystem": "Debian"},
     "max_severity": "HIGH",
     "vulns": [{"vuln_id": "DEBIAN-CVE-2024-5535", "severity": "CRITICAL", "cvss_score": 9.1,
                "summary": "…", "fixed_version": "3.0.15-1~deb12u1", "recommendation": "Upgrade to version 3.0.15-1~deb12u1",
                "epss_score": 0.0558, "epss_percentile": 0.92, "is_kev": false, "kev_description": null,
                "is_heuristic": false, "is_malicious": false, "poc_links": [], "cves": ["CVE-2024-5535"]}]}
  ]
}
```

`queried` counts packages that were actually checked (a failed OSV batch is reported as unchecked,
never as clean).

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Nothing at/above `--fail-on` |
| `1` | No packages / target failed / unreadable VEX or ignore file / push failed (`--push-file`) |
| `2` | Findings at/above `--fail-on`, or any KEV match, known-malicious package or license violation |
| `130` | Interrupted |

## Scheduling

### Cron

```bash
# /etc/cron.d/openbom — daily full hunt pushed to the backend
0 2 * * * root OPENBOM_API_KEY=... /usr/bin/python3 /opt/OpenBOM/agent/openbom_agent.py \
  --check-osv --diff --server-url https://openbom.internal --output-dir /var/lib/openbom/output >/dev/null 2>&1
```

### systemd timer

```ini
# /etc/systemd/system/openbom-scan.service
[Unit]
Description=OpenBOM endpoint scan
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/opt/OpenBOM
EnvironmentFile=/etc/openbom/agent.env          # OPENBOM_SERVER_URL=…, OPENBOM_API_KEY=…
ExecStart=/usr/bin/python3 /opt/OpenBOM/agent/openbom_agent.py --check-osv --diff --output-dir /var/lib/openbom/output
SuccessExitStatus=2                             # findings are not a service failure
```

```ini
# /etc/systemd/system/openbom-scan.timer
[Unit]
Description=Run OpenBOM every 6 hours

[Timer]
OnCalendar=*-*-* 00/6:00:00
RandomizedDelaySec=30m                          # spread load across the fleet
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl enable --now openbom-scan.timer
```

`SuccessExitStatus=2` matters: exit code 2 means "findings present", not a failure.

## Logging and state

* Console output via Rich; debug log in `/var/log/openbom_agent.log` (fallback `./logs/openbom_agent.log`).
  `-v` shows debug messages on the console too.
* Caches and baselines live in the private state dir (`~/.cache/openbom` or `/var/lib/openbom`, or
  `$OPENBOM_STATE_DIR`). Clear them with menu option 9 or `rm <state>/*.json`; use `--no-cache` to bypass
  the OSV cache for one run.

See [Troubleshooting](troubleshooting.md) when something does not behave as described.
