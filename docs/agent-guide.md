# Endpoint Agent Guide

> Deploying, configuring, and operating the OpenBOM Endpoint Agent.

## Overview

The OpenBOM Endpoint Agent is a single Python script (`agent/openbom_agent.py`) that runs on Linux systems to collect a Software Bill of Materials (SBOM), check for known vulnerabilities, and produce threat intelligence reports. It requires no daemon, no root access (for most features), and no external database.

## Requirements

### Minimum

- Python 3.12+
- `pip` (for PyPI package extraction)
- `rpm` or `dpkg-query` (auto-detected based on distro)

### Python Dependencies

```bash
# Required for --check-osv mode
pip install httpx

# Required for Rich CLI output
pip install rich

# Required for --report (HTML generation)
pip install jinja2

# Optional: PDF report generation
pip install weasyprint
```

### Optional Tools

| Tool | Purpose |
|------|---------|
| `npm` | Extract global Node.js packages |
| `podman` | Scan packages inside running containers |
| `curl`/`wget` | Not required — agent uses `httpx` directly |

## Usage

### Scan Modes

```bash
# Mode 1: SBOM collection only — zero network calls
python3 agent/openbom_agent.py --scan-only

# Mode 2: Full threat hunting
python3 agent/openbom_agent.py --check-osv

# Mode 3: Full scan + enterprise reports + delta tracking
python3 agent/openbom_agent.py --check-osv --report --diff

# Mode 4: Everything + webhook alerting
python3 agent/openbom_agent.py --check-osv --report --diff \
  --webhook-url https://hooks.slack.com/services/T00/B00/xxxxx
```

### CLI Flags

| Flag | Description |
|------|-------------|
| `--scan-only` | Collect SBOM only. No API calls. Generates JSON output. |
| `--check-osv` | Full threat hunt: OSV + EPSS + CISA KEV + PoC detection. |
| `-o PATH` | Write JSON report to a specific path (default: `output/sbom_YYYYMMDD_HHMMSS.json`). |
| `--report` | Generate HTML and PDF enterprise reports in `output/`. |
| `--diff` | Compare against previous scan. Labels packages as `[NEW]`, `[UPGRADED]`, `[DOWNGRADED]`. Triggers heuristic IOC scan on `[NEW]` packages. |
| `--no-cache` | Bypass the 12-hour OSV response cache. Forces fresh API queries. |
| `--webhook-url URL` | POST a Slack/Teams-compatible alert when CRITICAL or KEV findings are detected. |
| `-v, --verbose` | Enable debug-level console logging. |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan complete, no vulnerabilities |
| `1` | No packages found |
| `2` | Vulnerabilities detected |
| `130` | User interrupted (Ctrl+C) |

## Output Files

### JSON SBOM (`output/sbom_*.json`)

The primary output. Contains the full package inventory, vulnerability findings, EPSS scores, KEV flags, PoC links, and diff labels.

```json
{
  "hostname": "web-server-01",
  "scan_ts": "2026-05-25T12:00:00+00:00",
  "total_packages": 3614,
  "packages": [
    {"name": "requests", "version": "2.31.0", "ecosystem": "PyPI", "diff_label": null}
  ],
  "osv_summary": {
    "queried": 464,
    "vulnerable": 23,
    "kev_hits": 1,
    "poc_count": 3,
    "total_critical": 10
  },
  "osv_vulnerabilities": [
    {
      "package": {"name": "aiohttp", "version": "3.13.3", "ecosystem": "PyPI"},
      "vulns": [
        {
          "vuln_id": "GHSA-xxxx",
          "severity": "CRITICAL",
          "epss_score": 0.15,
          "is_kev": true,
          "kev_description": "...",
          "poc_links": ["https://exploit-db.com/..."],
          "fixed_version": "3.13.4",
          "recommendation": "Upgrade to version 3.13.4"
        }
      ]
    }
  ]
}
```

### HTML Report (`output/report_openbom_YYYYMMDD.html`)

A professional dark-theme report with:
- System overview (hostname, package counts by ecosystem)
- Delta summary (new/removed/upgraded/downgraded)
- CISA KEV alert section (pulsing red badges for actively exploited CVEs)
- Heuristic IOC alert section (malware pattern detections)
- Vulnerability metrics with severity distribution bar
- Detailed findings table with EPSS, Intel badges, and remediation

### PDF Report (`output/report_openbom_YYYYMMDD.pdf`)

Print-ready PDF generated from the HTML report via WeasyPrint.

## Deployment

### Option 1: Cron Job

```bash
# Run full scan daily at 2 AM
echo "0 2 * * * root python3 /opt/OpenBOM/agent/openbom_agent.py --check-osv --diff -o /opt/OpenBOM/output/scan_\$(date +\%Y\%m\%d).json 2>>/var/log/openbom_agent.log" > /etc/cron.d/openbom
```

### Option 2: Systemd Timer

```ini
# /etc/systemd/system/openbom-scan.service
[Unit]
Description=OpenBOM Endpoint Scan

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/OpenBOM/agent/openbom_agent.py --check-osv --diff --report
WorkingDirectory=/opt/OpenBOM
User=openbom
```

```ini
# /etc/systemd/system/openbom-scan.timer
[Unit]
Description=Run OpenBOM scan every 6 hours

[Timer]
OnCalendar=*-*-* 00/6:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl enable --now openbom-scan.timer
```

### Option 3: Agent + Backend Pipeline

```bash
#!/bin/bash
# /opt/OpenBOM/run_and_ingest.sh
set -euo pipefail

BACKEND="https://openbom-backend.internal:8000"
SCAN_FILE="/tmp/openbom_scan_$(date +%s).json"

python3 /opt/OpenBOM/agent/openbom_agent.py \
  --check-osv --diff -o "$SCAN_FILE"

curl -sf -X POST "$BACKEND/api/v1/ingest" \
  -H "Content-Type: application/json" \
  -d @"$SCAN_FILE"

rm -f "$SCAN_FILE"
```

## Supported Ecosystems

| Ecosystem | Detection Method | Package Manager |
|-----------|-----------------|-----------------|
| RPM | `rpm -qa` with fallback to `dnf list installed` | Fedora, RHEL, CentOS, openSUSE |
| Debian | `dpkg-query -W` | Debian, Ubuntu, Mint |
| PyPI | `pip freeze --all` | Any system with pip3 |
| NPM | `npm list -g --depth=0 --json` | Any system with npm |
| Podman-RPM | `podman exec <id> rpm -qa` | RPM-based containers |
| Podman-DEB | `podman exec <id> dpkg-query -W` | Debian-based containers |

## Heuristic IOC Patterns

The heuristic scanner runs only on packages labeled `[NEW]` by the diff engine. It scans `.py` and `.js` files for the following patterns:

| Pattern | Description | Common In |
|---------|-------------|-----------|
| `eval(base64)` | Base64-decoded code execution | Backdoors, obfuscated payloads |
| `exec(base64)` | Same as above via `exec()` | Typosquatting packages |
| `os.system(url)` | Shell execution with embedded URLs | Dependency confusion attacks |
| `subprocess+url` | subprocess calls to curl/wget/powershell | Payload download stages |
| `pastebin/ngrok` | References to pastebin.com, ngrok.io | C2 infrastructure |
| `suspicious_import` | Dynamic imports of socket/ctypes/winreg | Evasion techniques |

**Important**: The heuristic scanner produces findings that require manual review. Some legitimate packages (e.g., `eventlet` which monkey-patches socket imports) may trigger false positives. Treat `MALICIOUS_HEURISTIC` findings as indicators for investigation, not as confirmed malware.

## Logging

Logs are written to two destinations:

1. **File**: `/var/log/openbom_agent.log` (falls back to `logs/openbom_agent.log` if `/var/log` is not writable)
2. **Console**: Rich-formatted output to stdout

Debug-level logging is available with `-v`:

```bash
python3 agent/openbom_agent.py --check-osv -v
```

## Caching

| Cache File | TTL | Purpose |
|-----------|-----|---------|
| `/tmp/openbom_osv_cache.json` | 12 hours | Stores enriched OSV vuln data per package to avoid redundant API calls |
| `/tmp/openbom_kev_cache.json` | 24 hours | Local copy of the CISA KEV catalog (~1,600 entries) |
| `/tmp/openbom_last_state.json` | Permanent | Previous scan's package list for delta comparison |

To force fresh data, use `--no-cache` and delete the state file:

```bash
rm -f /tmp/openbom_osv_cache.json /tmp/openbom_kev_cache.json /tmp/openbom_last_state.json
python3 agent/openbom_agent.py --check-osv --diff --no-cache
```
