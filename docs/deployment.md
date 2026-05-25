# Production Deployment Guide

> Deploying OpenBOM at scale with PostgreSQL, systemd, and fleet-wide agent management.

## Architecture Overview

A production OpenBOM deployment consists of:

1. **Backend Server** — FastAPI application with PostgreSQL, running behind a reverse proxy
2. **Endpoint Agents** — Deployed to every managed Linux host, running on a schedule
3. **Alerting** — Webhook integration to Slack, Teams, or your SIEM

```
                    ┌──────────────────────────┐
                    │   Nginx / Caddy / ALB    │
                    │   (TLS termination)      │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────v─────────────┐
                    │   OpenBOM Backend        │
                    │   uvicorn --workers 4    │
                    │   port 8000              │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────v─────────────┐
                    │   PostgreSQL 15+         │
                    │   database: openbom      │
                    └──────────────────────────┘
```

## Backend Setup

### 1. Database

```bash
# PostgreSQL
sudo -u postgres createuser openbom --pwprompt
sudo -u postgres createdb openbom --owner=openbom
```

### 2. Application

```bash
# Clone and install
git clone https://github.com/Masriyan/OpenBOM.git /opt/OpenBOM
cd /opt/OpenBOM
python3 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn sqlalchemy asyncpg pydantic

# Configure
export DATABASE_URL="postgresql+asyncpg://openbom:yourpassword@localhost:5432/openbom"
```

### 3. Systemd Service

```ini
# /etc/systemd/system/openbom-backend.service
[Unit]
Description=OpenBOM Backend Server
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=exec
User=openbom
Group=openbom
WorkingDirectory=/opt/OpenBOM
Environment=DATABASE_URL=postgresql+asyncpg://openbom:yourpassword@localhost:5432/openbom
ExecStart=/opt/OpenBOM/venv/bin/uvicorn server.main:app \
    --host 127.0.0.1 \
    --port 8000 \
    --workers 4 \
    --access-log
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now openbom-backend
```

### 4. Reverse Proxy (Nginx)

```nginx
# /etc/nginx/conf.d/openbom.conf
server {
    listen 443 ssl http2;
    server_name openbom.internal.yourcompany.com;

    ssl_certificate     /etc/pki/tls/certs/openbom.crt;
    ssl_certificate_key /etc/pki/tls/private/openbom.key;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Agent Deployment

### 1. Install Agent on Endpoints

```bash
# Ansible example
- name: Deploy OpenBOM agent
  hosts: all
  tasks:
    - name: Create directory
      file:
        path: /opt/OpenBOM/agent
        state: directory
        mode: '0755'

    - name: Copy agent
      copy:
        src: agent/openbom_agent.py
        dest: /opt/OpenBOM/agent/openbom_agent.py
        mode: '0755'

    - name: Install dependencies
      pip:
        name:
          - httpx
          - rich
        executable: pip3

    - name: Deploy scan script
      template:
        src: templates/openbom-scan.sh.j2
        dest: /opt/OpenBOM/run_scan.sh
        mode: '0755'

    - name: Deploy systemd timer
      template:
        src: templates/openbom-scan.timer.j2
        dest: /etc/systemd/system/openbom-scan.timer
      notify: reload systemd

    - name: Enable timer
      systemd:
        name: openbom-scan.timer
        enabled: yes
        state: started
```

### 2. Agent Scan Script

```bash
#!/bin/bash
# /opt/OpenBOM/run_scan.sh
set -euo pipefail

BACKEND_URL="{{ openbom_backend_url }}"
SCAN_FILE="/tmp/openbom_scan_$$.json"
AGENT="/opt/OpenBOM/agent/openbom_agent.py"

# Run scan
python3 "$AGENT" --check-osv --diff -o "$SCAN_FILE" 2>>/var/log/openbom_agent.log

# Push to backend
if [ -f "$SCAN_FILE" ]; then
    curl -sf -X POST "$BACKEND_URL/api/v1/ingest" \
        -H "Content-Type: application/json" \
        -d @"$SCAN_FILE" >> /var/log/openbom_agent.log 2>&1
    rm -f "$SCAN_FILE"
fi
```

### 3. Scan Frequency Recommendations

| Environment | Frequency | Rationale |
|-------------|-----------|-----------|
| Production servers | Every 6 hours | Balance between coverage and API load |
| CI/CD runners | Every build | Catch newly introduced dependencies |
| Development workstations | Daily | Track developer tool sprawl |
| Container hosts | Every 4 hours | Container images change frequently |

## Webhook Configuration

### Slack

1. Create a Slack App at https://api.slack.com/apps
2. Enable Incoming Webhooks
3. Create a webhook for your `#security-alerts` channel
4. Pass the URL to the agent:

```bash
python3 agent/openbom_agent.py --check-osv --diff \
    --webhook-url https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
```

### Microsoft Teams

1. In your Teams channel, add an Incoming Webhook connector
2. Copy the webhook URL
3. Pass it to the agent (same `--webhook-url` flag — the payload format is compatible)

## Monitoring the Backend

### Health Check

```bash
curl -sf http://localhost:8000/health
# {"status": "ok", "service": "openbom-backend"}
```

### Fleet Summary

```bash
curl -sf http://localhost:8000/api/v1/threats/summary | python3 -m json.tool
```

### Alert on KEV Findings

```bash
# Cron job that checks for KEV threats every hour
0 * * * * curl -sf http://localhost:8000/api/v1/threats/kev | python3 -c "
import sys, json
data = json.load(sys.stdin)
if data:
    hosts = [a['asset']['hostname'] for a in data]
    print(f'KEV ALERT: {len(hosts)} host(s) affected: {hosts}')
    sys.exit(1)
" || mail -s "OpenBOM KEV Alert" security@yourcompany.com
```

## Scaling Considerations

| Component | Scaling Strategy |
|-----------|-----------------|
| Backend API | Increase `--workers` (1 per CPU core) or deploy behind a load balancer |
| PostgreSQL | Standard PostgreSQL scaling: read replicas, connection pooling (pgBouncer) |
| Agent scans | Stagger cron jobs across fleet to avoid API thundering herd |
| OSV API | Agent-side caching (12h) reduces load; batch queries minimize request count |
| KEV catalog | Single 1.2MB download per agent, cached 24 hours |
| EPSS API | Batch queries (100 CVEs per request) minimize request count |

## Security Considerations

- **No secrets in agent output**: The JSON payload contains only package names, versions, and public vulnerability data
- **Backend authentication**: Not included in the open-source version. Add API key middleware or OAuth2 for production deployments
- **Network**: Agents need outbound HTTPS to osv.dev, api.first.org, and cisa.gov. Backend needs inbound HTTP from agents only
- **Database**: Use TLS for PostgreSQL connections in production
- **Log files**: `/var/log/openbom_agent.log` may contain hostnames and package names — restrict access appropriately
