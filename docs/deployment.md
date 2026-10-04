# Production Deployment Guide

> Running the OpenBOM backend (2.1) with PostgreSQL, systemd and TLS, and rolling agents out to a fleet.

## Architecture overview

1. **Backend** — FastAPI application (API + Arco Design console) behind a TLS reverse proxy.
2. **Database** — PostgreSQL for fleets (SQLite is fine for a single analyst or a lab).
3. **Agents** — scheduled on every Linux host, in CI pipelines, or pointed at images/SBOMs.
4. **Alerting** — agent webhooks to Slack/Teams/Discord, plus polling of the threat API.

```
   agents (hosts, CI, image scans)          analysts (browser)
                │  POST /api/v1/ingest            │  https://openbom.internal/
                └──────────────┬──────────────────┘
                     ┌─────────v──────────┐
                     │ Nginx / Caddy (TLS)│
                     └─────────┬──────────┘
                     ┌─────────v──────────┐      outbound HTTPS (server-side analysis):
                     │ uvicorn server.main│ ───► api.osv.dev, api.first.org, www.cisa.gov
                     │ (API + console)    │
                     └─────────┬──────────┘
                     ┌─────────v──────────┐
                     │ PostgreSQL 14+     │
                     └────────────────────┘
```

## Backend setup

### 1. Database

```bash
sudo -u postgres createuser openbom --pwprompt
sudo -u postgres createdb openbom --owner=openbom
```

Tables are created on first start; later versions add new (nullable) columns automatically and log
`Schema upgrade: added column …`. Back up the database before upgrading.

### 2. Application

```bash
sudo useradd --system --home /opt/OpenBOM --shell /usr/sbin/nologin openbom
sudo git clone https://github.com/Masriyan/OpenBOM.git /opt/OpenBOM
cd /opt/OpenBOM
sudo python3 -m venv venv
sudo venv/bin/pip install -r requirements.txt asyncpg
sudo install -d -o openbom -g openbom -m 0700 /var/lib/openbom
```

### 3. Configuration

```bash
# /etc/openbom/backend.env  (chmod 600, owned by root)
DATABASE_URL=postgresql+asyncpg://openbom:CHANGE_ME@localhost:5432/openbom
OPENBOM_API_KEY=<output of: openssl rand -hex 32>        # comma-separate several keys to rotate
OPENBOM_CORS_ORIGINS=https://openbom.internal
OPENBOM_STALE_DAYS=7
OPENBOM_REANALYZE_HOURS=24                              # continuous monitoring (0 = off)
OPENBOM_STATE_DIR=/var/lib/openbom                      # OSV/KEV cache for server-side analysis
```

All variables are described in the [Configuration Reference](configuration.md#backend-environment-variables).

### 4. systemd service

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
curl -s http://127.0.0.1:8000/health     # {"status":"ok",…,"auth_required":true}
```

**Workers and re-analysis:** with `OPENBOM_REANALYZE_HOURS` set, every uvicorn worker runs its own
schedule. Either keep `--workers 1` (sufficient for most fleets — ingest is bulk) or run the API with
several workers and `OPENBOM_REANALYZE_HOURS=0`, triggering `POST /api/v1/reanalyze` from cron instead:

```bash
0 4 * * * curl -sf -X POST -H "X-API-Key: $KEY" https://openbom.internal/api/v1/reanalyze >/dev/null
```

### 5. Reverse proxy (Nginx)

```nginx
# /etc/nginx/conf.d/openbom.conf
server {
    listen 443 ssl http2;
    server_name openbom.internal;

    ssl_certificate     /etc/pki/tls/certs/openbom.crt;
    ssl_certificate_key /etc/pki/tls/private/openbom.key;

    client_max_body_size 64m;          # large hosts / SBOM uploads

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;        # fleet re-analysis can take minutes
    }
}
```

Serve OpenBOM at the root of a (sub)domain; sub-path deployments are not supported. The backend sets
its own CSP and security headers — do not override them with a weaker policy.

## Agent rollout

### Ansible

```yaml
- name: Deploy OpenBOM agent
  hosts: linux
  become: true
  vars:
    openbom_server: https://openbom.internal
    openbom_api_key: "{{ vault_openbom_api_key }}"
  tasks:
    - name: Install dependencies
      ansible.builtin.pip:
        name: [httpx, rich, jinja2, packaging]

    - name: Agent directory
      ansible.builtin.file: {path: /opt/OpenBOM/agent/templates, state: directory, mode: "0755"}

    - name: Copy agent
      ansible.builtin.copy: {src: agent/openbom_agent.py, dest: /opt/OpenBOM/agent/openbom_agent.py, mode: "0755"}

    - name: Copy report template
      ansible.builtin.copy: {src: agent/templates/report_template.html, dest: /opt/OpenBOM/agent/templates/, mode: "0644"}

    - name: Agent environment
      ansible.builtin.copy:
        dest: /etc/openbom/agent.env
        mode: "0600"
        content: |
          OPENBOM_SERVER_URL={{ openbom_server }}
          OPENBOM_API_KEY={{ openbom_api_key }}

    - name: systemd units
      ansible.builtin.copy: {src: "files/{{ item }}", dest: "/etc/systemd/system/{{ item }}"}
      loop: [openbom-scan.service, openbom-scan.timer]

    - name: Enable timer
      ansible.builtin.systemd: {name: openbom-scan.timer, enabled: true, state: started, daemon_reload: true}
```

The unit files are in the [Agent Guide](agent-guide.md#systemd-timer) (note `SuccessExitStatus=2` and
`RandomizedDelaySec`).

### Scan frequency

| Asset type | Recommendation |
|------------|----------------|
| Internet-facing servers | every 6 h with `--diff` (new packages get heuristic checks quickly) |
| Internal servers | daily |
| Developer workstations | daily, `--heuristics new` |
| CI | every build (`--path` / `--image`, see [CI/CD Integration](ci-integration.md)) |
| Images in a registry | on push, plus nightly backend re-analysis |

Between scans, backend re-analysis picks up advisories published since the last scan.

## Alerting

### Webhooks from agents

```bash
--webhook-url https://hooks.slack.com/services/T000/B000/XXXX       # Slack (text)
--webhook-url https://outlook.office.com/webhook/...                # Teams (text)
--webhook-url https://discord.com/api/webhooks/...                  # Discord (content)
```

Alerts are sent when known-malicious packages, KEV matches, heuristic detections, CRITICAL findings or
end-of-life software are present. The URL is never written to logs.

### Polling the backend

```bash
# hourly: alert when any asset has a KEV or known-malicious finding
0 * * * * for t in kev malicious; do \
  n=$(curl -sf -H "X-API-Key: $KEY" https://openbom.internal/api/v1/threats/$t | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))'); \
  [ "$n" -gt 0 ] && echo "OpenBOM: $n asset(s) with $t findings" | mail -s "OpenBOM $t alert" soc@example.com; done
```

## Monitoring

| Check | How |
|-------|-----|
| Liveness | `GET /health` (no auth) |
| Fleet coverage | `GET /api/v1/threats/summary` → `stale_assets`, `recent_scans` |
| Re-analysis | backend log line `Scheduled re-analysis: N assets, …` |
| Database growth | run *Settings → Prune orphaned records* (or `POST /api/v1/maintenance/prune`) after decommissioning many assets |

## Scaling

| Component | Strategy |
|-----------|----------|
| Ingest | Bulk upserts (chunks of 400); thousands of packages per host ingest in about a second |
| API | More uvicorn workers or replicas behind the proxy (see the re-analysis note above) |
| PostgreSQL | Standard tuning, connection pooling (pgBouncer), regular backups |
| Agents | Stagger schedules (`RandomizedDelaySec`); each agent caches OSV 12 h, KEV/EOL 24 h |
| External APIs | Batched OSV (1000) and EPSS (100) queries with retry/backoff |

## Security checklist

- [ ] `OPENBOM_API_KEY` set; keys distributed via a secret manager; rotate by adding the new key, rolling agents, removing the old one
- [ ] TLS at the proxy; backend bound to `127.0.0.1`
- [ ] PostgreSQL over TLS or local socket; database reachable only from the backend host
- [ ] `OPENBOM_CORS_ORIGINS` restricted to the console origin
- [ ] `/etc/openbom/*.env` mode `0600`
- [ ] Agent logs (`/var/log/openbom_agent.log`) treated as internal data
- [ ] Outbound HTTPS allowed from agents and backend to `api.osv.dev`, `api.first.org`, `www.cisa.gov`, `endoflife.date` (and `api.deps.dev` if `--deps-dev` is used)

See also [SECURITY.md](../SECURITY.md).
