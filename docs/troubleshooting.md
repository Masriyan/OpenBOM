# Troubleshooting

Run the agent with `-v` for debug output; the full debug log is written to
`/var/log/openbom_agent.log` or `./logs/openbom_agent.log`.

## Agent

| Symptom | Cause / fix |
|---------|-------------|
| `one of --scan-only, --check-osv, --push-file or --menu is required` | No mode and no TTY (cron/CI). Add `--check-osv` or `--scan-only`, or pass a target (`--path` etc.), which implies `--check-osv` |
| Exit code `1`, "No packages found" | The target has no recognised packages. For `--path`, only **pinned** requirements (`==`) are read — `>=` ranges cannot be matched. Check `--ecosystems` for host scans |
| "OSV has no advisory feed for Fedora/RHEL…" | Expected: OSV publishes no Fedora/RHEL/openSUSE advisories. OS packages are inventoried and diffed; PyPI/npm packages are still checked |
| Many OS packages but few findings on Debian/Ubuntu | Debian matching uses **source** package names and versions; that is correct, findings are reported on the binary package |
| "OSV batch query failed (N packages will be reported as unchecked)" | Network or OSV outage. Those packages are not cached as clean; re-run later. `queried` in the JSON shows how many were actually checked |
| "N vulnerability record(s) could not be enriched" | Individual `GET /v1/vulns/{id}` failed; findings are kept with UNKNOWN severity and not cached |
| Heuristic scan never runs | `--heuristics new` needs `--diff` (only changed packages are scanned). Use `--heuristics all` for a full sweep |
| Every package is `[NEW]` | First run with `--diff` for this target (no baseline yet), or the state dir changed (e.g. root vs. user, different `OPENBOM_STATE_DIR`) |
| "Ignoring untrusted state file … (symlink or foreign owner)" | A cache/baseline file is a symlink or owned by another user. Delete it; the agent refuses such files on purpose |
| "OSV cache disabled: … owned by uid …" | The state dir belongs to another user. Fix ownership or set `OPENBOM_STATE_DIR` |
| `--image` fails with "needs podman or docker on PATH" / "create … failed" | Install podman or docker, check the image reference and registry login; the agent runs `create` + `export` with your user's permissions |
| "RPM database found … but no rpm binary" (rootfs/image) | Scanning an RPM-based rootfs needs `rpm` on the scanning host |
| `--sbom`: "not a CycloneDX or SPDX JSON document" | Only JSON is supported. Convert XML/tag-value first |
| SBOM components skipped | Components without a purl (or without a version) cannot be matched; the count is logged |
| License shows as empty | Debian packages only have licenses when `/usr/share/doc/<pkg>/copyright` is machine-readable; lockfile packages often lack metadata — use `--deps-dev` |
| "weasyprint not installed — PDF generation skipped" | `pip install weasyprint` (needs Pango); the HTML report is still written |
| Webhook "delivery failed" | The URL is never logged (it embeds a secret); test it with `curl -X POST -d '{"text":"t"}'` |
| Push fails with HTTP 401 | Wrong/missing `--api-key` / `OPENBOM_API_KEY` |
| Push fails with HTTP 413 | Payload above `OPENBOM_MAX_PACKAGES` on the server |
| Push fails with HTTP 422 | Payload validation; usually a hand-edited JSON (e.g. hostname containing `/`) |

### Resetting the agent state

```bash
python3 agent/openbom_agent.py      # menu → 9 "Clear caches & diff baseline"
# or
rm -f ~/.cache/openbom/*.json       # /var/lib/openbom/*.json when running as root
```

## Backend

| Symptom | Cause / fix |
|---------|-------------|
| Log: "OPENBOM_API_KEY is not set — the API is unauthenticated" | Set `OPENBOM_API_KEY` for anything beyond local testing |
| Log: "Schema upgrade: added column …" | Normal after upgrading: new nullable columns are added to an existing database once |
| `database is locked` (SQLite) | Many agents pushing at once. SQLite has a 30 s busy timeout and WAL; for fleets use PostgreSQL |
| HTTP 409 "Concurrent ingest conflict" | Two ingests created the same package simultaneously three times in a row; the agent can simply retry |
| A removed package still shows as vulnerable | Ingest is snapshot-based — the host's next scan removes it. To drop a host entirely use *Decommission* |
| Counts differ between Overview and an asset | Triage decisions suppress findings fleet-wide or per asset; enable "show suppressed" to compare |
| Re-analysis returns `packages_checked: 0` | The stored packages have no OSV ecosystem (e.g. Fedora RPMs) — nothing to query |
| Scheduled re-analysis does nothing | `OPENBOM_REANALYZE_HOURS` must be > 0; the first run happens one interval after startup. Check the log for "Scheduled re-analysis" |

## Console

| Symptom | Cause / fix |
|---------|-------------|
| "API key required" on every page | Enter the key in **Settings**; it is stored per browser |
| Blank page | Check the browser console. The page needs JavaScript and loads only from the same origin; a reverse proxy must forward `/static/*` |
| Old UI after upgrading | Hard-reload; `app.js`/`app.css` are served `no-cache`, vendor files are cached 7 days and only change with new filenames/versions |
| Behind a reverse proxy at a sub-path | Not supported yet — serve OpenBOM at the root of a (sub)domain |
