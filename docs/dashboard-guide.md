# Dashboard Guide

The OpenBOM console is served by the backend at `http://<server>:8000/`. It is built with
[Arco Design](https://arco.design) (React) and ships all assets locally, so it works offline and
on air-gapped networks. Pages and cards animate in, KPI numbers count up and severity bars fill in.
All motion is switched off when the operating system asks for reduced motion (`prefers-reduced-motion`).

![Fleet overview](../assets/dashboard-overview.jpg)

## First login

1. Open the console. If the server has `OPENBOM_API_KEY` set, every page shows *API key required*.
2. Go to **Settings → API key**, paste a key and click **Save & test**. The key is stored only in this
   browser (`localStorage`) and sent as `X-API-Key`.
3. The status dot in the top bar is green when authentication is on, orange when the API is
   unauthenticated, red when the backend is unreachable.

The header also has a **global search**: an advisory id (`CVE-`, `GHSA-`, `MAL-`, `PYSEC-`, `GO-`,
`RUSTSEC-`, `DEBIAN-`, `UBUNTU-`, `ALSA-`, `RLSA-`, `ALPINE-`) opens the vulnerability list filtered
to it; anything else searches packages across the fleet. The sun/moon button switches dark/light theme.

## Menu

### Monitor

**Overview** — fleet KPIs (assets, packages, vulnerabilities, critical, KEV, malicious, IOC/typosquat,
end-of-life, license violations, stale assets). Every card is clickable. Red/orange banners appear when
known-malicious packages or KEV vulnerabilities are present; the KEV banner reminds you that findings
reflect each asset's *last pushed scan*. Below, in rows of equal-height cards:

* **Severity distribution** (bar + one tile per severity, click a tile to open the filtered
  vulnerability list) next to **Coverage** (scan targets by type, suppressing triage decisions, stale threshold),
* **Highest-risk assets** next to **Packages by ecosystem**,
* **Recent scans** across the full width (source: agent, sbom-upload, reanalysis; packages, critical, high, KEV).

**Assets** — every host, image, repository, rootfs and imported SBOM. Filter by name and type, sort by
risk, name, last seen or package count. Tags show the target type, **STALE** (no scan for
`OPENBOM_STALE_DAYS`) and **EOL**. Click a row for the asset page:

* header actions: **Re-analyze** (re-match the stored inventory against fresh OSV/EPSS/KEV),
  **CycloneDX** (download the asset SBOM), **Decommission** (delete links and history; asks for confirmation),
* tabs: **Vulnerabilities** (with severity filter, "show suppressed" switch and a **Triage** button per row),
  **Packages** (search, ecosystem filter, license, **found in** path, purl), **Licenses** (policy violations reported by the agent),
  **End-of-life**, **Scan history** (trend of critical + high findings per scan).

The **risk score** (0–100) saturates: each distinct vulnerability adds its severity weight
(CRITICAL 10, HIGH 6, MEDIUM 3, LOW/UNKNOWN 1), +15 if KEV, +20 if heuristic, +30 if known-malicious,
+10 × EPSS; the sum is mapped through `100·(1−e^(−Σ/200))`.

### Hunt

**Threat Hunt** — five tabs, each listing affected assets with their findings:
*Malicious packages* (OSV `MAL-*`), *CISA KEV*, *IOC & typosquat* (agent heuristics), *Critical*,
*High EPSS* (slider for the minimum probability). Each finding shows the package, the fixed version and
**where the package was found**. Each asset card shows when it was last scanned; hover it for the exact
agent command that rescans that target.

**Vulnerabilities** — every advisory present on at least one asset, highest risk first (malicious →
heuristic → KEV → severity → EPSS). Filter by text (id, CVE, summary), severity and intel (malicious,
KEV, IOC, EPSS ≥ 10 %). The **Affected package · asset · path** column lists the first five exposures:
package, installed → fixed version, asset and the path it was found in. **Export CSV** respects the
filters and includes a `found_in` column. Clicking a row opens the **vulnerability drawer**: summary,
CVE links (NVD), CVSS, EPSS with percentile, KEV description, PoC/exploit links, triage state, and every
affected host with installed version, fixed version and the full **Found in** path.

![Vulnerabilities with package paths](../assets/dashboard-vulnerabilities.jpg)

**Package Search** — "which assets have X installed right now?" Search by name (contains or exact),
optional exact version and ecosystem. Results show license, vulnerability count/max severity, and every
asset with the path where it holds the package (click an asset to open it).

#### Package paths ("Found in")

Paths tell you *which* copy of a package to fix, for example the venv of one project inside a scanned
repository tree. Long paths are shortened around the project and the file
(`~/…/payments-api/venv/…/anyio-4.12.1.dist-info`). Hover a path, or open the vulnerability
drawer, to see the full path.

| Source | Path shown |
|--------|------------|
| Host pip packages | The `*.dist-info` directory (or the site-packages directory when `pip` belongs to another environment) |
| Host global npm packages | `…/node_modules/<package>` |
| `--path` / `--rootfs` | The manifest, lockfile, venv `METADATA` or archive, as an absolute path |
| `--image` | Path inside the image |
| OS packages (RPM/dpkg/apk), containers | None. Shown as *system package (package manager)*, because they live in the package-manager database |

*Path not recorded* appears for language packages from scans made by agents that predate this feature. Re-run the agent
on that target to fill it in.

### Govern

**Licenses** — license inventory of installed packages grouped by category: permissive, weak copyleft,
strong copyleft, unknown, other. Click a category card to filter, click a license to see its packages
and hosts. Enforce policy in the agent with `--license-deny`; violations show on the asset page.

**End-of-Life** — assets running operating systems or runtimes past (or within 180 days of) end of
life, as reported by agents during `--check-osv` scans.

**Triage & VEX** — all analyst decisions with scope, state, justification, notes and author.
**Import OpenVEX** applies statements fleet-wide; **Export OpenVEX** downloads every decision with the
affected package purls. See [SBOM, VEX & Triage](sbom-and-vex.md) for the state semantics.

#### Triaging a finding

1. Click **Triage** in a vulnerability table or in the vulnerability drawer.
2. Pick a state. For `not_affected`, pick an OpenVEX justification.
3. Choose the scope: *whole fleet* or *only this asset* (available from an asset page).
4. Add analyst notes and **Save decision**.

`not_affected` and `false_positive` hide the finding from views, counts and risk scores. Other states
are shown as a tag next to the finding.

`resolved` does **not** hide a finding. If the latest scan still contains the vulnerable version, the tag
reads **resolved · still detected** and the drawer explains why. Upgrade the copy at the path shown, then
re-run the agent on the same target (`--path`, `--image`, … as before). The finding then disappears
because ingest is snapshot-based.

### Data

**SBOM Import** — drag a CycloneDX or SPDX JSON file, confirm the asset name and choose whether the
server should analyse it (OSV/EPSS/KEV). **Re-analyse entire fleet now** re-matches every stored
inventory; automate it with `OPENBOM_REANALYZE_HOURS`.

**Reports & Export** — asset CycloneDX, OpenVEX, fleet inventory CSV, threat summary JSON, and a link to
the filtered vulnerability CSV.

**Agent Setup** — copy-ready commands for installing the agent, scanning hosts, images, repositories
and SBOMs, and scheduling with cron (pre-filled with this server's URL), plus a coverage summary.

**Settings** — API key, server status/version, link to `/docs`, and **Prune orphaned records**
(deletes packages no asset has and vulnerabilities no package references).

## Keyboard & URL tips

* Every view is a URL fragment (`#/asset/web-01?tab=packages`, `#/vulns?q=CVE-2024-3094`,
  `#/packages?name=xz&exact=1`) — bookmark or share them.
* `#/vulns?open=<id>` opens the vulnerability drawer directly.
* Collapse the sidebar with the button left of the breadcrumb (it collapses automatically on narrow screens).

## Security notes

* Agent-supplied data (package names, summaries, paths) is untrusted; the console renders it only as text.
* The console refuses to be framed (`frame-ancestors 'none'`, `X-Frame-Options: DENY`).
* The page runs under `Content-Security-Policy: script-src 'self'` — no inline scripts, no eval, no
  third-party origins. Vendored library versions and licenses are listed in
  `server/static/vendor/LICENSES.md`.
