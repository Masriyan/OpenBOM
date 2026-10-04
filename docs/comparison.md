# OpenBOM vs. the SBOM / SCA market

> Gap analysis performed 2026-10-04 against the tools most teams combine today
> ("Syft to generate, Grype/Trivy to scan, Dependency-Track to manage", plus Socket-style
> malicious-package detection). ✅ = supported, ◐ = partial, ✗ = not supported.
> "Before" = OpenBOM agent v5.0 / backend 2.0; "Now" = agent v5.1 / backend 2.1.

## Feature matrix

| Capability | Syft | Grype | Trivy | OSV-Scanner | cdxgen | Dependency-Track | Socket | OpenBOM before | **OpenBOM now** |
|---|---|---|---|---|---|---|---|---|---|
| Host OS packages (rpm/dpkg/apk) | ✅ | ✅ | ✅ | ◐ | ◐ | ✗ (ingests SBOM) | ✗ | ◐ rpm/dpkg | ✅ rpm/dpkg/apk |
| Container images | ✅ | ✅ | ✅ | ✅ | ✅ | ✗ | ✗ | ◐ running Podman only | ✅ `--image` (podman/docker), running Podman/Docker |
| Filesystem / rootfs | ✅ | ✅ | ✅ | ✅ | ✅ | ✗ | ✗ | ✗ | ✅ `--rootfs` |
| Repo lockfiles (Py, npm/yarn/pnpm, Go, Cargo, Gem, Composer, NuGet, Maven/Gradle) | ✅ | ✅ | ✅ | ✅ | ✅ | ✗ | ✅ | ✗ global pip/npm only | ✅ `--path` |
| JAR/WAR (incl. nested fat jars) | ✅ | ✅ | ✅ | ◐ | ✅ | ✗ | ✗ | ✗ | ✅ |
| SBOM input (CycloneDX/SPDX) | — | ✅ | ✅ | ✅ | — | ✅ | ✗ | ✗ | ✅ agent `--sbom`, backend `POST /sbom` |
| SBOM output CycloneDX | ✅ | — | ✅ | ✗ | ✅ | ✅ | ✗ | ✅ | ✅ (distro/epoch/upstream purls) |
| SBOM output SPDX | ✅ | — | ✅ | ✗ | ✗ | ◐ | ✗ | ✗ | ✅ SPDX 2.3 |
| SARIF (code scanning) | — | ✅ | ✅ | ✅ | — | ✗ | ✗ | ✗ | ✅ |
| OSV.dev matching | — | ◐ | ◐ | ✅ | — | ✅ | ✅ | ◐ PyPI only | ✅ PyPI, npm, Go, crates, Gem, Packagist, NuGet, Maven, Debian, Ubuntu, Alma, Rocky, Alpine |
| Known-malicious packages (OpenSSF MAL-*) | ✗ | ◐ | ◐ | ✅ | ✗ | ◐ | ✅ | ✗ (read as UNKNOWN) | ✅ flagged CRITICAL + dedicated views |
| Behavioural / heuristic malware detection | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✅ | ◐ noisy regexes | ✅ strong/weak indicator model, install hooks, typosquats |
| CISA KEV | ✗ | ✅ | ◐ | ✗ | ✗ | ◐ | ✗ | ✅ | ✅ |
| EPSS | ✗ | ✅ | ✗ | ✗ | ✗ | ✅ | ✗ | ✅ | ✅ |
| License detection | ✅ | — | ✅ | ◐ | ✅ | ✅ | ✅ | ✗ | ✅ rpm/apk/dpkg copyright, PyPI, npm, lockfiles, deps.dev |
| License policy / CI gate | ✗ | ✗ | ◐ | ✗ | ✗ | ✅ | ✅ | ✗ | ✅ `--license-deny` |
| VEX consumption | — | ✅ | ✅ | ◐ | ◐ | ✅ | ✗ | ✗ | ✅ OpenVEX + CycloneDX VEX, ignore file w/ expiry |
| Triage workflow + VEX export | ✗ | ✗ | ✗ | ✗ | ✗ | ✅ | ◐ | ✗ | ✅ fleet / per-asset, OpenVEX import/export |
| Continuous re-analysis (no rescan) | ✗ | ✗ | ✗ | ✗ | ✗ | ✅ | ✅ | ✗ | ✅ on demand + `OPENBOM_REANALYZE_HOURS` |
| End-of-life detection | ✗ | ✗ | ◐ | ✗ | ✗ | ✗ | ✗ | ✗ | ✅ OS + Python/Node (endoflife.date) |
| Fleet portfolio / dashboard | ✗ | ✗ | ✗ | ✗ | ✗ | ✅ | ✅ | ◐ basic | ✅ Arco Design console, 13 views |
| Fleet-wide package hunt ("who has xz 5.6.0?") | ✗ | ✗ | ✗ | ✗ | ✗ | ✅ | ◐ | ✅ | ✅ |
| Delta / new-package detection | ✗ | ✗ | ✗ | ✗ | ✗ | ◐ | ✅ | ✅ | ✅ per target baseline |
| Reachability / call-graph analysis | ✗ | ✗ | ✗ | ◐ Go | ◐ | ✗ | ✅ | ✗ | ✗ |
| Go/Rust binary build-info scanning | ✅ | ✅ | ✅ | ✅ | ◐ | ✗ | ✗ | ✗ | ✗ |
| Windows / macOS hosts | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ | ✗ | ✗ |
| Signed attestations (SLSA, in-toto, cosign) | ◐ | ✗ | ✅ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Secrets / IaC misconfiguration | ✗ | ✗ | ✅ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |

## What OpenBOM does that the usual stack does not combine

* One self-hosted tool covers generation (agent), matching (OSV + MAL + KEV + EPSS), behavioural
  heuristics, and portfolio management — instead of Syft + Grype + Dependency-Track + Socket.
* Endpoint-first: runs on Linux hosts (and their running containers) with delta detection, so a newly
  installed or downgraded package is heuristically inspected the moment it appears.
* Data from other generators is a first-class citizen (SBOM upload / `--sbom`), and the backend keeps
  re-matching it as new advisories appear.

## Remaining gaps (not implemented)

| Gap | Why it matters | Notes |
|---|---|---|
| Reachability analysis | Cuts false positives for libraries whose vulnerable function is never called | Needs per-language call graphs (Socket, Endor, osv-scanner for Go) |
| Go/Rust binary scanning | Statically linked binaries hide their dependencies | `go version -m` / `cargo auditable` parsing could be added to the rootfs scanner |
| Windows / macOS agents | Mixed fleets | Agent currently relies on rpm/dpkg/apk + Unix paths |
| Attestations / signature verification | Provenance (SLSA), tamper evidence | deps.dev exposes SLSA provenance; cosign verification would need a dependency |
| Fedora/RHEL OS advisories | OSV has no Fedora/RHEL feed | Inventory works; matching would need Red Hat CSAF/OVAL |
| Secrets / IaC scanning | Out of SBOM scope | Trivy covers it |

Sources: [appsecsanta SBOM comparison](https://appsecsanta.com/sca-tools/sbom-tools-comparison),
[Dependency-Track review](https://appsecsanta.com/dependency-track),
[OpenSSF: detecting malicious packages with the OSV API](https://openssf.org/blog/2026/05/20/detecting-malicious-packages-using-the-osv-api/),
[deps-lsp issue on MAL-* rendering as unknown severity](https://github.com/bug-ops/deps-lsp/issues/646),
[Trivy vs Syft vs Dependency-Track (2026)](https://devsecops.ae/sbom-tools-comparison-2026/).
