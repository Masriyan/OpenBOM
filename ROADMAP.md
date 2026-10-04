# Roadmap

Planned work, ordered by expected impact. Items come from the gap analysis in
[docs/comparison.md](docs/comparison.md) and from operating OpenBOM on real fleets. Contributions are
welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## Near term

| Item | Why | Sketch |
|------|-----|--------|
| Go / Rust binary scanning | Statically linked binaries hide their dependencies from package managers | Parse Go build info (`go version -m` or the `.go.buildinfo` section) and `cargo auditable` sections in the rootfs/path scanner |
| Red Hat / Fedora advisories | OSV has no Fedora/RHEL feed, so RPM hosts are inventory-only today | Consume Red Hat CSAF/VEX and Fedora Bodhi data; map by NEVRA |
| Container layer attribution | Know which Dockerfile layer introduced a package | Walk `podman save`/`docker save` layers instead of the flattened export |
| Notifications from the backend | Alerts today come from agents only | Webhook/e-mail on new KEV or malicious findings after ingest or re-analysis |
| SBOM quality score | Imported SBOMs vary in completeness | Score purl/license/version coverage per uploaded SBOM |

## Mid term

| Item | Why |
|------|-----|
| Reachability hints | Prioritise vulnerable functions that are actually imported/called (start with Python import graphs) |
| Attestation verification | Check SLSA provenance (deps.dev exposes it) and cosign signatures for images |
| Role-based access | Separate read-only and triage/admin API keys, audit log of triage changes |
| Windows / macOS agents | Mixed fleets (winget/MSI, Homebrew, pkgutil) |
| Helm chart & container image for the backend | Simpler deployment |

## Not planned

* Secrets scanning and IaC misconfiguration — out of SBOM scope; pair OpenBOM with Trivy/gitleaks.
* A hosted SaaS — OpenBOM stays self-hosted.

## Done recently

See [CHANGELOG.md](CHANGELOG.md): multi-ecosystem OSV matching, malicious-package intel, repo/image/rootfs/SBOM
targets, SPDX/SARIF, licenses, EOL, VEX & triage, continuous re-analysis, Arco Design console, package
locations ("found in" paths from agent to console) and the console refresh (palette, motion, layout).
