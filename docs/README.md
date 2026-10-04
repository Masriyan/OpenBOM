# OpenBOM Documentation

Start with the project [README](../README.md) for the overview and quick start. This index lists every
document by the question it answers.

## Using OpenBOM

| Document | Read it when you want to… |
|----------|---------------------------|
| [Agent Guide](agent-guide.md) | Run the agent: scan modes, scan targets (host, repo, image, rootfs, SBOM), outputs, menu |
| [Dashboard Guide](dashboard-guide.md) | Use the web console: every menu, triage, SBOM import, exports |
| [Configuration Reference](configuration.md) | Look up every CLI flag, environment variable, file and default |
| [CI/CD Integration](ci-integration.md) | Gate builds in GitHub Actions / GitLab CI / Jenkins, upload SARIF |
| [SBOM, VEX & Triage](sbom-and-vex.md) | Exchange CycloneDX / SPDX / OpenVEX, suppress findings correctly |
| [Troubleshooting](troubleshooting.md) | Fix a failing scan, push, login or dashboard problem |

## Operating OpenBOM

| Document | Read it when you want to… |
|----------|---------------------------|
| [Deployment Guide](deployment.md) | Run the backend in production (PostgreSQL, systemd, TLS, fleet rollout) |
| [API Reference](api-reference.md) | Integrate with the REST API |

## Understanding OpenBOM

| Document | Read it when you want to… |
|----------|---------------------------|
| [Architecture](architecture.md) | Understand the agent pipeline, backend data model and console |
| [Threat Model](threat-model.md) | Understand how intelligence layers are combined into priorities |
| [Detection Rules](detection-rules.md) | See exactly what the heuristic IOC and typosquat engines flag, and tune them |
| [Market Comparison](comparison.md) | Compare OpenBOM with Syft, Grype, Trivy, OSV-Scanner, Dependency-Track, Socket |

## Contributing

| Document | Read it when you want to… |
|----------|---------------------------|
| [Contributing](../CONTRIBUTING.md) | Open an issue or pull request |
| [Development Guide](development.md) | Set up a dev environment, run tests, add parsers / rules / console pages |
| [Changelog](../CHANGELOG.md) | See what changed between versions |
| [Roadmap](../ROADMAP.md) | See planned work and known gaps |
| [Security Policy](../SECURITY.md) | Report a vulnerability, understand the security design |
| [Code of Conduct](../CODE_OF_CONDUCT.md) | Know the community rules |
