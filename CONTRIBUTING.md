# Contributing to OpenBOM

Thank you for your interest in contributing to OpenBOM. This project aims to make the software supply
chain more secure, and community contributions are essential to that mission. Please follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## How to contribute

### Reporting bugs

1. Check [existing issues](https://github.com/Masriyan/OpenBOM/issues) to avoid duplicates.
2. Open an issue using the **Bug report** template: steps to reproduce, expected vs. actual behaviour,
   agent/backend version (`python3 agent/openbom_agent.py --version`, `GET /health`), OS and Python version,
   and the relevant part of the debug log (`-v`). Remove hostnames or package lists you consider sensitive.

Security vulnerabilities go to the private channel in [SECURITY.md](SECURITY.md), never to public issues.

### Suggesting features

Use the **Feature request** template: the problem, your proposed solution, alternatives you considered.
Check the [Roadmap](ROADMAP.md) and [market comparison](docs/comparison.md) first.

### Submitting code

1. Fork https://github.com/Masriyan/OpenBOM and branch from `main` (`feature/<topic>` or `fix/<topic>`).
2. Set up the environment and read the [Development Guide](docs/development.md).
3. Make your change **with tests** — the suite must stay green and offline:
   ```bash
   python3 -m pytest
   python3 -m pyflakes agent server tests
   ```
4. For behaviour that depends on live data (a new ecosystem, distro or intel feed), also run the agent
   against the real service once and mention the result in the PR.
5. Update the documentation you touched (README, `docs/`, CHANGELOG under "Unreleased").
6. Open a pull request using the template.

## Code guidelines

- Python 3.12+, type hints throughout, `from __future__ import annotations` at the top of modules.
- Follow the surrounding style; `pyflakes` must be clean (no other linter is enforced).
- **The agent stays a single file** (`agent/openbom_agent.py`) for ease of deployment, and importing it must
  have no side effects (the backend imports it for server-side analysis).
- Backend follows FastAPI conventions: routers, schemas, models in separate files; exposure queries must
  respect triage suppression (`findings_query` / `not_suppressed`).
- New database columns must be nullable (automatic forward migration).
- Console: no build step, no inline scripts, never inject raw HTML; vendored libraries only (update
  `server/static/vendor/LICENSES.md` when changing them).
- Never write caches or state to world-writable locations; never log secrets (webhook URLs, API keys).
- Parsers must tolerate malformed input — log and skip, never abort a scan.

## Areas where help is needed

- Go/Rust binary build-info scanning and Red Hat/Fedora advisory sources (see the [Roadmap](ROADMAP.md))
- More lockfile formats (Swift, Dart/pub, Elixir/mix, Conan)
- Windows/macOS inventory
- Backend notifications and role-based API keys
- Packaging: RPM/DEB, container image, Helm chart
- Documentation, translations and real-world false-positive reports for the heuristic engine

## License

By contributing you agree that your contributions are licensed under the project's [MIT License](LICENSE).
