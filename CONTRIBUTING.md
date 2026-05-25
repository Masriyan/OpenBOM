# Contributing to OpenBOM

Thank you for your interest in contributing to OpenBOM. This project aims to make the software supply chain more secure, and community contributions are essential to that mission.

## How to Contribute

### Reporting Bugs

1. Check [existing issues](https://github.com/Masriyan/OpenBOM/issues) to avoid duplicates
2. Open a new issue with:
   - A clear title describing the bug
   - Steps to reproduce
   - Expected vs. actual behavior
   - Your OS, Python version, and relevant package versions

### Suggesting Features

Open an issue with the `enhancement` label. Describe:
- The problem you're trying to solve
- Your proposed solution
- Alternative approaches you've considered

### Submitting Code

1. Fork the repository at https://github.com/Masriyan/OpenBOM
2. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature
   ```
3. Make your changes
4. Test locally:
   ```bash
   # Agent
   python3 agent/openbom_agent.py --scan-only
   python3 agent/openbom_agent.py --check-osv --diff

   # Backend
   uvicorn server.main:app --reload
   curl -X POST http://localhost:8000/api/v1/ingest -H "Content-Type: application/json" -d @output/your_scan.json
   ```
5. Commit with a descriptive message
6. Push and open a Pull Request

## Development Setup

```bash
git clone https://github.com/Masriyan/OpenBOM.git
cd OpenBOM

# Install all dependencies
pip install httpx rich jinja2 weasyprint
pip install fastapi uvicorn sqlalchemy aiosqlite

# Run the backend in dev mode
uvicorn server.main:app --reload

# Run the agent
python3 agent/openbom_agent.py --check-osv --diff --report
```

## Code Guidelines

- Python 3.12+ with type hints throughout
- Use `from __future__ import annotations` for forward references
- Follow existing code style — no linter configuration is enforced, but consistency matters
- Keep the agent as a single file (`openbom_agent.py`) for ease of deployment
- Backend follows FastAPI conventions: routers, schemas, models in separate files

## Areas Where Help Is Needed

- **Ecosystem expansion**: Adding support for Go modules, Cargo (Rust), Maven (Java)
- **Container scanning**: Extending Podman support to Docker, and adding image layer analysis
- **NVD integration**: Direct NVD API queries as a fallback when OSV data is sparse
- **Dashboard**: A web frontend for the backend API
- **Authentication**: API key or OAuth2 middleware for the backend
- **Testing**: Unit tests for the agent extraction functions and backend routes
- **Packaging**: RPM/DEB packages, Docker images, Helm charts

## Code of Conduct

Be respectful, constructive, and professional. We're all here to make software safer.
