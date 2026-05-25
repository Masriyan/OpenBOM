# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in OpenBOM, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email: **riyan.pratama@security-life.org** (or open a private security advisory at https://github.com/Masriyan/OpenBOM/security/advisories/new)

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

We will acknowledge receipt within 48 hours and provide a timeline for resolution.

## Scope

This policy applies to:
- The OpenBOM endpoint agent (`agent/openbom_agent.py`)
- The OpenBOM backend server (`server/`)
- The HTML report template (`agent/templates/`)

## Security Design Principles

### Agent
- Runs as an unprivileged user (no root required for most features)
- Makes only outbound HTTPS connections (osv.dev, first.org, cisa.gov)
- Does not listen on any ports
- Does not transmit system secrets, credentials, or file contents
- Heuristic scanner reads only package source files — never executes them
- Cache files in `/tmp/` contain only public vulnerability data

### Backend
- No built-in authentication (must be added for production — see [deployment guide](docs/deployment.md))
- Input validation via Pydantic on all endpoints
- Parameterized queries via SQLAlchemy (no raw SQL)
- CORS is permissive by default — restrict `allow_origins` in production

## Supported Versions

| Version | Supported |
|---------|-----------|
| v4.x (current) | Yes |
| < v4 | No |
