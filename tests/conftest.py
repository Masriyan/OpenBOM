from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]

# The server reads DATABASE_URL at import time — point it at a throwaway SQLite file first.
_DB_DIR = tempfile.mkdtemp(prefix="openbom-test-")
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_DB_DIR}/test.db"
os.environ.pop("OPENBOM_API_KEY", None)
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _load_agent() -> ModuleType:
    spec = importlib.util.spec_from_file_location("openbom_agent", ROOT / "agent" / "openbom_agent.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["openbom_agent"] = module
    spec.loader.exec_module(module)
    return module


AGENT = _load_agent()
# Keep agent logs out of the repository (main() would otherwise fall back to ./logs/).
AGENT.DEFAULT_LOG_PATH = Path(_DB_DIR) / "agent.log"
AGENT.FALLBACK_LOG_PATH = Path(_DB_DIR) / "agent-fallback.log"


@pytest.fixture
def agent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """The agent module with its state dir redirected to a private temp dir."""
    state = tmp_path / "state"
    monkeypatch.setenv("OPENBOM_STATE_DIR", str(state))
    return AGENT


@pytest.fixture
async def db_reset() -> AsyncIterator[None]:
    from server.database import engine, init_db
    from server.models import Base

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await init_db()
    yield


@pytest.fixture
async def client(db_reset: None, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    import httpx

    from server.main import app

    monkeypatch.delenv("OPENBOM_API_KEY", raising=False)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        yield c


def make_payload(
    hostname: str = "web-01",
    packages: list[tuple[str, str, str]] | None = None,
    findings: list[dict] | None = None,
    **extra: object,
) -> dict:
    pkgs = packages if packages is not None else [
        ("requests", "2.19.0", "PyPI"), ("openssl", "3.0.1-41.el9_0", "RPM"), ("lodash", "4.17.15", "NPM"),
    ]
    payload = {
        "hostname": hostname,
        "scan_ts": "2026-10-01T10:00:00+00:00",
        "agent_version": "5.0.0",
        "os": {"id": "almalinux", "version_id": "9.4", "pretty_name": "AlmaLinux 9.4", "osv_ecosystem": "AlmaLinux:9"},
        "total_packages": len(pkgs),
        "packages": [{"name": n, "version": v, "ecosystem": e, "diff_label": None} for n, v, e in pkgs],
        "osv_summary": {"queried": len(pkgs), "vulnerable": len(findings or []), "kev_hits": 0, "poc_count": 0,
                        "total_critical": 0, "total_high": 0, "total_medium": 0, "total_low": 0, "total_unknown": 0},
        "osv_vulnerabilities": findings or [],
    }
    payload.update(extra)
    return payload


def finding(name: str, version: str, ecosystem: str, *vulns: dict) -> dict:
    return {"package": {"name": name, "version": version, "ecosystem": ecosystem, "diff_label": None},
            "max_severity": "UNKNOWN", "vulns": list(vulns)}


def vuln(vuln_id: str, severity: str = "HIGH", **kw: object) -> dict:
    base = {"vuln_id": vuln_id, "severity": severity, "summary": f"{vuln_id} summary",
            "fixed_version": None, "recommendation": "Upgrade", "epss_score": None, "epss_percentile": None,
            "is_kev": False, "kev_description": None, "poc_links": []}
    base.update(kw)
    return base
