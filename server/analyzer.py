"""Server-side analysis: reuse the agent's OSV/EPSS/KEV engine for SBOM uploads and continuous re-analysis.

The agent stays a single deployable file; the backend imports it from ../agent so both use the exact
same matching logic. Re-analysis turns stored package inventories back into OSV queries, so newly
published advisories show up without re-running agents (Dependency-Track-style continuous monitoring).
"""

from __future__ import annotations

import asyncio
import importlib.util
import logging
import sys
from functools import lru_cache
from pathlib import Path
from types import ModuleType
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models import Asset, Package, asset_package

log = logging.getLogger("openbom.server")
AGENT_PATH = Path(__file__).resolve().parents[1] / "agent" / "openbom_agent.py"
_LOCK = asyncio.Lock()


@lru_cache(maxsize=1)
def agent() -> ModuleType:
    if "openbom_agent" in sys.modules and getattr(sys.modules["openbom_agent"], "query_osv_batch", None):
        return sys.modules["openbom_agent"]
    spec = importlib.util.spec_from_file_location("openbom_agent", AGENT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load agent from {AGENT_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["openbom_agent"] = module
    spec.loader.exec_module(module)
    return module


def _to_agent_package(pkg: Package) -> Any:
    A = agent()
    osv_eco = pkg.osv_ecosystem or A.LANG_OSV_ECOSYSTEM.get(pkg.ecosystem)
    return A.Package(name=pkg.name, version=pkg.version, ecosystem=pkg.ecosystem, osv_ecosystem=osv_eco,
                     osv_name=pkg.osv_name, osv_version=pkg.osv_version, license=pkg.license)


async def analyze(packages: list[Any], use_cache: bool = True) -> tuple[list[Any], int]:
    """OSV + EPSS + KEV for agent Package objects. Returns (VulnResults, packages actually checked)."""
    from rich.progress import Progress

    A = agent()
    async with _LOCK:  # one analysis at a time: OSV rate limits + shared cache file
        with Progress(disable=True) as progress:
            cache = A.OsvCache() if use_cache else None
            results, enriched = await A.query_osv_batch(packages, progress, progress.add_task("osv"), cache)
            kev = A.KevCatalog()
            await asyncio.gather(kev.load(progress, progress.add_task("kev")),
                                 A.query_epss(results, enriched, progress, progress.add_task("epss")))
            if kev.size:
                A.apply_kev(results, enriched, kev)
    return results, len(results)


def build_payload(hostname: str, packages: list[Any], results: list[Any] | None, scan_target: dict[str, str],
                  os_info: dict[str, str] | None = None, queried: int = 0) -> dict[str, Any]:
    A = agent()
    report = A.build_report(packages, results, None, hostname=hostname, os_info=os_info, queried=queried)
    report.agent_version = f"server-{A.AGENT_VERSION}"
    report.scan_target = scan_target
    return report.to_dict()


async def sbom_payload(document: dict[str, Any], hostname: str | None, run_analysis: bool) -> dict[str, Any]:
    A = agent()
    packages, meta = A.parse_sbom_document(document)
    if not packages:
        raise ValueError("SBOM contains no components with a usable purl")
    name = A.asset_name(hostname or meta.get("name") or "sbom-upload")
    results, queried = (await analyze(packages)) if run_analysis else (None, 0)
    return build_payload(name, packages, results, {"type": "sbom", "ref": meta.get("format", "SBOM")},
                         queried=queried)


async def reanalysis_payload(db: AsyncSession, asset: Asset) -> tuple[dict[str, Any], int]:
    """Rebuild the asset's payload from stored packages and re-run the vulnerability analysis."""
    rows = (await db.execute(
        select(Package).join(asset_package, asset_package.c.package_id == Package.id)
        .where(asset_package.c.asset_id == asset.id)
    )).scalars().all()
    packages = [_to_agent_package(p) for p in rows]
    results, queried = await analyze(packages, use_cache=False)
    target = {"type": asset.target_type or "host", "ref": asset.target_ref or asset.hostname}
    payload = build_payload(asset.hostname, packages, results, target, queried=queried)
    payload["os"] = {"pretty_name": asset.os_name or ""}
    return payload, queried
