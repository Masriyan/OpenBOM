"""Asset and package lookup endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models import Asset, Package, ScanRecord, asset_package
from server.queries import (
    affected_out,
    asset_detail,
    asset_stats,
    findings_query,
    get_asset_or_none,
    triage_states,
    vuln_sort_key,
)
from server.sbom import asset_cyclonedx
from server.schemas import (
    AffectedPackageOut,
    AssetDetailOut,
    AssetStatsOut,
    AssetVulnerabilityOut,
    PackageOut,
    ScanOut,
    VulnerabilityOut,
)
from server.security import require_api_key

router = APIRouter(prefix="/api/v1", tags=["assets"], dependencies=[Depends(require_api_key)])

SORTS = {"risk", "hostname", "last_seen", "packages"}


async def _asset_or_404(db: AsyncSession, hostname: str) -> Asset:
    asset = await get_asset_or_none(db, hostname)
    if asset is None:
        raise HTTPException(status_code=404, detail=f"Asset '{hostname}' not found")
    return asset


@router.get("/assets", response_model=list[AssetStatsOut])
async def list_assets(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    q: str | None = Query(None, description="Hostname substring filter"),
    sort: str = Query("last_seen", description="risk | hostname | last_seen | packages"),
    db: AsyncSession = Depends(get_db),
) -> list[AssetStatsOut]:
    if sort not in SORTS:
        raise HTTPException(status_code=422, detail=f"sort must be one of {sorted(SORTS)}")
    stmt = select(Asset)
    if q:
        stmt = stmt.where(Asset.hostname.ilike(f"%{q}%"))
    if sort in ("hostname", "last_seen"):
        order = Asset.hostname.asc() if sort == "hostname" else Asset.last_seen.desc()
        assets = (await db.execute(stmt.order_by(order).offset(offset).limit(limit))).scalars().all()
        return await asset_stats(db, assets)
    # risk / packages are computed — sort in Python, then page
    stats = await asset_stats(db, (await db.execute(stmt)).scalars().all())
    key = (lambda a: (-a.risk_score, a.hostname)) if sort == "risk" else (lambda a: (-a.package_count, a.hostname))
    return sorted(stats, key=key)[offset: offset + limit]


@router.get("/assets/{hostname}", response_model=AssetDetailOut)
async def get_asset(hostname: str, db: AsyncSession = Depends(get_db)) -> AssetDetailOut:
    return await asset_detail(db, await _asset_or_404(db, hostname))


@router.delete("/assets/{hostname}", status_code=204)
async def delete_asset(hostname: str, db: AsyncSession = Depends(get_db)) -> Response:
    """Decommission an asset: removes its package links and scan history (packages/vulns stay for other hosts)."""
    asset = await _asset_or_404(db, hostname)
    await db.execute(delete(asset_package).where(asset_package.c.asset_id == asset.id))
    await db.execute(delete(ScanRecord).where(ScanRecord.asset_id == asset.id))
    await db.execute(delete(Asset).where(Asset.id == asset.id))
    await db.commit()
    return Response(status_code=204)


@router.get("/assets/{hostname}/packages", response_model=list[PackageOut])
async def get_asset_packages(
    hostname: str,
    ecosystem: str | None = Query(None),
    q: str | None = Query(None, description="Package name substring filter"),
    limit: int = Query(5000, ge=1, le=100000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> list[PackageOut]:
    asset = await _asset_or_404(db, hostname)
    stmt = (select(Package).join(asset_package, asset_package.c.package_id == Package.id)
            .where(asset_package.c.asset_id == asset.id))
    if ecosystem:
        stmt = stmt.where(Package.ecosystem.ilike(ecosystem))
    if q:
        stmt = stmt.where(Package.name.ilike(f"%{q}%"))
    rows = (await db.execute(stmt.order_by(Package.ecosystem, Package.name).offset(offset).limit(limit))).scalars()
    return [PackageOut.model_validate(p) for p in rows]


@router.get("/assets/{hostname}/vulnerabilities", response_model=list[AssetVulnerabilityOut])
async def get_asset_vulnerabilities(
    hostname: str,
    severity: str | None = Query(None),
    kev: bool | None = Query(None),
    heuristic: bool | None = Query(None),
    include_suppressed: bool = Query(False),
    db: AsyncSession = Depends(get_db),
) -> list[AssetVulnerabilityOut]:
    asset = await _asset_or_404(db, hostname)
    rows = (await db.execute(findings_query(Asset.id == asset.id, include_suppressed=include_suppressed))).all()
    grouped: dict[int, tuple[Any, list[AffectedPackageOut]]] = {}
    for _asset, pkg, vuln, fixed, rec in rows:
        if severity and (vuln.severity or "").upper() != severity.upper():
            continue
        if kev is not None and vuln.is_kev != kev:
            continue
        if heuristic is not None and vuln.is_heuristic != heuristic:
            continue
        grouped.setdefault(vuln.id, (vuln, []))[1].append(affected_out(pkg, fixed, rec))
    states = await triage_states(db, grouped.keys(), asset.id)
    out = [
        AssetVulnerabilityOut(**{**VulnerabilityOut.model_validate(v).model_dump(), "triage_state": states.get(v.id)},
                              affected_packages=pkgs)
        for v, pkgs in grouped.values()
    ]
    out.sort(key=vuln_sort_key)
    return out


@router.get("/assets/{hostname}/scans", response_model=list[ScanOut])
async def get_asset_scans(
    hostname: str, limit: int = Query(50, ge=1, le=1000), db: AsyncSession = Depends(get_db),
) -> list[ScanOut]:
    asset = await _asset_or_404(db, hostname)
    rows = (await db.execute(
        select(ScanRecord).where(ScanRecord.asset_id == asset.id)
        .order_by(ScanRecord.received_at.desc()).limit(limit)
    )).scalars()
    return [ScanOut.model_validate(r) for r in rows]


@router.get("/assets/{hostname}/sbom")
async def get_asset_sbom(hostname: str, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """CycloneDX 1.5 JSON SBOM (with vulnerabilities) for the asset's current package snapshot."""
    asset = await _asset_or_404(db, hostname)
    return await asset_cyclonedx(db, asset)

