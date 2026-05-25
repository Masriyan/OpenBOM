"""Asset and package lookup endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models import Asset, Package, Vulnerability
from server.schemas import AssetOut, PackageOut, VulnerabilityOut

router = APIRouter(prefix="/api/v1", tags=["assets"])


@router.get("/assets", response_model=list[AssetOut])
async def list_assets(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> list[AssetOut]:
    result = await db.execute(
        select(Asset).order_by(Asset.last_seen.desc()).offset(offset).limit(limit)
    )
    return [AssetOut.model_validate(a) for a in result.scalars().all()]


@router.get("/assets/{hostname}", response_model=AssetOut)
async def get_asset(hostname: str, db: AsyncSession = Depends(get_db)) -> AssetOut:
    result = await db.execute(select(Asset).where(Asset.hostname == hostname))
    asset = result.scalar_one_or_none()
    if asset is None:
        raise HTTPException(status_code=404, detail=f"Asset '{hostname}' not found")
    return AssetOut.model_validate(asset)


@router.get("/assets/{hostname}/packages", response_model=list[PackageOut])
async def get_asset_packages(
    hostname: str,
    ecosystem: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
) -> list[PackageOut]:
    result = await db.execute(select(Asset).where(Asset.hostname == hostname))
    asset = result.scalar_one_or_none()
    if asset is None:
        raise HTTPException(status_code=404, detail=f"Asset '{hostname}' not found")
    packages = asset.packages
    if ecosystem:
        packages = [p for p in packages if p.ecosystem.upper() == ecosystem.upper()]
    return [PackageOut.model_validate(p) for p in packages]


@router.get("/assets/{hostname}/vulnerabilities", response_model=list[VulnerabilityOut])
async def get_asset_vulnerabilities(
    hostname: str,
    severity: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
) -> list[VulnerabilityOut]:
    result = await db.execute(select(Asset).where(Asset.hostname == hostname))
    asset = result.scalar_one_or_none()
    if asset is None:
        raise HTTPException(status_code=404, detail=f"Asset '{hostname}' not found")
    vulns: list[Vulnerability] = []
    seen: set[int] = set()
    for pkg in asset.packages:
        for v in pkg.vulnerabilities:
            if v.id not in seen:
                seen.add(v.id)
                if severity is None or v.severity.upper() == severity.upper():
                    vulns.append(v)
    vulns.sort(key=lambda v: v.vuln_id)
    return [VulnerabilityOut.model_validate(v) for v in vulns]
