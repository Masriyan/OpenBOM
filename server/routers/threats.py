"""Threat hunting query endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from server.database import get_db
from server.models import Asset, Package, Vulnerability, asset_package, package_vulnerability
from server.schemas import (
    AssetOut,
    PackageOut,
    ThreatAssetOut,
    ThreatFindingOut,
    VulnerabilityOut,
)

router = APIRouter(prefix="/api/v1/threats", tags=["threats"])


async def _assets_by_vuln_filter(
    db: AsyncSession,
    is_kev: bool | None = None,
    is_heuristic: bool | None = None,
    min_epss: float | None = None,
    severity: str | None = None,
) -> list[ThreatAssetOut]:
    """Shared query: find assets linked to vulns matching the given filters."""

    vuln_q = select(Vulnerability)
    if is_kev is not None:
        vuln_q = vuln_q.where(Vulnerability.is_kev == is_kev)
    if is_heuristic is not None:
        vuln_q = vuln_q.where(Vulnerability.is_heuristic == is_heuristic)
    if min_epss is not None:
        vuln_q = vuln_q.where(Vulnerability.epss_score >= min_epss)
    if severity is not None:
        vuln_q = vuln_q.where(func.upper(Vulnerability.severity) == severity.upper())

    vuln_result = await db.execute(vuln_q)
    vulns = vuln_result.scalars().all()
    if not vulns:
        return []

    # For each vuln, walk package -> asset relations
    # Build: asset_id -> { vuln_id -> [package_ids] }
    asset_map: dict[int, dict[int, list[Package]]] = {}
    vuln_lookup: dict[int, Vulnerability] = {v.id: v for v in vulns}

    for vuln in vulns:
        for pkg in vuln.packages:
            for asset in pkg.assets:
                asset_map.setdefault(asset.id, {}).setdefault(vuln.id, []).append(pkg)

    # Fetch full asset objects
    if not asset_map:
        return []
    asset_result = await db.execute(select(Asset).where(Asset.id.in_(asset_map.keys())))
    assets = {a.id: a for a in asset_result.scalars().all()}

    output: list[ThreatAssetOut] = []
    for asset_id, vuln_pkg_map in asset_map.items():
        asset = assets.get(asset_id)
        if not asset:
            continue
        findings: list[ThreatFindingOut] = []
        for vuln_id, pkgs in vuln_pkg_map.items():
            vuln = vuln_lookup[vuln_id]
            findings.append(ThreatFindingOut(
                vulnerability=VulnerabilityOut.model_validate(vuln),
                affected_packages=[PackageOut.model_validate(p) for p in pkgs],
            ))
        findings.sort(key=lambda f: f.vulnerability.vuln_id)
        output.append(ThreatAssetOut(asset=AssetOut.model_validate(asset), findings=findings))

    output.sort(key=lambda a: a.asset.hostname)
    return output


@router.get("/kev", response_model=list[ThreatAssetOut])
async def get_kev_threats(db: AsyncSession = Depends(get_db)) -> list[ThreatAssetOut]:
    """Assets with packages affected by CISA Known Exploited Vulnerabilities."""
    return await _assets_by_vuln_filter(db, is_kev=True)


@router.get("/heuristics", response_model=list[ThreatAssetOut])
async def get_heuristic_threats(db: AsyncSession = Depends(get_db)) -> list[ThreatAssetOut]:
    """Assets with heuristic malware detections (MALICIOUS_HEURISTIC)."""
    return await _assets_by_vuln_filter(db, is_heuristic=True)


@router.get("/critical", response_model=list[ThreatAssetOut])
async def get_critical_threats(db: AsyncSession = Depends(get_db)) -> list[ThreatAssetOut]:
    """Assets with CRITICAL-severity vulnerabilities."""
    return await _assets_by_vuln_filter(db, severity="CRITICAL")


@router.get("/high-epss", response_model=list[ThreatAssetOut])
async def get_high_epss_threats(
    min_score: float = Query(0.1, ge=0.0, le=1.0, description="Minimum EPSS score (0.0-1.0)"),
    db: AsyncSession = Depends(get_db),
) -> list[ThreatAssetOut]:
    """Assets with vulnerabilities above the given EPSS exploit probability threshold."""
    return await _assets_by_vuln_filter(db, min_epss=min_score)


@router.get("/summary")
async def get_threat_summary(db: AsyncSession = Depends(get_db)) -> dict:
    """Aggregate threat statistics across all assets."""
    total_assets = (await db.execute(select(func.count(Asset.id)))).scalar() or 0
    total_packages = (await db.execute(select(func.count(Package.id)))).scalar() or 0
    total_vulns = (await db.execute(select(func.count(Vulnerability.id)))).scalar() or 0
    kev_count = (await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.is_kev == True)
    )).scalar() or 0
    heuristic_count = (await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.is_heuristic == True)
    )).scalar() or 0
    critical_count = (await db.execute(
        select(func.count(Vulnerability.id)).where(func.upper(Vulnerability.severity) == "CRITICAL")
    )).scalar() or 0

    sev_result = await db.execute(
        select(Vulnerability.severity, func.count(Vulnerability.id)).group_by(Vulnerability.severity)
    )
    severity_breakdown = {row[0]: row[1] for row in sev_result.all()}

    return {
        "total_assets": total_assets,
        "total_packages": total_packages,
        "total_vulnerabilities": total_vulns,
        "kev_vulnerabilities": kev_count,
        "heuristic_detections": heuristic_count,
        "critical_vulnerabilities": critical_count,
        "severity_breakdown": severity_breakdown,
    }
