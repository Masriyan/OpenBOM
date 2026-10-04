"""Fleet-wide hunting: package search, vulnerability listing/detail, maintenance."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import delete, distinct, exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models import Asset, Package, Vulnerability, asset_package, package_vulnerability
from server.queries import (
    SEVERITY_ORDER,
    affected_out,
    findings_query,
    not_suppressed,
    triage_states,
    vuln_filters,
    vuln_sort_key,
)
from server.schemas import (
    AffectedAssetOut,
    PackageHostsOut,
    PackageOut,
    PruneResponse,
    VulnerabilityDetailOut,
    VulnerabilityListOut,
    VulnerabilityOut,
)
from server.security import require_api_key

router = APIRouter(prefix="/api/v1", tags=["hunt"], dependencies=[Depends(require_api_key)])


@router.get("/packages/search", response_model=list[PackageHostsOut])
async def search_packages(
    name: str = Query(..., min_length=1, description="Package name (substring unless exact=true)"),
    version: str | None = Query(None, description="Exact version filter"),
    ecosystem: str | None = Query(None),
    exact: bool = Query(False),
    limit: int = Query(200, ge=1, le=2000),
    db: AsyncSession = Depends(get_db),
) -> list[PackageHostsOut]:
    """Which hosts have package X (optionally version Y) installed right now?"""
    stmt = (select(Package, Asset.hostname)
            .join(asset_package, asset_package.c.package_id == Package.id)
            .join(Asset, Asset.id == asset_package.c.asset_id))
    stmt = stmt.where(func.lower(Package.name) == name.lower()) if exact else stmt.where(Package.name.ilike(f"%{name}%"))
    if version:
        stmt = stmt.where(Package.version == version)
    if ecosystem:
        stmt = stmt.where(Package.ecosystem.ilike(ecosystem))
    rows = (await db.execute(stmt.order_by(Package.name, Package.version))).all()

    grouped: dict[int, tuple[Package, list[str]]] = {}
    for pkg, host in rows:
        grouped.setdefault(pkg.id, (pkg, []))[1].append(host)
    pkg_ids = list(grouped)[:limit]

    vuln_info: dict[int, list[str]] = {}
    if pkg_ids:
        for pid, sev in (await db.execute(
            select(package_vulnerability.c.package_id, Vulnerability.severity)
            .join(Vulnerability, Vulnerability.id == package_vulnerability.c.vulnerability_id)
            .where(package_vulnerability.c.package_id.in_(pkg_ids))
        )).all():
            vuln_info.setdefault(pid, []).append((sev or "UNKNOWN").upper())

    out: list[PackageHostsOut] = []
    for pid in pkg_ids:
        pkg, hosts = grouped[pid]
        sevs = vuln_info.get(pid, [])
        out.append(PackageHostsOut(
            package=PackageOut.model_validate(pkg),
            hosts=sorted(set(hosts)),
            vulnerability_count=len(sevs),
            max_severity=min(sevs, key=lambda s: SEVERITY_ORDER.get(s, 9)) if sevs else None,
        ))
    return out


@router.get("/vulnerabilities", response_model=list[VulnerabilityListOut])
async def list_vulnerabilities(
    severity: str | None = Query(None),
    kev: bool | None = Query(None),
    heuristic: bool | None = Query(None),
    min_epss: float | None = Query(None, ge=0.0, le=1.0),
    malicious: bool | None = Query(None),
    include_suppressed: bool = Query(False, description="Include findings triaged as not_affected/false_positive"),
    q: str | None = Query(None, description="Search vuln id, CVE or summary"),
    limit: int = Query(200, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> list[VulnerabilityListOut]:
    """Vulnerabilities currently present on at least one asset, highest risk first."""
    filters: list[Any] = vuln_filters(is_kev=kev, is_heuristic=heuristic, min_epss=min_epss, severity=severity,
                                      is_malicious=malicious)
    if not include_suppressed:
        filters.append(not_suppressed())
    if q:
        like = f"%{q}%"
        filters.append(or_(Vulnerability.vuln_id.ilike(like), Vulnerability.summary.ilike(like),
                           Vulnerability.cves.ilike(like)))
    stmt = (
        select(Vulnerability,
               func.count(distinct(asset_package.c.asset_id)),
               func.count(distinct(package_vulnerability.c.package_id)))
        .join(package_vulnerability, package_vulnerability.c.vulnerability_id == Vulnerability.id)
        .join(asset_package, asset_package.c.package_id == package_vulnerability.c.package_id)
        .where(*filters)
        .group_by(Vulnerability.id)
    )
    rows = (await db.execute(stmt)).all()
    rows.sort(key=lambda r: vuln_sort_key(r[0]))
    page = rows[offset: offset + limit]
    states = await triage_states(db, [v.id for v, *_ in page])
    return [
        VulnerabilityListOut(**{**VulnerabilityOut.model_validate(v).model_dump(), "triage_state": states.get(v.id)},
                             affected_assets=n_assets, affected_packages=n_pkgs)
        for v, n_assets, n_pkgs in page
    ]


@router.get("/vulnerabilities/{vuln_id:path}", response_model=VulnerabilityDetailOut)
async def get_vulnerability(vuln_id: str, db: AsyncSession = Depends(get_db)) -> VulnerabilityDetailOut:
    vuln = (await db.execute(select(Vulnerability).where(Vulnerability.vuln_id == vuln_id))).scalar_one_or_none()
    if vuln is None:
        raise HTTPException(status_code=404, detail=f"Vulnerability '{vuln_id}' not found")
    rows = (await db.execute(findings_query(Vulnerability.id == vuln.id, include_suppressed=True)
                             .order_by(Asset.hostname))).all()
    state = (await triage_states(db, [vuln.id])).get(vuln.id)
    return VulnerabilityDetailOut(
        vulnerability=VulnerabilityOut.model_validate(vuln).model_copy(update={"triage_state": state}),
        affected=[AffectedAssetOut(hostname=a.hostname, package=affected_out(p, fixed, rec))
                  for a, p, _v, fixed, rec in rows],
    )


@router.post("/maintenance/prune", response_model=PruneResponse)
async def prune_orphans(db: AsyncSession = Depends(get_db)) -> PruneResponse:
    """Delete packages no asset has installed and vulnerabilities no package references."""
    orphan_pkgs = select(Package.id).where(~exists().where(asset_package.c.package_id == Package.id))
    pkg_ids = (await db.execute(orphan_pkgs)).scalars().all()
    for i in range(0, len(pkg_ids), 400):
        chunk = pkg_ids[i: i + 400]
        await db.execute(delete(package_vulnerability).where(package_vulnerability.c.package_id.in_(chunk)))
        await db.execute(delete(Package).where(Package.id.in_(chunk)))
    orphan_vulns = select(Vulnerability.id).where(
        ~exists().where(package_vulnerability.c.vulnerability_id == Vulnerability.id))
    vuln_ids = (await db.execute(orphan_vulns)).scalars().all()
    for i in range(0, len(vuln_ids), 400):
        await db.execute(delete(Vulnerability).where(Vulnerability.id.in_(vuln_ids[i: i + 400])))
    await db.commit()
    return PruneResponse(packages_deleted=len(pkg_ids), vulnerabilities_deleted=len(vuln_ids))
