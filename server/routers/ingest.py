"""POST /api/v1/ingest — receive and persist agent scan payloads."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models import Asset, Package, Vulnerability, asset_package, package_vulnerability
from server.schemas import AgentPayload, IngestResponse

router = APIRouter(prefix="/api/v1", tags=["ingest"])


async def _upsert_asset(db: AsyncSession, hostname: str, scan_ts: str, summary_json: str | None) -> Asset:
    result = await db.execute(select(Asset).where(Asset.hostname == hostname))
    asset = result.scalar_one_or_none()
    if asset is None:
        asset = Asset(hostname=hostname, last_seen=datetime.now(timezone.utc), last_scan_summary=summary_json)
        db.add(asset)
        await db.flush()
    else:
        asset.last_seen = datetime.now(timezone.utc)
        asset.last_scan_summary = summary_json
    return asset


async def _get_or_create_package(db: AsyncSession, name: str, version: str, ecosystem: str) -> Package:
    result = await db.execute(
        select(Package).where(
            Package.name == name, Package.version == version, Package.ecosystem == ecosystem,
        )
    )
    pkg = result.scalar_one_or_none()
    if pkg is None:
        pkg = Package(name=name, version=version, ecosystem=ecosystem)
        db.add(pkg)
        await db.flush()
    return pkg


async def _get_or_create_vuln(db: AsyncSession, vuln_id: str, **kwargs: object) -> Vulnerability:
    result = await db.execute(select(Vulnerability).where(Vulnerability.vuln_id == vuln_id))
    vuln = result.scalar_one_or_none()
    if vuln is None:
        vuln = Vulnerability(vuln_id=vuln_id, **kwargs)
        db.add(vuln)
        await db.flush()
    else:
        for k, v in kwargs.items():
            if v is not None:
                setattr(vuln, k, v)
    return vuln


async def _link_asset_package(
    db: AsyncSession, asset_id: int, package_id: int, diff_label: str | None, scan_ts: datetime,
) -> None:
    existing = await db.execute(
        select(asset_package).where(
            asset_package.c.asset_id == asset_id,
            asset_package.c.package_id == package_id,
        )
    )
    if existing.first() is None:
        await db.execute(
            asset_package.insert().values(
                asset_id=asset_id, package_id=package_id,
                diff_label=diff_label, scan_ts=scan_ts,
            )
        )
    else:
        await db.execute(
            asset_package.update()
            .where(asset_package.c.asset_id == asset_id, asset_package.c.package_id == package_id)
            .values(diff_label=diff_label, scan_ts=scan_ts)
        )


async def _link_package_vuln(db: AsyncSession, package_id: int, vuln_id: int) -> None:
    existing = await db.execute(
        select(package_vulnerability).where(
            package_vulnerability.c.package_id == package_id,
            package_vulnerability.c.vulnerability_id == vuln_id,
        )
    )
    if existing.first() is None:
        await db.execute(
            package_vulnerability.insert().values(package_id=package_id, vulnerability_id=vuln_id)
        )


@router.post("/ingest", response_model=IngestResponse)
async def ingest_scan(payload: AgentPayload, db: AsyncSession = Depends(get_db)) -> IngestResponse:
    scan_time = datetime.now(timezone.utc)
    summary_json = payload.osv_summary.model_dump_json() if payload.osv_summary else None

    asset = await _upsert_asset(db, payload.hostname, payload.scan_ts, summary_json)

    # --- Process packages ---
    pkg_cache: dict[str, Package] = {}
    for p in payload.packages:
        key = f"{p.ecosystem}::{p.name}::{p.version}"
        if key not in pkg_cache:
            pkg_obj = await _get_or_create_package(db, p.name, p.version, p.ecosystem)
            pkg_cache[key] = pkg_obj
        await _link_asset_package(db, asset.id, pkg_cache[key].id, p.diff_label, scan_time)

    # --- Process vulnerabilities ---
    vuln_count = 0
    for finding in payload.osv_vulnerabilities or []:
        fp = finding.package
        pkg_key = f"{fp.ecosystem}::{fp.name}::{fp.version}"
        if pkg_key not in pkg_cache:
            pkg_obj = await _get_or_create_package(db, fp.name, fp.version, fp.ecosystem)
            pkg_cache[pkg_key] = pkg_obj
            await _link_asset_package(db, asset.id, pkg_obj.id, fp.diff_label, scan_time)

        pkg_obj = pkg_cache[pkg_key]

        for v in finding.vulns:
            is_heuristic = v.vuln_id == "MALICIOUS_HEURISTIC"
            vuln_obj = await _get_or_create_vuln(
                db,
                vuln_id=v.vuln_id if not is_heuristic else f"MALICIOUS_HEURISTIC::{fp.name}",
                severity=v.severity,
                summary=v.summary,
                fixed_version=v.fixed_version,
                recommendation=v.recommendation,
                epss_score=v.epss_score,
                epss_percentile=v.epss_percentile,
                is_kev=v.is_kev,
                kev_description=v.kev_description,
                is_heuristic=is_heuristic,
                poc_links=json.dumps(v.poc_links) if v.poc_links else None,
            )
            await _link_package_vuln(db, pkg_obj.id, vuln_obj.id)
            vuln_count += 1

    await db.commit()

    return IngestResponse(
        status="ok",
        hostname=payload.hostname,
        packages_processed=len(pkg_cache),
        vulnerabilities_linked=vuln_count,
    )
