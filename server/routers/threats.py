"""Threat hunting query endpoints."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.config import get_settings
from server.database import get_db
from server.models import (
    SUPPRESSED_STATES,
    Asset,
    Package,
    ScanRecord,
    Triage,
    Vulnerability,
    as_utc,
    asset_package,
    package_vulnerability,
)
from server.queries import asset_stats, not_suppressed, threat_assets, vuln_filters
from server.schemas import ThreatAssetOut
from server.security import require_api_key

def _count_by(values: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return out


router = APIRouter(prefix="/api/v1/threats", tags=["threats"], dependencies=[Depends(require_api_key)])


@router.get("/kev", response_model=list[ThreatAssetOut])
async def get_kev_threats(db: AsyncSession = Depends(get_db)) -> list[ThreatAssetOut]:
    """Assets with packages affected by CISA Known Exploited Vulnerabilities."""
    return await threat_assets(db, vuln_filters(is_kev=True))


@router.get("/heuristics", response_model=list[ThreatAssetOut])
async def get_heuristic_threats(db: AsyncSession = Depends(get_db)) -> list[ThreatAssetOut]:
    """Assets with heuristic malware / typosquat detections."""
    return await threat_assets(db, vuln_filters(is_heuristic=True))


@router.get("/malicious", response_model=list[ThreatAssetOut])
async def get_malicious_threats(db: AsyncSession = Depends(get_db)) -> list[ThreatAssetOut]:
    """Assets with known-malicious packages (OpenSSF malicious-packages advisories, OSV MAL-*)."""
    return await threat_assets(db, vuln_filters(is_malicious=True))


@router.get("/critical", response_model=list[ThreatAssetOut])
async def get_critical_threats(db: AsyncSession = Depends(get_db)) -> list[ThreatAssetOut]:
    """Assets with CRITICAL-severity vulnerabilities."""
    return await threat_assets(db, vuln_filters(severity="CRITICAL"))


@router.get("/high-epss", response_model=list[ThreatAssetOut])
async def get_high_epss_threats(
    min_score: float = Query(0.1, ge=0.0, le=1.0, description="Minimum EPSS score (0.0-1.0)"),
    db: AsyncSession = Depends(get_db),
) -> list[ThreatAssetOut]:
    """Assets with vulnerabilities above the given EPSS exploit probability threshold."""
    return await threat_assets(db, vuln_filters(min_epss=min_score))


@router.get("/summary")
async def get_threat_summary(db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """Fleet-wide statistics. Counts only exposure that is currently installed on at least one asset."""
    exposure = (
        select(Vulnerability.id, Vulnerability.severity, Vulnerability.is_kev, Vulnerability.is_heuristic,
               Vulnerability.is_malicious)
        .join(package_vulnerability, package_vulnerability.c.vulnerability_id == Vulnerability.id)
        .join(asset_package, asset_package.c.package_id == package_vulnerability.c.package_id)
        .where(not_suppressed())
        .distinct()
        .subquery()
    )
    total_assets = (await db.execute(select(func.count(Asset.id)))).scalar() or 0
    total_packages = (await db.execute(select(func.count(distinct(asset_package.c.package_id))))).scalar() or 0
    total_vulns = (await db.execute(select(func.count()).select_from(exposure))).scalar() or 0
    kev_count = (await db.execute(
        select(func.count()).select_from(exposure).where(exposure.c.is_kev.is_(True)))).scalar() or 0
    heuristic_count = (await db.execute(
        select(func.count()).select_from(exposure).where(exposure.c.is_heuristic.is_(True)))).scalar() or 0
    malicious_count = (await db.execute(
        select(func.count()).select_from(exposure).where(exposure.c.is_malicious.is_(True)))).scalar() or 0
    suppressed_count = (await db.execute(select(func.count(Triage.id)).where(
        Triage.state.in_(SUPPRESSED_STATES)))).scalar() or 0
    severity_breakdown = {
        (sev or "UNKNOWN").upper(): n
        for sev, n in (await db.execute(
            select(exposure.c.severity, func.count()).group_by(exposure.c.severity))).all()
    }
    ecosystem_breakdown = dict((await db.execute(
        select(Package.ecosystem, func.count(distinct(Package.id)))
        .join(asset_package, asset_package.c.package_id == Package.id)
        .group_by(Package.ecosystem)
    )).all())

    cutoff = datetime.now(timezone.utc) - timedelta(days=get_settings().stale_days)
    stale_assets = (await db.execute(select(func.count(Asset.id)).where(Asset.last_seen < cutoff))).scalar() or 0

    assets = (await db.execute(select(Asset))).scalars().all()
    stats = sorted(await asset_stats(db, assets), key=lambda a: (-a.risk_score, a.hostname))
    recent = (await db.execute(
        select(ScanRecord, Asset.hostname).join(Asset, Asset.id == ScanRecord.asset_id)
        .order_by(ScanRecord.received_at.desc()).limit(10)
    )).all()

    return {
        "total_assets": total_assets,
        "total_packages": total_packages,
        "total_vulnerabilities": total_vulns,
        "kev_vulnerabilities": kev_count,
        "heuristic_detections": heuristic_count,
        "malicious_packages": malicious_count,
        "suppressed_decisions": suppressed_count,
        "eol_assets": sum(1 for a in stats if any(e.get("is_eol") for e in a.eol)),
        "license_violations": sum(a.license_violation_count for a in stats),
        "target_breakdown": _count_by(a.target_type or "host" for a in stats),
        "critical_vulnerabilities": severity_breakdown.get("CRITICAL", 0),
        "severity_breakdown": severity_breakdown,
        "ecosystem_breakdown": ecosystem_breakdown,
        "stale_assets": stale_assets,
        "stale_after_days": get_settings().stale_days,
        "top_risky_assets": [
            {"hostname": a.hostname, "risk_score": a.risk_score, "kev_count": a.kev_count,
             "heuristic_count": a.heuristic_count, "malicious_count": a.malicious_count,
             "critical": a.severity_counts.get("CRITICAL", 0), "target_type": a.target_type or "host"}
            for a in stats[:5] if a.vulnerability_count
        ],
        "recent_scans": [
            {"hostname": host, "received_at": as_utc(rec.received_at), "total_packages": rec.total_packages,
             "source": rec.source or "agent",
             "critical": rec.critical, "high": rec.high, "kev_hits": rec.kev_hits,
             "heuristic_hits": rec.heuristic_hits}
            for rec, host in recent
        ],
    }
