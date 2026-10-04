"""Shared read queries: findings joins, per-asset stats and risk scoring."""

from __future__ import annotations

import json
import math
from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import Select, exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.config import get_settings
from server.models import (
    SUPPRESSED_STATES,
    Asset,
    Package,
    Triage,
    Vulnerability,
    as_utc,
    asset_package,
    package_vulnerability,
)
from server.schemas import (
    AffectedPackageOut,
    AssetDetailOut,
    AssetOut,
    AssetStatsOut,
    PackageOut,
    ThreatAssetOut,
    ThreatFindingOut,
    VulnerabilityOut,
)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
SEVERITY_WEIGHT = {"CRITICAL": 10.0, "HIGH": 6.0, "MEDIUM": 3.0, "LOW": 1.0, "UNKNOWN": 1.0}


def not_suppressed(asset_id_col: Any = None) -> Any:
    """SQL predicate: no not_affected/false_positive triage covers this vuln (fleet-wide or for this asset)."""
    asset_col = asset_package.c.asset_id if asset_id_col is None else asset_id_col
    return ~exists().where(
        Triage.vulnerability_id == Vulnerability.id,
        Triage.state.in_(SUPPRESSED_STATES),
        or_(Triage.asset_id.is_(None), Triage.asset_id == asset_col),
    )


def findings_query(*filters: Any, include_suppressed: bool = False) -> Select[Any]:
    """(Asset, Package, Vulnerability, fixed_version, recommendation, location) rows for current host↔vuln exposure."""
    if not include_suppressed:
        filters = (*filters, not_suppressed())
    return (
        select(
            Asset, Package, Vulnerability,
            package_vulnerability.c.fixed_version, package_vulnerability.c.recommendation,
            asset_package.c.location,
        )
        .join(asset_package, asset_package.c.asset_id == Asset.id)
        .join(Package, Package.id == asset_package.c.package_id)
        .join(package_vulnerability, package_vulnerability.c.package_id == Package.id)
        .join(Vulnerability, Vulnerability.id == package_vulnerability.c.vulnerability_id)
        .where(*filters)
    )


def vuln_filters(
    *,
    is_kev: bool | None = None,
    is_heuristic: bool | None = None,
    min_epss: float | None = None,
    severity: str | None = None,
    is_malicious: bool | None = None,
) -> list[Any]:
    out: list[Any] = []
    if is_malicious is not None:
        out.append(Vulnerability.is_malicious.is_(True) if is_malicious else
                   or_(Vulnerability.is_malicious.is_(False), Vulnerability.is_malicious.is_(None)))
    if is_kev is not None:
        out.append(Vulnerability.is_kev == is_kev)
    if is_heuristic is not None:
        out.append(Vulnerability.is_heuristic == is_heuristic)
    if min_epss is not None:
        out.append(Vulnerability.epss_score >= min_epss)
    if severity:
        out.append(func.upper(Vulnerability.severity) == severity.upper())
    return out


def affected_out(pkg: Package, fixed: str | None, rec: str | None, location: str | None = None) -> AffectedPackageOut:
    return AffectedPackageOut(
        id=pkg.id, name=pkg.name, version=pkg.version, ecosystem=pkg.ecosystem,
        fixed_version=fixed, recommendation=rec, location=location,
    )


def vuln_sort_key(v: Vulnerability | VulnerabilityOut) -> tuple[int, int, int, int, float, str]:
    return (
        0 if v.is_malicious else 1,
        0 if v.is_heuristic else 1,
        0 if v.is_kev else 1,
        SEVERITY_ORDER.get((v.severity or "UNKNOWN").upper(), 9),
        -(v.epss_score or 0.0),
        v.vuln_id,
    )


async def threat_assets(db: AsyncSession, filters: list[Any]) -> list[ThreatAssetOut]:
    rows = (await db.execute(findings_query(*filters))).all()
    assets: dict[int, Asset] = {}
    grouped: dict[int, dict[int, tuple[Vulnerability, list[AffectedPackageOut]]]] = {}
    for asset, pkg, vuln, fixed, rec, loc in rows:
        assets[asset.id] = asset
        slot = grouped.setdefault(asset.id, {}).setdefault(vuln.id, (vuln, []))
        slot[1].append(affected_out(pkg, fixed, rec, loc))

    output: list[ThreatAssetOut] = []
    for asset_id, vmap in grouped.items():
        findings = [
            ThreatFindingOut(vulnerability=VulnerabilityOut.model_validate(v), affected_packages=pkgs)
            for v, pkgs in sorted(vmap.values(), key=lambda t: vuln_sort_key(t[0]))
        ]
        output.append(ThreatAssetOut(asset=AssetOut.model_validate(assets[asset_id]), findings=findings))
    output.sort(key=lambda a: a.asset.hostname)
    return output


def risk_score(vulns: Iterable[tuple[Any, ...]]) -> int:
    """0-100 saturating score from (severity, is_kev, is_heuristic, epss) of each distinct exposure.

    Each vuln contributes severity weight + 15 if KEV + 20 if heuristic + 10*EPSS;
    the sum is mapped through 100*(1-e^(-sum/60)) so a handful of KEV/IOC hits
    dominates hundreds of LOW findings. Scale: one CRITICAL ≈ 5, one KEV-listed HIGH ≈ 10,
    twenty HIGHs ≈ 45, a typical unpatched workstation (hundreds of findings) → 95+.
    """
    total = 0.0
    for sev, kev, heur, epss, *rest in vulns:
        total += 30.0 if rest and rest[0] else 0.0  # known-malicious package
        total += SEVERITY_WEIGHT.get((sev or "UNKNOWN").upper(), 1.0)
        total += 15.0 if kev else 0.0
        total += 20.0 if heur else 0.0
        total += 10.0 * (epss or 0.0)
    return int(round(100 * (1 - math.exp(-total / 200.0))))


def is_stale(asset: Asset) -> bool:
    last = as_utc(asset.last_seen)
    if last is None:
        return True
    return datetime.now(timezone.utc) - last > timedelta(days=get_settings().stale_days)


async def asset_stats(db: AsyncSession, assets: Sequence[Asset]) -> list[AssetStatsOut]:
    if not assets:
        return []
    ids = [a.id for a in assets]
    pkg_counts = dict((await db.execute(
        select(asset_package.c.asset_id, func.count())
        .where(asset_package.c.asset_id.in_(ids))
        .group_by(asset_package.c.asset_id)
    )).all())
    rows = (await db.execute(
        select(asset_package.c.asset_id, Vulnerability.id, Vulnerability.severity, Vulnerability.is_kev,
               Vulnerability.is_heuristic, Vulnerability.epss_score, Vulnerability.is_malicious)
        .join(package_vulnerability, package_vulnerability.c.package_id == asset_package.c.package_id)
        .join(Vulnerability, Vulnerability.id == package_vulnerability.c.vulnerability_id)
        .where(asset_package.c.asset_id.in_(ids), not_suppressed())
        .distinct()
    )).all()
    per_asset: dict[int, dict[int, tuple[str, bool, bool, float | None, bool]]] = {}
    for asset_id, vid, sev, kev, heur, epss, mal in rows:
        per_asset.setdefault(asset_id, {})[vid] = ((sev or "UNKNOWN").upper(), bool(kev), bool(heur), epss, bool(mal))

    out: list[AssetStatsOut] = []
    for a in assets:
        vulns = per_asset.get(a.id, {})
        sev_counts = {s: 0 for s in SEVERITY_ORDER}
        for sev, *_ in vulns.values():
            sev_counts[sev if sev in sev_counts else "UNKNOWN"] += 1
        epss_values = [v[3] for v in vulns.values() if v[3] is not None]
        violations = 0
        if a.license_violations_json:
            try:
                violations = len(json.loads(a.license_violations_json))
            except json.JSONDecodeError:
                violations = 0
        out.append(AssetStatsOut(
            **AssetOut.model_validate(a).model_dump(),
            package_count=pkg_counts.get(a.id, 0),
            vulnerability_count=len(vulns),
            severity_counts=sev_counts,
            kev_count=sum(1 for v in vulns.values() if v[1]),
            heuristic_count=sum(1 for v in vulns.values() if v[2]),
            malicious_count=sum(1 for v in vulns.values() if v[4]),
            license_violation_count=violations,
            max_epss=max(epss_values) if epss_values else None,
            risk_score=risk_score(vulns.values()),
            stale=is_stale(a),
        ))
    return out


async def asset_detail(db: AsyncSession, asset: Asset) -> AssetDetailOut:
    stats = (await asset_stats(db, [asset]))[0]
    eco_counts = dict((await db.execute(
        select(Package.ecosystem, func.count())
        .join(asset_package, asset_package.c.package_id == Package.id)
        .where(asset_package.c.asset_id == asset.id)
        .group_by(Package.ecosystem)
    )).all())
    summary: dict[str, Any] | None = None
    if asset.last_scan_summary:
        try:
            summary = json.loads(asset.last_scan_summary)
        except json.JSONDecodeError:
            summary = None
    violations: list[dict[str, str]] = []
    if asset.license_violations_json:
        try:
            violations = json.loads(asset.license_violations_json)
        except json.JSONDecodeError:
            violations = []
    return AssetDetailOut(**stats.model_dump(), last_scan_summary=summary, ecosystem_counts=eco_counts,
                          license_violations=violations)


async def get_asset_or_none(db: AsyncSession, hostname: str) -> Asset | None:
    return (await db.execute(select(Asset).where(Asset.hostname == hostname))).scalar_one_or_none()


def package_out(pkg: Package) -> PackageOut:
    return PackageOut.model_validate(pkg)


async def triage_states(db: AsyncSession, vuln_ids: Iterable[int], asset_id: int | None = None) -> dict[int, str]:
    """Effective triage state per vulnerability (asset-specific decision overrides the fleet-wide one)."""
    ids = list(set(vuln_ids))
    if not ids:
        return {}
    rows = (await db.execute(
        select(Triage.vulnerability_id, Triage.asset_id, Triage.state)
        .where(Triage.vulnerability_id.in_(ids), or_(Triage.asset_id.is_(None), Triage.asset_id == asset_id))
    )).all()
    out: dict[int, str] = {}
    for vid, aid, state in sorted(rows, key=lambda r: r[1] is not None):  # fleet-wide first, asset overrides
        out[vid] = state
    return out
