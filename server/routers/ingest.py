"""POST /api/v1/ingest — receive and persist agent scan payloads.

Ingest is idempotent and snapshot-based: the asset's package links are
replaced by the payload's package list, so removed or upgraded packages no
longer count against the host. Packages and vulnerabilities are resolved in
bulk (a handful of queries per payload instead of one per package).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from typing import TypeVar

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from server.config import get_settings
from server.database import get_db
from server.models import Asset, Package, ScanRecord, Vulnerability, asset_package, package_vulnerability, utcnow
from server.schemas import AgentPayload, IngestResponse, PackageIn, VulnDetailIn
from server.security import require_api_key

router = APIRouter(prefix="/api/v1", tags=["ingest"], dependencies=[Depends(require_api_key)])
log = logging.getLogger("openbom.server")

T = TypeVar("T")
CHUNK = 400  # stays well under SQLite's bound-parameter limit
MAX_ATTEMPTS = 3

PkgKey = tuple[str, str, str]  # (name, version, ecosystem)


def _chunks(items: list[T], size: int = CHUNK) -> Iterator[list[T]]:
    for i in range(0, len(items), size):
        yield items[i: i + size]


def _parse_ts(value: str) -> datetime | None:
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _vuln_key(v: VulnDetailIn, ecosystem: str, name: str) -> str:
    # Heuristic hits are host/package observations, not global advisories — namespace them per package
    if v.heuristic:
        return f"{v.vuln_id}::{ecosystem}::{name}"[:255]
    return v.vuln_id


PKG_ATTRS = ("purl", "license", "osv_ecosystem", "osv_name", "osv_version")


async def _resolve_packages(
    db: AsyncSession, keys: Iterable[PkgKey], attrs: dict[PkgKey, PackageIn] | None = None,
) -> dict[PkgKey, Package]:
    wanted = set(keys)
    attrs = attrs or {}
    found: dict[PkgKey, Package] = {}
    names = sorted({k[0] for k in wanted})
    for chunk in _chunks(names):
        for pkg in (await db.execute(select(Package).where(Package.name.in_(chunk)))).scalars():
            key = (pkg.name, pkg.version, pkg.ecosystem)
            if key in wanted:
                found[key] = pkg
    missing = [Package(name=n, version=v, ecosystem=e) for (n, v, e) in sorted(wanted - found.keys())]
    for key, pkg in [*((k, p) for k, p in found.items()), *(((p.name, p.version, p.ecosystem), p) for p in missing)]:
        src = attrs.get(key)
        if src is None:
            continue
        for attr in PKG_ATTRS:
            value = getattr(src, attr)
            if value and getattr(pkg, attr) != value:
                setattr(pkg, attr, value)
    if missing:
        db.add_all(missing)
    await db.flush()
    for pkg in missing:
        found[(pkg.name, pkg.version, pkg.ecosystem)] = pkg
    return found


async def _resolve_vulns(db: AsyncSession, data: dict[str, tuple[VulnDetailIn, bool]]) -> dict[str, Vulnerability]:
    found: dict[str, Vulnerability] = {}
    ids = sorted(data)
    for chunk in _chunks(ids):
        for v in (await db.execute(select(Vulnerability).where(Vulnerability.vuln_id.in_(chunk)))).scalars():
            found[v.vuln_id] = v
    now = utcnow()
    new: list[Vulnerability] = []
    for vid, (v, heuristic) in data.items():
        attrs = {
            "severity": v.severity,
            "summary": v.summary,
            "fixed_version": v.fixed_version,
            "recommendation": v.recommendation,
            "cvss_score": v.cvss_score,
            "epss_score": v.epss_score,
            "epss_percentile": v.epss_percentile,
            "kev_description": v.kev_description,
            "poc_links": json.dumps(v.poc_links) if v.poc_links else None,
            "cves": json.dumps(v.cves) if v.cves else None,
        }
        obj = found.get(vid)
        if obj is None:
            obj = Vulnerability(vuln_id=vid, is_kev=v.is_kev, is_heuristic=heuristic, is_malicious=v.malicious,
                                first_seen=now, last_updated=now, **attrs)
            new.append(obj)
            found[vid] = obj
        else:
            for k, val in attrs.items():
                if val is not None:
                    setattr(obj, k, val)
            # KEV is sticky: a catalog entry is never removed once a CVE is known-exploited
            obj.is_kev = obj.is_kev or v.is_kev
            obj.is_heuristic = obj.is_heuristic or heuristic
            obj.is_malicious = bool(obj.is_malicious) or v.malicious
            obj.last_updated = now
    if new:
        db.add_all(new)
    await db.flush()
    return found


async def _do_ingest(
    db: AsyncSession, payload: AgentPayload, client_ip: str | None, source: str = "agent",
) -> IngestResponse:
    now = utcnow()
    scan_ts = _parse_ts(payload.scan_ts)
    summary_json = payload.osv_summary.model_dump_json() if payload.osv_summary else None

    asset = (await db.execute(select(Asset).where(Asset.hostname == payload.hostname))).scalar_one_or_none()
    if asset is None:
        asset = Asset(hostname=payload.hostname, first_seen=now, last_seen=now)
        db.add(asset)
    asset.last_seen = now
    asset.last_scan_ts = scan_ts or now
    if summary_json is not None:
        asset.last_scan_summary = summary_json
    if client_ip:
        asset.ip_address = client_ip[:45]
    if payload.os and payload.os.pretty_name:
        asset.os_name = payload.os.pretty_name[:255]
    if payload.agent_version and source == "agent":
        asset.agent_version = payload.agent_version
    if payload.scan_target:
        asset.target_type = str(payload.scan_target.get("type", ""))[:16] or None
        asset.target_ref = str(payload.scan_target.get("ref", ""))[:512] or None
    if payload.eol is not None:
        asset.eol_json = json.dumps(payload.eol)
    if payload.license_violations is not None:
        asset.license_violations_json = json.dumps(payload.license_violations[:5000])
    await db.flush()

    # --- Packages: snapshot of what is installed right now ---
    labels: dict[PkgKey, str | None] = {}
    attrs: dict[PkgKey, PackageIn] = {}
    for p in payload.packages:
        labels[(p.name, p.version, p.ecosystem)] = p.diff_label
        attrs[(p.name, p.version, p.ecosystem)] = p
    for finding in payload.osv_vulnerabilities or []:
        fp = finding.package
        labels.setdefault((fp.name, fp.version, fp.ecosystem), fp.diff_label)
        attrs.setdefault((fp.name, fp.version, fp.ecosystem), fp)

    pkg_map = await _resolve_packages(db, labels, attrs)
    previous = (await db.execute(
        select(asset_package.c.package_id).where(asset_package.c.asset_id == asset.id)
    )).scalars().all()
    current_ids = {pkg_map[k].id for k in labels}
    unlinked = len(set(previous) - current_ids)

    await db.execute(delete(asset_package).where(asset_package.c.asset_id == asset.id))
    link_rows = [
        {"asset_id": asset.id, "package_id": pkg_map[k].id, "diff_label": label, "scan_ts": scan_ts or now}
        for k, label in labels.items()
    ]
    for chunk in _chunks(link_rows):
        await db.execute(asset_package.insert(), chunk)

    # --- Vulnerabilities ---
    vuln_data: dict[str, tuple[VulnDetailIn, bool]] = {}
    pairs: dict[tuple[int, str], VulnDetailIn] = {}
    for finding in payload.osv_vulnerabilities or []:
        fp = finding.package
        pkg = pkg_map[(fp.name, fp.version, fp.ecosystem)]
        for v in finding.vulns:
            vid = _vuln_key(v, fp.ecosystem, fp.name)
            vuln_data[vid] = (v, v.heuristic)
            pairs[(pkg.id, vid)] = v

    linked = 0
    if vuln_data:
        vuln_map = await _resolve_vulns(db, vuln_data)
        pkg_ids = sorted({pid for pid, _ in pairs})
        existing: dict[tuple[int, int], tuple[str | None, str | None]] = {}
        for chunk in _chunks(pkg_ids):
            for pid, vid_db, fixed, rec in (await db.execute(
                select(package_vulnerability.c.package_id, package_vulnerability.c.vulnerability_id,
                       package_vulnerability.c.fixed_version, package_vulnerability.c.recommendation)
                .where(package_vulnerability.c.package_id.in_(chunk))
            )).tuples():
                existing[(pid, vid_db)] = (fixed, rec)
        inserts: list[dict[str, object]] = []
        for (pid, vid), v in pairs.items():
            db_id = vuln_map[vid].id
            values = {"fixed_version": v.fixed_version, "recommendation": v.recommendation}
            if (pid, db_id) in existing:
                if existing[(pid, db_id)] == (v.fixed_version, v.recommendation):
                    continue
                await db.execute(
                    package_vulnerability.update()
                    .where(package_vulnerability.c.package_id == pid,
                           package_vulnerability.c.vulnerability_id == db_id)
                    .values(**values)
                )
            else:
                inserts.append({"package_id": pid, "vulnerability_id": db_id, **values})
        for chunk in _chunks(inserts):
            await db.execute(package_vulnerability.insert(), chunk)
        linked = len(pairs)

    # --- Scan history ---
    s = payload.osv_summary
    record = ScanRecord(
        asset_id=asset.id, received_at=now, scan_ts=scan_ts, agent_version=payload.agent_version,
        total_packages=len(labels),
        vulnerable_packages=s.vulnerable if s else 0,
        critical=s.total_critical if s else 0,
        high=s.total_high if s else 0,
        medium=s.total_medium if s else 0,
        low=s.total_low if s else 0,
        unknown=s.total_unknown if s else 0,
        kev_hits=s.kev_hits if s else 0,
        heuristic_hits=sum(1 for v, h in vuln_data.values() if h),
        malicious_hits=sum(1 for v, _ in vuln_data.values() if v.malicious),
        license_violations=len(payload.license_violations or []),
        source=source,
        diff_new=payload.diff_summary.new if payload.diff_summary else None,
        diff_removed=payload.diff_summary.removed if payload.diff_summary else None,
        osv_checked=bool(s and s.queried),
    )
    db.add(record)
    await db.flush()
    scan_id = record.id
    await db.commit()

    return IngestResponse(
        status="ok",
        hostname=payload.hostname,
        scan_id=scan_id,
        packages_processed=len(labels),
        packages_unlinked=unlinked,
        vulnerabilities_linked=linked,
    )


async def ingest_payload(
    db: AsyncSession, payload: AgentPayload, client_ip: str | None, source: str = "agent",
) -> IngestResponse:
    """Validated ingest with retry on concurrent-insert conflicts (shared by /ingest, SBOM upload, reanalysis)."""
    max_pkgs = get_settings().max_packages
    if len(payload.packages) > max_pkgs:
        raise HTTPException(status_code=413, detail=f"Payload has {len(payload.packages)} packages (limit {max_pkgs})")
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            return await _do_ingest(db, payload, client_ip, source)
        except IntegrityError:
            # A concurrent ingest inserted the same package/vuln first — retry against the committed rows
            await db.rollback()
            if attempt == MAX_ATTEMPTS:
                log.exception("Ingest for %s failed after %d attempts", payload.hostname, attempt)
                raise HTTPException(status_code=409, detail="Concurrent ingest conflict — retry the request")
    raise AssertionError("unreachable")


@router.post("/ingest", response_model=IngestResponse)
async def ingest_scan(payload: AgentPayload, request: Request, db: AsyncSession = Depends(get_db)) -> IngestResponse:
    return await ingest_payload(db, payload, request.client.host if request.client else None)
