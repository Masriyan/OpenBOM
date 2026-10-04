"""Governance: triage / VEX, licenses, end-of-life, SBOM import and continuous re-analysis."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, Response
from sqlalchemy import delete, distinct, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from server import analyzer
from server.database import get_db
from server.models import Asset, Package, Triage, Vulnerability, asset_package, package_vulnerability, utcnow
from server.routers.ingest import ingest_payload
from server.schemas import (
    AgentPayload,
    EolAssetOut,
    IngestResponse,
    LicensePackageOut,
    LicenseSummaryOut,
    PackageOut,
    ReanalyzeResponse,
    TriageIn,
    TriageOut,
)
from server.security import require_api_key

router = APIRouter(prefix="/api/v1", tags=["governance"], dependencies=[Depends(require_api_key)])

VEX_STATUS = {"not_affected": "not_affected", "false_positive": "not_affected", "resolved": "fixed",
              "exploitable": "affected", "in_triage": "under_investigation"}
VEX_TO_STATE = {"not_affected": "not_affected", "fixed": "resolved", "affected": "exploitable",
                "under_investigation": "in_triage"}


# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------


async def _vuln_or_404(db: AsyncSession, vuln_id: str) -> Vulnerability:
    vuln = (await db.execute(select(Vulnerability).where(Vulnerability.vuln_id == vuln_id))).scalar_one_or_none()
    if vuln is None:
        raise HTTPException(status_code=404, detail=f"Vulnerability '{vuln_id}' not found")
    return vuln


async def _upsert_triage(db: AsyncSession, vuln: Vulnerability, asset: Asset | None, state: str,
                         justification: str | None, detail: str | None, author: str | None) -> Triage:
    cond = Triage.asset_id.is_(None) if asset is None else Triage.asset_id == asset.id
    entry = (await db.execute(select(Triage).where(Triage.vulnerability_id == vuln.id, cond))).scalar_one_or_none()
    if entry is None:
        entry = Triage(vulnerability_id=vuln.id, asset_id=asset.id if asset else None, state=state)
        db.add(entry)
    entry.state, entry.justification, entry.detail, entry.author = state, justification, detail, author
    entry.updated_at = utcnow()
    await db.flush()
    return entry


def _triage_out(t: Triage, vuln_id: str, hostname: str | None) -> TriageOut:
    return TriageOut(id=t.id, vuln_id=vuln_id, hostname=hostname, state=t.state, justification=t.justification,
                     detail=t.detail, author=t.author, updated_at=t.updated_at)


@router.get("/triage", response_model=list[TriageOut])
async def list_triage(state: str | None = Query(None), db: AsyncSession = Depends(get_db)) -> list[TriageOut]:
    stmt = (select(Triage, Vulnerability.vuln_id, Asset.hostname)
            .join(Vulnerability, Vulnerability.id == Triage.vulnerability_id)
            .outerjoin(Asset, Asset.id == Triage.asset_id).order_by(Triage.updated_at.desc()))
    if state:
        stmt = stmt.where(Triage.state == state)
    return [_triage_out(t, vid, host) for t, vid, host in (await db.execute(stmt)).all()]


@router.put("/triage", response_model=TriageOut)
async def set_triage(body: TriageIn, db: AsyncSession = Depends(get_db)) -> TriageOut:
    """Record an analyst decision. not_affected / false_positive hide the finding (fleet-wide or per asset)."""
    vuln = await _vuln_or_404(db, body.vuln_id)
    asset = None
    if body.hostname:
        asset = (await db.execute(select(Asset).where(Asset.hostname == body.hostname))).scalar_one_or_none()
        if asset is None:
            raise HTTPException(status_code=404, detail=f"Asset '{body.hostname}' not found")
    entry = await _upsert_triage(db, vuln, asset, body.state, body.justification, body.detail, body.author)
    await db.commit()
    return _triage_out(entry, vuln.vuln_id, body.hostname)


@router.delete("/triage/{triage_id}", status_code=204)
async def delete_triage(triage_id: int, db: AsyncSession = Depends(get_db)) -> Response:
    result = await db.execute(delete(Triage).where(Triage.id == triage_id))
    if not result.rowcount:
        raise HTTPException(status_code=404, detail="Triage entry not found")
    await db.commit()
    return Response(status_code=204)


@router.get("/vex")
async def export_vex(db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """OpenVEX 0.2.0 document generated from triage decisions (products = affected package purls)."""
    rows = (await db.execute(
        select(Triage, Vulnerability.vuln_id, Asset.hostname)
        .join(Vulnerability, Vulnerability.id == Triage.vulnerability_id)
        .outerjoin(Asset, Asset.id == Triage.asset_id)
    )).all()
    statements = []
    for t, vid, host in rows:
        pkg_stmt = (select(distinct(Package.purl)).join(package_vulnerability,
                    package_vulnerability.c.package_id == Package.id)
                    .where(package_vulnerability.c.vulnerability_id == t.vulnerability_id, Package.purl.is_not(None)))
        if t.asset_id is not None:
            pkg_stmt = pkg_stmt.join(asset_package, asset_package.c.package_id == Package.id) \
                .where(asset_package.c.asset_id == t.asset_id)
        purls = sorted(p for p in (await db.execute(pkg_stmt)).scalars() if p)
        status = VEX_STATUS[t.state]
        st: dict[str, Any] = {"vulnerability": {"name": vid}, "products": [{"@id": p} for p in purls],
                              "status": status, "timestamp": t.updated_at.replace(tzinfo=timezone.utc).isoformat()
                              if t.updated_at.tzinfo is None else t.updated_at.isoformat()}
        if status == "not_affected":
            st["justification"] = t.justification or "vulnerable_code_not_in_execute_path"
            if t.detail:
                st["impact_statement"] = t.detail
        elif t.detail:
            st["action_statement" if status == "affected" else "status_notes"] = t.detail
        if host:
            st["status_notes"] = (st.get("status_notes", "") + f" (scope: {host})").strip()
        statements.append(st)
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://openbom.local/vex/{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "author": "OpenBOM",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": 1,
        "statements": statements,
    }


@router.post("/vex")
async def import_vex(document: dict[str, Any] = Body(...), db: AsyncSession = Depends(get_db)) -> dict[str, int]:
    """Import OpenVEX statements as fleet-wide triage decisions (matched by vuln id or CVE alias)."""
    statements = document.get("statements")
    if not isinstance(statements, list):
        raise HTTPException(status_code=422, detail="expected an OpenVEX document with 'statements'")
    applied = skipped = 0
    for st in statements:
        vuln = st.get("vulnerability")
        name = (vuln.get("name") or vuln.get("@id")) if isinstance(vuln, dict) else vuln
        state = VEX_TO_STATE.get(st.get("status", ""))
        if not name or not state:
            skipped += 1
            continue
        matches = (await db.execute(select(Vulnerability).where(
            or_(Vulnerability.vuln_id == name, Vulnerability.cves.ilike(f'%"{name}"%'))))).scalars().all()
        if not matches:
            skipped += 1
            continue
        for v in matches:
            await _upsert_triage(db, v, None, state, st.get("justification"),
                                 st.get("impact_statement") or st.get("status_notes"), "vex-import")
            applied += 1
    await db.commit()
    return {"applied": applied, "skipped": skipped}


# ---------------------------------------------------------------------------
# Licenses + EOL
# ---------------------------------------------------------------------------


@router.get("/licenses", response_model=list[LicenseSummaryOut])
async def license_summary(db: AsyncSession = Depends(get_db)) -> list[LicenseSummaryOut]:
    rows = (await db.execute(
        select(func.coalesce(Package.license, "UNKNOWN"), func.count(distinct(Package.id)),
               func.count(distinct(asset_package.c.asset_id)))
        .join(asset_package, asset_package.c.package_id == Package.id)
        .group_by(func.coalesce(Package.license, "UNKNOWN"))
    )).all()
    return sorted((LicenseSummaryOut(license=lic, packages=n, assets=a) for lic, n, a in rows),
                  key=lambda r: (-r.packages, r.license))


@router.get("/licenses/packages", response_model=list[LicensePackageOut])
async def license_packages(
    license: str = Query(..., description="License id, or UNKNOWN for packages without license data"),
    limit: int = Query(500, ge=1, le=5000),
    db: AsyncSession = Depends(get_db),
) -> list[LicensePackageOut]:
    cond = Package.license.is_(None) if license == "UNKNOWN" else Package.license == license
    rows = (await db.execute(
        select(Package, Asset.hostname).join(asset_package, asset_package.c.package_id == Package.id)
        .join(Asset, Asset.id == asset_package.c.asset_id).where(cond).order_by(Package.name)
    )).all()
    grouped: dict[int, tuple[Package, set[str]]] = {}
    for pkg, host in rows:
        grouped.setdefault(pkg.id, (pkg, set()))[1].add(host)
    return [LicensePackageOut(package=PackageOut.model_validate(p), hosts=sorted(h))
            for p, h in list(grouped.values())[:limit]]


@router.get("/eol", response_model=list[EolAssetOut])
async def eol_status(db: AsyncSession = Depends(get_db)) -> list[EolAssetOut]:
    out = []
    for a in (await db.execute(select(Asset).where(Asset.eol_json.is_not(None)).order_by(Asset.hostname))).scalars():
        try:
            entries = json.loads(a.eol_json or "[]")
        except json.JSONDecodeError:
            continue
        if entries:
            out.append(EolAssetOut(hostname=a.hostname, target_type=a.target_type, eol=entries))
    out.sort(key=lambda e: (not any(x.get("is_eol") for x in e.eol), e.hostname))
    return out


# ---------------------------------------------------------------------------
# SBOM import + continuous re-analysis
# ---------------------------------------------------------------------------


@router.post("/sbom", response_model=IngestResponse)
async def upload_sbom(
    request: Request,
    document: dict[str, Any] = Body(..., description="CycloneDX or SPDX JSON document"),
    hostname: str | None = Query(None, description="Asset name (default: SBOM metadata name)"),
    analyze: bool = Query(True, description="Run OSV/EPSS/KEV analysis server-side"),
    db: AsyncSession = Depends(get_db),
) -> IngestResponse:
    """Import an SBOM produced by any tool (Syft, Trivy, cdxgen, Microsoft sbom-tool, …) as an asset."""
    try:
        payload = await analyzer.sbom_payload(document, hostname, analyze)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return await ingest_payload(db, AgentPayload.model_validate(payload),
                                request.client.host if request.client else None, source="sbom-upload")


async def reanalyze_assets(db: AsyncSession, assets: list[Asset]) -> ReanalyzeResponse:
    checked = linked = 0
    for asset in assets:
        payload, queried = await analyzer.reanalysis_payload(db, asset)
        result = await ingest_payload(db, AgentPayload.model_validate(payload), None, source="reanalysis")
        checked += queried
        linked += result.vulnerabilities_linked
    return ReanalyzeResponse(assets=len(assets), packages_checked=checked, vulnerabilities_linked=linked)


@router.post("/assets/{hostname}/reanalyze", response_model=ReanalyzeResponse)
async def reanalyze_asset(hostname: str, db: AsyncSession = Depends(get_db)) -> ReanalyzeResponse:
    """Re-run OSV/EPSS/KEV on the stored inventory — picks up advisories published since the last scan."""
    asset = (await db.execute(select(Asset).where(Asset.hostname == hostname))).scalar_one_or_none()
    if asset is None:
        raise HTTPException(status_code=404, detail=f"Asset '{hostname}' not found")
    return await reanalyze_assets(db, [asset])


@router.post("/reanalyze", response_model=ReanalyzeResponse)
async def reanalyze_all(db: AsyncSession = Depends(get_db)) -> ReanalyzeResponse:
    assets = list((await db.execute(select(Asset).order_by(Asset.hostname))).scalars())
    return await reanalyze_assets(db, assets)
