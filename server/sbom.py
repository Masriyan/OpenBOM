"""CycloneDX 1.5 export of an asset's current package snapshot."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models import Asset, Package, asset_package
from server.queries import findings_query


def purl_for(pkg: Package, distro: str = "linux") -> str | None:
    name = re.sub(r" \[[0-9a-f]+\]$", "", pkg.name)
    version = quote(pkg.version, safe="")
    eco = pkg.ecosystem
    if eco == "PyPI":
        return f"pkg:pypi/{re.sub(r'[-_.]+', '-', name).lower()}@{version}"
    if eco == "NPM":
        if name.startswith("@") and "/" in name:
            scope, _, base = name.partition("/")
            return f"pkg:npm/{quote(scope, safe='')}/{quote(base, safe='')}@{version}"
        return f"pkg:npm/{quote(name, safe='')}@{version}"
    if eco in ("RPM", "Podman-RPM"):
        return f"pkg:rpm/{quote(distro, safe='')}/{quote(name, safe='')}@{version}"
    if eco in ("Debian", "Podman-DEB"):
        return f"pkg:deb/{quote(distro, safe='')}/{quote(name, safe='')}@{version}"
    return None


def _distro_id(os_name: str | None) -> str:
    if not os_name:
        return "linux"
    first = os_name.split()[0].lower()
    return re.sub(r"[^a-z0-9]+", "", first) or "linux"


async def asset_cyclonedx(db: AsyncSession, asset: Asset) -> dict[str, Any]:
    distro = _distro_id(asset.os_name)
    pkgs = (await db.execute(
        select(Package).join(asset_package, asset_package.c.package_id == Package.id)
        .where(asset_package.c.asset_id == asset.id).order_by(Package.ecosystem, Package.name)
    )).scalars().all()

    refs: dict[int, str] = {}
    used: set[str] = set()
    components: list[dict[str, Any]] = []
    for p in pkgs:
        purl = p.purl or purl_for(p, distro)
        ref = purl or f"{p.ecosystem}:{p.name}@{p.version}"
        if ref in used:
            ref = f"{ref}#{p.id}"
        used.add(ref)
        refs[p.id] = ref
        comp: dict[str, Any] = {"type": "library", "bom-ref": ref, "name": p.name, "version": p.version,
                                "properties": [{"name": "openbom:ecosystem", "value": p.ecosystem}]}
        if purl:
            comp["purl"] = purl
        components.append(comp)

    vulns: dict[int, dict[str, Any]] = {}
    for _a, pkg, v, fixed, rec, _loc in (await db.execute(findings_query(Asset.id == asset.id))).all():
        entry = vulns.get(v.id)
        if entry is None:
            rating: dict[str, Any] = {"severity": (v.severity or "unknown").lower()}
            if v.cvss_score is not None:
                rating.update({"score": v.cvss_score, "method": "CVSSv31"})
            props = []
            if v.epss_score is not None:
                props.append({"name": "openbom:epss", "value": f"{v.epss_score:.5f}"})
            if v.is_kev:
                props.append({"name": "openbom:cisa_kev", "value": "true"})
            entry = {
                "bom-ref": f"vuln-{v.id}",
                "id": v.vuln_id.split("::", 1)[0] if v.is_heuristic else v.vuln_id,
                "source": {"name": "OpenBOM heuristics"} if v.is_heuristic else
                          {"name": "OSV", "url": f"https://osv.dev/vulnerability/{v.vuln_id}"},
                "ratings": [rating],
                "description": v.summary or "",
                "recommendation": rec or v.recommendation or "",
                "affects": [],
                "properties": props,
            }
            vulns[v.id] = entry
        entry["affects"].append({"ref": refs.get(pkg.id, f"{pkg.ecosystem}:{pkg.name}@{pkg.version}")})

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {"components": [{"type": "application", "name": "OpenBOM Backend", "version": "2.1.0"}]},
            "component": {"type": "device", "name": asset.hostname, "bom-ref": f"host:{asset.hostname}"},
        },
        "components": components,
        "vulnerabilities": list(vulns.values()),
    }
