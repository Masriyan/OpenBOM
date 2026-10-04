"""Backend gap-fill features: malicious, triage/VEX, licenses, EOL, SBOM upload, re-analysis."""

from __future__ import annotations

import httpx
import pytest

from tests.conftest import finding, make_payload, vuln
from tests.test_agent_pipeline import osv_handler, patch_httpx

MAL = finding("eslint-plugin-react_editor", "71.71.72", "NPM",
              vuln("MAL-2025-6812", "UNKNOWN", summary="Malicious code in eslint-plugin-react_editor (npm)"))
KEV = finding("requests", "2.19.0", "PyPI",
              vuln("GHSA-x84v-xcm2-53pg", "HIGH", is_kev=True, cves=["CVE-2018-18074"]))


async def ingest(client: httpx.AsyncClient, payload: dict) -> dict:
    r = await client.post("/api/v1/ingest", json=payload)
    assert r.status_code == 200, r.text
    return r.json()


def rich_payload(hostname: str = "web-01", findings: list | None = None) -> dict:
    p = make_payload(hostname, packages=[("requests", "2.19.0", "PyPI"), ("eslint-plugin-react_editor", "71.71.72", "NPM"),
                                         ("gpl-lib", "1.0", "PyPI")], findings=findings)
    p["packages"][0].update(license="Apache-2.0", purl="pkg:pypi/requests@2.19.0", osv_ecosystem="PyPI")
    p["packages"][2].update(license="GPL-3.0", purl="pkg:pypi/gpl-lib@1.0", osv_ecosystem="PyPI")
    p["scan_target"] = {"type": "image", "ref": "registry/app:1.0"}
    p["eol"] = [{"product": "alpine-linux", "cycle": "3.16", "label": "Alpine 3.16", "eol": "2024-05-23",
                 "is_eol": True, "days_left": -800}]
    p["license_violations"] = [{"package": "gpl-lib", "version": "1.0", "ecosystem": "PyPI", "license": "GPL-3.0",
                                "rule": "GPL"}]
    return p


async def test_malicious_and_new_asset_fields(client: httpx.AsyncClient) -> None:
    await ingest(client, rich_payload(findings=[MAL, KEV]))
    mal = (await client.get("/api/v1/threats/malicious")).json()
    v = mal[0]["findings"][0]["vulnerability"]
    assert v["vuln_id"] == "MAL-2025-6812" and v["is_malicious"] is True
    a = (await client.get("/api/v1/assets/web-01")).json()
    assert a["malicious_count"] == 1 and a["license_violation_count"] == 1 and a["target_type"] == "image"
    assert a["eol"][0]["is_eol"] is True and a["license_violations"][0]["package"] == "gpl-lib"
    vulns = (await client.get("/api/v1/assets/web-01/vulnerabilities")).json()
    assert vulns[0]["vuln_id"] == "MAL-2025-6812"  # malware sorts before everything else
    s = (await client.get("/api/v1/threats/summary")).json()
    assert s["malicious_packages"] == 1 and s["eol_assets"] == 1 and s["license_violations"] == 1
    assert s["target_breakdown"] == {"image": 1}
    pkgs = {p["name"]: p for p in (await client.get("/api/v1/assets/web-01/packages")).json()}
    assert pkgs["requests"]["license"] == "Apache-2.0" and pkgs["requests"]["purl"] == "pkg:pypi/requests@2.19.0"
    assert (await client.get("/api/v1/vulnerabilities?malicious=true")).json()[0]["vuln_id"] == "MAL-2025-6812"


async def test_triage_suppresses_and_exports_vex(client: httpx.AsyncClient) -> None:
    await ingest(client, rich_payload("web-01", [KEV]))
    await ingest(client, rich_payload("web-02", [KEV]))
    r = await client.put("/api/v1/triage", json={"vuln_id": "GHSA-x84v-xcm2-53pg", "hostname": "web-01",
                                                 "state": "not_affected", "justification": "vulnerable_code_not_in_execute_path",
                                                 "detail": "proxy auth never used"})
    assert r.status_code == 200 and r.json()["hostname"] == "web-01"
    kev_hosts = [t["asset"]["hostname"] for t in (await client.get("/api/v1/threats/kev")).json()]
    assert kev_hosts == ["web-02"]                                   # suppressed only on web-01
    assert (await client.get("/api/v1/assets/web-01/vulnerabilities")).json() == []
    shown = (await client.get("/api/v1/assets/web-01/vulnerabilities?include_suppressed=true")).json()
    assert shown[0]["triage_state"] == "not_affected"
    assert (await client.get("/api/v1/assets/web-01")).json()["vulnerability_count"] == 0

    # fleet-wide decision hides it everywhere; asset-specific one is kept
    await client.put("/api/v1/triage", json={"vuln_id": "GHSA-x84v-xcm2-53pg", "state": "false_positive"})
    assert (await client.get("/api/v1/threats/kev")).json() == []
    assert (await client.get("/api/v1/threats/summary")).json()["total_vulnerabilities"] == 0
    assert (await client.get("/api/v1/vulnerabilities")).json() == []
    assert (await client.get("/api/v1/vulnerabilities?include_suppressed=true")).json()[0]["triage_state"] == "false_positive"
    entries = (await client.get("/api/v1/triage")).json()
    assert len(entries) == 2

    vex = (await client.get("/api/v1/vex")).json()
    assert vex["@context"].startswith("https://openvex.dev")
    st = {s.get("status_notes", ""): s for s in vex["statements"]}
    assert all(s["status"] == "not_affected" for s in vex["statements"])
    assert vex["statements"][0]["products"] == [{"@id": "pkg:pypi/requests@2.19.0"}]
    assert any("web-01" in k for k in st)

    for e in entries:
        assert (await client.delete(f"/api/v1/triage/{e['id']}")).status_code == 204
    assert len((await client.get("/api/v1/threats/kev")).json()) == 2
    assert (await client.delete("/api/v1/triage/99999")).status_code == 404


async def test_vex_import_and_triage_validation(client: httpx.AsyncClient) -> None:
    await ingest(client, rich_payload(findings=[KEV]))
    doc = {"@context": "https://openvex.dev/ns/v0.2.0", "statements": [
        {"vulnerability": {"name": "CVE-2018-18074"}, "status": "not_affected", "justification": "component_not_present"},
        {"vulnerability": {"name": "CVE-0000-0000"}, "status": "not_affected"},
        {"vulnerability": {"name": "GHSA-x84v-xcm2-53pg"}, "status": "bogus"}]}
    r = (await client.post("/api/v1/vex", json=doc)).json()
    assert r == {"applied": 1, "skipped": 2}
    assert (await client.get("/api/v1/threats/kev")).json() == []
    assert (await client.post("/api/v1/vex", json={"nope": 1})).status_code == 422
    bad = await client.put("/api/v1/triage", json={"vuln_id": "GHSA-x84v-xcm2-53pg", "state": "maybe"})
    assert bad.status_code == 422
    assert (await client.put("/api/v1/triage", json={"vuln_id": "NOPE", "state": "in_triage"})).status_code == 404
    assert (await client.put("/api/v1/triage", json={"vuln_id": "GHSA-x84v-xcm2-53pg", "state": "in_triage",
                                                     "hostname": "ghost"})).status_code == 404


async def test_licenses_and_eol_endpoints(client: httpx.AsyncClient) -> None:
    await ingest(client, rich_payload("web-01"))
    await ingest(client, make_payload("db-01", packages=[("requests", "2.19.0", "PyPI")]))
    lic = {r["license"]: r for r in (await client.get("/api/v1/licenses")).json()}
    assert lic["Apache-2.0"] == {"license": "Apache-2.0", "packages": 1, "assets": 2}
    assert lic["GPL-3.0"]["assets"] == 1 and lic["UNKNOWN"]["packages"] == 1
    gpl = (await client.get("/api/v1/licenses/packages?license=GPL-3.0")).json()
    assert gpl[0]["package"]["name"] == "gpl-lib" and gpl[0]["hosts"] == ["web-01"]
    unknown = (await client.get("/api/v1/licenses/packages?license=UNKNOWN")).json()
    assert [u["package"]["name"] for u in unknown] == ["eslint-plugin-react_editor"]
    eol = (await client.get("/api/v1/eol")).json()
    assert eol[0]["hostname"] == "web-01" and eol[0]["eol"][0]["is_eol"] is True and len(eol) == 1


async def test_sbom_upload_with_server_side_analysis(client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch,
                                                     tmp_path) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("OPENBOM_STATE_DIR", str(tmp_path / "state"))
    from server.main import app
    asgi_client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    patch_httpx(monkeypatch, httpx.MockTransport(osv_handler([])))  # analyzer's outbound OSV/EPSS/KEV calls
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"component": {"name": "syft-image"}},
           "components": [{"type": "library", "purl": "pkg:pypi/requests@2.28.0"},
                          {"type": "library", "purl": "pkg:npm/lodash@4.17.21", "licenses": [{"license": {"id": "MIT"}}]}]}
    async with asgi_client as c:
        r = await c.post("/api/v1/sbom", json=cdx)
        assert r.status_code == 200, r.text
        assert r.json()["hostname"] == "syft-image" and r.json()["vulnerabilities_linked"] == 1
        a = (await c.get("/api/v1/assets/syft-image")).json()
        assert a["target_type"] == "sbom" and a["severity_counts"]["MEDIUM"] == 1 and a["kev_count"] == 1
        scans = (await c.get("/api/v1/assets/syft-image/scans")).json()
        assert scans[0]["source"] == "sbom-upload"
        r = await c.post("/api/v1/sbom?hostname=renamed&analyze=false", json=cdx)
        assert r.json()["hostname"] == "renamed" and r.json()["vulnerabilities_linked"] == 0
        assert (await c.post("/api/v1/sbom", json={"bomFormat": "CycloneDX", "components": []})).status_code == 422
        assert (await c.post("/api/v1/sbom", json={"random": True})).status_code == 422


async def test_reanalysis_picks_up_new_advisories(client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch,
                                                  tmp_path) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("OPENBOM_STATE_DIR", str(tmp_path / "state"))
    # inventory ingested with no findings (e.g. before the advisory existed)
    payload = make_payload("old-host", packages=[("requests", "2.28.0", "PyPI"), ("bash", "5.2", "RPM")])
    payload["agent_version"] = "5.1.0"
    await ingest(client, payload)
    assert (await client.get("/api/v1/assets/old-host")).json()["vulnerability_count"] == 0
    from server.main import app
    asgi_client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
    patch_httpx(monkeypatch, httpx.MockTransport(osv_handler([])))  # only the analyzer's outbound calls are mocked
    async with asgi_client as c:
        r = await c.post("/api/v1/assets/old-host/reanalyze")
        assert r.status_code == 200, r.text
        assert r.json() == {"assets": 1, "packages_checked": 1, "vulnerabilities_linked": 1}
        a = (await c.get("/api/v1/assets/old-host")).json()
        assert a["vulnerability_count"] == 1 and a["kev_count"] == 1 and a["agent_version"] == "5.1.0"
        assert (await c.get("/api/v1/assets/old-host/scans")).json()[0]["source"] == "reanalysis"
        assert (await c.post("/api/v1/reanalyze")).json()["assets"] == 1
        assert (await c.post("/api/v1/assets/ghost/reanalyze")).status_code == 404
