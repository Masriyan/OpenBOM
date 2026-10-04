"""Backend API tests (in-process ASGI + temporary SQLite)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from tests.conftest import finding, make_payload, vuln


KEV_FINDING = finding("requests", "2.19.0", "PyPI",
                      vuln("GHSA-x84v-xcm2-53pg", "HIGH", fixed_version="2.20.0", epss_score=0.3, is_kev=True,
                           cves=["CVE-2018-18074"], poc_links=["https://www.exploit-db.com/exploits/1"]))
CRIT_FINDING = finding("openssl", "3.0.1-41.el9_0", "RPM",
                       vuln("ALSA-2022:6224", "CRITICAL", fixed_version="1:3.0.1-43.el9_0", cvss_score=9.8))
IOC_FINDING = finding("lodash", "4.17.15", "NPM",
                      vuln("MALICIOUS_HEURISTIC", "CRITICAL", is_heuristic=True, summary="eval(base64) in index.js:1"))


async def ingest(client: httpx.AsyncClient, payload: dict, **headers: str) -> dict:
    r = await client.post("/api/v1/ingest", json=payload, headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


async def test_health_and_dashboard(client: httpx.AsyncClient) -> None:
    r = await client.get("/health")
    assert r.json()["status"] == "ok" and r.json()["auth_required"] is False
    page = await client.get("/")
    assert page.status_code == 200 and "OpenBOM Console" in page.text
    csp = page.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "script-src 'self';" in csp  # no inline/eval script allowed
    assert page.headers["x-content-type-options"] == "nosniff"
    assert "<script>" not in page.text and "<script src=\"/static/app.js\">" in page.text
    for path in ("/static/app.js", "/static/app.css", "/static/logo.svg", "/static/favicon.svg",
                 "/static/vendor/arco.min.js", "/static/vendor/arco.min.css", "/static/vendor/react.production.min.js",
                 "/static/vendor/react-dom.production.min.js", "/static/vendor/htm.umd.js",
                 "/static/vendor/arco-icon.min.js"):
        r = await client.get(path)
        assert r.status_code == 200 and len(r.content) > 500, path
    assert "immutable" in (await client.get("/static/vendor/htm.umd.js")).headers["cache-control"]
    assert (await client.get("/static/../server/main.py")).status_code == 404


async def test_ingest_and_query_everything(client: httpx.AsyncClient) -> None:
    body = await ingest(client, make_payload(findings=[KEV_FINDING, CRIT_FINDING, IOC_FINDING]))
    assert body["packages_processed"] == 3 and body["vulnerabilities_linked"] == 3 and body["scan_id"] >= 1

    assets = (await client.get("/api/v1/assets?sort=risk")).json()
    a = assets[0]
    assert a["hostname"] == "web-01" and a["package_count"] == 3 and a["vulnerability_count"] == 3
    assert a["kev_count"] == 1 and a["heuristic_count"] == 1 and a["os_name"] == "AlmaLinux 9.4"
    assert a["severity_counts"]["CRITICAL"] == 2 and 0 < a["risk_score"] <= 100 and a["max_epss"] == 0.3
    assert a["last_seen"].endswith(("Z", "+00:00"))  # SQLite naive datetimes are re-tagged as UTC
    scans = (await client.get("/api/v1/assets/web-01/scans")).json()
    assert scans[0]["received_at"].endswith(("Z", "+00:00"))

    detail = (await client.get("/api/v1/assets/web-01")).json()
    assert detail["ecosystem_counts"] == {"NPM": 1, "PyPI": 1, "RPM": 1}
    assert detail["last_scan_summary"]["queried"] == 3

    vulns = (await client.get("/api/v1/assets/web-01/vulnerabilities")).json()
    assert [v["vuln_id"] for v in vulns][0].startswith("MALICIOUS_HEURISTIC::NPM::lodash")  # IOC sorted first
    kev = next(v for v in vulns if v["is_kev"])
    assert kev["poc_links"] == ["https://www.exploit-db.com/exploits/1"] and kev["cves"] == ["CVE-2018-18074"]
    assert kev["affected_packages"][0]["fixed_version"] == "2.20.0"
    crit = (await client.get("/api/v1/assets/web-01/vulnerabilities?severity=critical")).json()
    assert {v["vuln_id"].split("::")[0] for v in crit} == {"ALSA-2022:6224", "MALICIOUS_HEURISTIC"}

    pkgs = (await client.get("/api/v1/assets/web-01/packages?ecosystem=npm")).json()
    assert [p["name"] for p in pkgs] == ["lodash"]

    for path, expected in [("kev", {"GHSA-x84v-xcm2-53pg"}), ("critical", {"ALSA-2022:6224", "MALICIOUS_HEURISTIC"}),
                           ("heuristics", {"MALICIOUS_HEURISTIC"}), ("high-epss?min_score=0.25", {"GHSA-x84v-xcm2-53pg"})]:
        data = (await client.get(f"/api/v1/threats/{path}")).json()
        got = {f["vulnerability"]["vuln_id"].split("::")[0] for t in data for f in t["findings"]}
        assert got == expected, path
    assert (await client.get("/api/v1/threats/high-epss?min_score=0.5")).json() == []

    summary = (await client.get("/api/v1/threats/summary")).json()
    assert summary["total_assets"] == 1 and summary["total_vulnerabilities"] == 3
    assert summary["kev_vulnerabilities"] == 1 and summary["heuristic_detections"] == 1
    assert summary["critical_vulnerabilities"] == 2 and summary["top_risky_assets"][0]["hostname"] == "web-01"
    assert summary["recent_scans"][0]["hostname"] == "web-01"


async def test_reingest_is_idempotent(client: httpx.AsyncClient) -> None:
    payload = make_payload(findings=[KEV_FINDING])
    await ingest(client, payload)
    await ingest(client, payload)
    summary = (await client.get("/api/v1/threats/summary")).json()
    assert summary["total_packages"] == 3 and summary["total_vulnerabilities"] == 1
    scans = (await client.get("/api/v1/assets/web-01/scans")).json()
    assert len(scans) == 2 and scans[0]["osv_checked"] is True


async def test_snapshot_unlinks_removed_and_upgraded_packages(client: httpx.AsyncClient) -> None:
    await ingest(client, make_payload(findings=[KEV_FINDING]))
    assert (await client.get("/api/v1/threats/kev")).json()
    # requests upgraded to a fixed version, lodash uninstalled
    upgraded = make_payload(packages=[("requests", "2.31.0", "PyPI"), ("openssl", "3.0.1-41.el9_0", "RPM")])
    body = await ingest(client, upgraded)
    assert body["packages_unlinked"] == 2
    assert (await client.get("/api/v1/threats/kev")).json() == []
    assert (await client.get("/api/v1/threats/summary")).json()["total_vulnerabilities"] == 0
    names = {p["name"]: p["version"] for p in (await client.get("/api/v1/assets/web-01/packages")).json()}
    assert names == {"requests": "2.31.0", "openssl": "3.0.1-41.el9_0"}
    pruned = (await client.post("/api/v1/maintenance/prune")).json()
    assert pruned == {"packages_deleted": 2, "vulnerabilities_deleted": 1}


async def test_findings_report_where_the_package_was_found(client: httpx.AsyncClient) -> None:
    payload = make_payload(hostname="path:repo", packages=[], findings=[KEV_FINDING])
    payload["packages"] = [
        {"name": "requests", "version": "2.19.0", "ecosystem": "PyPI", "location": loc}
        for loc in ("app-a/venv/lib/requests-2.19.0.dist-info/METADATA", "app-b/requirements.txt",
                    "app-a/venv/lib/requests-2.19.0.dist-info/METADATA")
    ]
    await ingest(client, payload)
    vulns = (await client.get("/api/v1/assets/path:repo/vulnerabilities")).json()
    assert vulns[0]["affected_packages"][0]["location"] == (
        "app-a/venv/lib/requests-2.19.0.dist-info/METADATA\napp-b/requirements.txt")
    kev = (await client.get("/api/v1/threats/kev")).json()
    assert kev[0]["findings"][0]["affected_packages"][0]["location"].startswith("app-a/")
    detail = (await client.get("/api/v1/vulnerabilities/GHSA-x84v-xcm2-53pg")).json()
    assert detail["affected"][0]["package"]["location"].endswith("app-b/requirements.txt")

    # path/rootfs scans report locations relative to the target root — stored as absolute paths
    payload["scan_target"] = {"type": "path", "ref": "/srv/repo"}
    payload["packages"].append({"name": "lodash", "version": "4.17.15", "ecosystem": "NPM",
                                "location": "/usr/lib/node_modules/lodash"})
    await ingest(client, payload)
    vulns = (await client.get("/api/v1/assets/path:repo/vulnerabilities")).json()
    assert vulns[0]["affected_packages"][0]["location"].split("\n") == [
        "/srv/repo/app-a/venv/lib/requests-2.19.0.dist-info/METADATA", "/srv/repo/app-b/requirements.txt"]
    pkgs = (await client.get("/api/v1/assets/path:repo/packages")).json()
    assert {x["name"]: x["location"] for x in pkgs}["lodash"] == "/usr/lib/node_modules/lodash"

    listed = (await client.get("/api/v1/vulnerabilities?kev=true")).json()
    occ = listed[0]["occurrences"]
    assert [(o["hostname"], o["name"], o["version"], o["fixed_version"]) for o in occ] == [
        ("path:repo", "requests", "2.19.0", "2.20.0")]
    assert occ[0]["location"].startswith("/srv/repo/app-a/")
    hunt = (await client.get("/api/v1/packages/search?name=requests&exact=true")).json()
    assert hunt[0]["locations"][0]["hostname"] == "path:repo"
    assert hunt[0]["locations"][0]["location"].endswith("app-b/requirements.txt")


async def test_shared_package_across_hosts_and_search(client: httpx.AsyncClient) -> None:
    await ingest(client, make_payload("web-01", findings=[KEV_FINDING]))
    await ingest(client, make_payload("db-01", packages=[("requests", "2.19.0", "PyPI"), ("xz", "5.6.0-1", "RPM")]))
    res = (await client.get("/api/v1/packages/search?name=requests&exact=true")).json()
    assert len(res) == 1 and res[0]["hosts"] == ["db-01", "web-01"]
    assert res[0]["vulnerability_count"] == 1 and res[0]["max_severity"] == "HIGH"
    assert (await client.get("/api/v1/packages/search?name=xz&version=5.6.0-1")).json()[0]["hosts"] == ["db-01"]
    assert (await client.get("/api/v1/packages/search?name=REQ")).json()[0]["package"]["name"] == "requests"
    kev = (await client.get("/api/v1/threats/kev")).json()
    assert [t["asset"]["hostname"] for t in kev] == ["db-01", "web-01"]  # vuln is a property of the package version

    listing = (await client.get("/api/v1/vulnerabilities?kev=true")).json()
    assert listing[0]["affected_assets"] == 2 and listing[0]["affected_packages"] == 1
    assert (await client.get("/api/v1/vulnerabilities?q=CVE-2018-18074")).json()[0]["vuln_id"] == "GHSA-x84v-xcm2-53pg"
    detail = (await client.get("/api/v1/vulnerabilities/GHSA-x84v-xcm2-53pg")).json()
    assert [a["hostname"] for a in detail["affected"]] == ["db-01", "web-01"]
    assert detail["affected"][0]["package"]["fixed_version"] == "2.20.0"


async def test_vuln_detail_with_colon_and_namespaced_ids(client: httpx.AsyncClient) -> None:
    await ingest(client, make_payload(findings=[CRIT_FINDING, IOC_FINDING]))
    r = await client.get("/api/v1/vulnerabilities/ALSA-2022%3A6224")
    assert r.status_code == 200 and r.json()["vulnerability"]["cvss_score"] == 9.8
    r = await client.get("/api/v1/vulnerabilities/MALICIOUS_HEURISTIC::NPM::lodash")
    assert r.status_code == 200 and r.json()["vulnerability"]["is_heuristic"] is True
    assert (await client.get("/api/v1/vulnerabilities/NOPE-1")).status_code == 404


async def test_kev_is_sticky_and_epss_updates(client: httpx.AsyncClient) -> None:
    await ingest(client, make_payload(findings=[KEV_FINDING]))
    refreshed = finding("requests", "2.19.0", "PyPI", vuln("GHSA-x84v-xcm2-53pg", "HIGH", epss_score=0.9, is_kev=False))
    await ingest(client, make_payload(findings=[refreshed]))
    v = (await client.get("/api/v1/vulnerabilities/GHSA-x84v-xcm2-53pg")).json()["vulnerability"]
    assert v["is_kev"] is True and v["epss_score"] == 0.9


async def test_delete_asset(client: httpx.AsyncClient) -> None:
    await ingest(client, make_payload("gone-01", findings=[KEV_FINDING]))
    assert (await client.delete("/api/v1/assets/gone-01")).status_code == 204
    assert (await client.get("/api/v1/assets/gone-01")).status_code == 404
    assert (await client.delete("/api/v1/assets/gone-01")).status_code == 404
    assert (await client.get("/api/v1/threats/kev")).json() == []


async def test_asset_sbom_export(client: httpx.AsyncClient) -> None:
    await ingest(client, make_payload(findings=[KEV_FINDING, IOC_FINDING]))
    bom = (await client.get("/api/v1/assets/web-01/sbom")).json()
    assert bom["bomFormat"] == "CycloneDX" and len(bom["components"]) == 3
    purls = {c["purl"] for c in bom["components"]}
    assert "pkg:pypi/requests@2.19.0" in purls and "pkg:rpm/almalinux/openssl@3.0.1-41.el9_0" in purls
    assert {v["id"] for v in bom["vulnerabilities"]} == {"GHSA-x84v-xcm2-53pg", "MALICIOUS_HEURISTIC"}


async def test_validation_errors(client: httpx.AsyncClient) -> None:
    bad = make_payload()
    bad["hostname"] = "a/b"
    assert (await client.post("/api/v1/ingest", json=bad)).status_code == 422
    bad = make_payload()
    bad["packages"][0]["name"] = ""
    assert (await client.post("/api/v1/ingest", json=bad)).status_code == 422
    assert (await client.get("/api/v1/assets?sort=bogus")).status_code == 422
    assert (await client.get("/api/v1/assets/nonexistent")).status_code == 404


async def test_moderate_severity_normalised(client: httpx.AsyncClient) -> None:
    f = finding("lodash", "4.17.15", "NPM", vuln("GHSA-29mw-wpgm-hmr9", "MODERATE"))
    await ingest(client, make_payload(findings=[f]))
    v = (await client.get("/api/v1/vulnerabilities")).json()[0]
    assert v["severity"] == "MEDIUM"


async def test_max_packages_limit(client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENBOM_MAX_PACKAGES", "2")
    assert (await client.post("/api/v1/ingest", json=make_payload())).status_code == 413


async def test_api_key_auth(client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENBOM_API_KEY", "s3cret,other-key")
    assert (await client.get("/api/v1/assets")).status_code == 401
    assert (await client.get("/api/v1/assets", headers={"X-API-Key": "wrong"})).status_code == 401
    assert (await client.get("/api/v1/assets", headers={"X-API-Key": "s3cret"})).status_code == 200
    assert (await client.get("/api/v1/assets", headers={"Authorization": "Bearer other-key"})).status_code == 200
    assert (await client.post("/api/v1/ingest", json=make_payload())).status_code == 401
    await ingest(client, make_payload(), **{"X-API-Key": "s3cret"})
    assert (await client.get("/health")).json()["auth_required"] is True
    assert (await client.get("/")).status_code == 200  # dashboard shell stays public; data needs the key


async def test_concurrent_ingests(client: httpx.AsyncClient) -> None:
    payloads = [make_payload(f"host-{i}", findings=[KEV_FINDING]) for i in range(6)]
    results = await asyncio.gather(*(client.post("/api/v1/ingest", json=p) for p in payloads))
    assert all(r.status_code == 200 for r in results), [r.text for r in results]
    summary = (await client.get("/api/v1/threats/summary")).json()
    assert summary["total_assets"] == 6 and summary["total_packages"] == 3


async def test_v4_agent_payload_still_accepted(client: httpx.AsyncClient) -> None:
    """Payload shape produced by agent v4 (no os/agent_version/is_heuristic/cvss fields)."""
    legacy = {
        "hostname": "legacy-01", "scan_ts": "2026-05-25T17:47:31+00:00", "total_packages": 2,
        "packages": [{"name": "evilpkg", "version": "0.1", "ecosystem": "PyPI", "diff_label": "[NEW]"},
                     {"name": "zeromq", "version": "4.3.5-22.fc43", "ecosystem": "RPM", "diff_label": "[NEW]"}],
        "diff_summary": {"new": 2, "removed": 0, "upgraded": 0, "downgraded": 0, "unchanged": 0},
        "osv_summary": {"queried": 1, "vulnerable": 1, "kev_hits": 0, "poc_count": 0, "total_critical": 1,
                        "total_high": 0, "total_medium": 0, "total_low": 0, "total_unknown": 0},
        "osv_vulnerabilities": [{"package": {"name": "evilpkg", "version": "0.1", "ecosystem": "PyPI",
                                             "diff_label": "[NEW]"}, "max_severity": "CRITICAL",
                                 "vulns": [{"vuln_id": "MALICIOUS_HEURISTIC", "severity": "CRITICAL",
                                            "summary": "eval(base64) in x.py", "fixed_version": None,
                                            "recommendation": "Quarantine", "epss_score": None,
                                            "epss_percentile": None, "is_kev": False, "kev_description": None,
                                            "poc_links": []}]}],
    }
    await ingest(client, legacy)
    heur = (await client.get("/api/v1/threats/heuristics")).json()
    assert heur[0]["asset"]["hostname"] == "legacy-01"
    assert heur[0]["findings"][0]["vulnerability"]["is_heuristic"] is True


async def test_schema_upgrade_adds_missing_columns(tmp_path: Path) -> None:
    """A database created by the v1 schema gets new nullable columns added on startup."""
    import sqlite3

    from sqlalchemy.ext.asyncio import create_async_engine

    from server.database import _add_missing_columns
    from server.models import Base

    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE assets (id INTEGER PRIMARY KEY, hostname VARCHAR(255) UNIQUE NOT NULL, ip_address VARCHAR(45),
                             last_seen DATETIME NOT NULL, last_scan_summary TEXT);
        CREATE TABLE package_vulnerability (package_id INTEGER, vulnerability_id INTEGER,
                                            PRIMARY KEY (package_id, vulnerability_id));
        INSERT INTO assets (hostname, last_seen) VALUES ('old-host', '2026-01-01 00:00:00');
    """)
    con.close()
    engine = create_async_engine(f"sqlite+aiosqlite:///{db}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_add_missing_columns)
    await engine.dispose()
    con = sqlite3.connect(db)
    cols = {r[1] for r in con.execute("PRAGMA table_info(assets)")}
    pv_cols = {r[1] for r in con.execute("PRAGMA table_info(package_vulnerability)")}
    assert {"os_name", "agent_version", "first_seen", "last_scan_ts"} <= cols
    assert {"fixed_version", "recommendation"} <= pv_cols
    assert con.execute("SELECT hostname FROM assets").fetchone() == ("old-host",)
    con.close()


async def test_agent_push_end_to_end(client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Agent push_to_server → real ASGI app → data visible through the API."""
    from server.main import app
    from tests.conftest import AGENT
    from tests.test_agent_pipeline import patch_httpx, sample_report

    patch_httpx(monkeypatch, httpx.ASGITransport(app=app))
    payload = json.loads(json.dumps(sample_report(AGENT).to_dict()))
    body = await AGENT.push_to_server("http://openbom.test", payload)
    assert body is not None and body["hostname"] == "unit-host" and body["vulnerabilities_linked"] == 2

    monkeypatch.setenv("OPENBOM_API_KEY", "k")
    assert await AGENT.push_to_server("http://openbom.test", payload) is None          # rejected without key
    assert await AGENT.push_to_server("http://openbom.test", payload, api_key="k") is not None


def test_risk_score_scale() -> None:
    from server.queries import risk_score

    assert risk_score([]) == 0
    one_crit = risk_score([("CRITICAL", False, False, None)])
    kev_high = risk_score([("HIGH", True, False, 0.5)])
    many = risk_score([("HIGH", False, False, None)] * 100)
    assert 0 < one_crit < kev_high < many <= 100
    assert risk_score([("LOW", False, False, None)] * 5) < kev_high  # KEV outranks a pile of LOWs
