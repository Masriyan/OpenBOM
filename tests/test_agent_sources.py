"""Gap-fill features: lockfile/rootfs/SBOM sources, licenses, VEX/ignore, EOL, SARIF/SPDX, malicious packages."""

from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType

import httpx
import pytest

from tests.test_agent_pipeline import fake_extractors, patch_httpx


def keys(pkgs: list) -> set[tuple[str, str, str]]:  # type: ignore[type-arg]
    return {(p.ecosystem, p.name, p.version) for p in pkgs}


# ---------------------------------------------------------------------------
# Lockfile / manifest parsers
# ---------------------------------------------------------------------------

def build_repo(root: Path) -> None:
    files = {
        "requirements.txt": "requests==2.19.0\nflask[async]>=2.0\n# comment\nDjango===3.2.1 ; python_version>'3'\n-r other.txt\n",
        "poetry.lock": '[[package]]\nname = "urllib3"\nversion = "1.26.4"\n\n[[package]]\nname = "local"\nversion = "0.1"\n'
                       '[package.source]\ntype = "directory"\nurl = "../local"\n',
        "Pipfile.lock": json.dumps({"default": {"jinja2": {"version": "==2.10"}}, "develop": {"pytest": {"version": "==7.0.0"}}}),
        "web/package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "web"}, "node_modules/lodash": {"version": "4.17.15", "license": "MIT"},
            "node_modules/a/node_modules/@scope/b": {"version": "1.0.0"},
            "node_modules/linked": {"link": True}}}),
        "legacy/package-lock.json": json.dumps({"lockfileVersion": 1, "dependencies": {
            "minimist": {"version": "0.0.8", "dependencies": {"x": {"version": "1.0.0"}}}}}),
        "y/yarn.lock": '# yarn lockfile v1\n\n"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.1.0"\n\n'
                       'axios@^0.21.0:\n  version "0.21.0"\n  resolved "https://..."\n',
        "berry/yarn.lock": '__metadata:\n  version: 6\n\n"ws@npm:^7.0.0":\n  version: 7.4.5\n\n'
                           '"app@workspace:.":\n  version: 0.0.0-use.local\n',
        "p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      x: 1\n\npackages:\n\n"
                            "  express@4.17.1:\n    resolution: {}\n  '@types/node@20.1.0':\n    resolution: {}\n"
                            "  /old-style@1.2.3:\n    resolution: {}\n\nsnapshots:\n  express@4.17.1: {}\n",
        "go.mod": "module example.com/app\n\ngo 1.21\n\ntoolchain go1.21.4\n\nrequire (\n\tgolang.org/x/net v0.7.0\n"
                  "\tgithub.com/x/y v1.2.3+incompatible // indirect\n)\n\nrequire github.com/single/dep v0.1.0\n",
        "Cargo.lock": '[[package]]\nname = "tokio"\nversion = "1.18.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n'
                      '[[package]]\nname = "myapp"\nversion = "0.1.0"\n',
        "Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n  specs:\n    actionpack (6.1.0)\n      rack (~> 2.0)\n"
                        "    nokogiri (1.11.0-x86_64-linux)\n\nPLATFORMS\n  ruby\n",
        "composer.lock": json.dumps({"packages": [{"name": "laravel/framework", "version": "v8.0.0", "license": ["MIT"]}],
                                     "packages-dev": [{"name": "x/y", "version": "dev-main"}]}),
        "packages.lock.json": json.dumps({"version": 1, "dependencies": {"net6.0": {
            "Newtonsoft.Json": {"type": "Direct", "resolved": "12.0.1"}, "MyLib": {"type": "Project"}}}}),
        "pom.xml": '<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies><dependency>'
                   "<groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version>"
                   "</dependency><dependency><groupId>x</groupId><artifactId>y</artifactId><version>${v}</version>"
                   "</dependency></dependencies></project>",
        "gradle.lockfile": "com.google.guava:guava:30.0-jre=compileClasspath\nempty=annotationProcessor\n",
        "venv/lib/python3.12/site-packages/PyYAML-5.3.dist-info/METADATA":
            "Metadata-Version: 2.1\nName: PyYAML\nVersion: 5.3\nLicense: MIT\n\nbody",
        "img/node_modules/@scope/pkg/package.json": json.dumps({"name": "@scope/pkg", "version": "2.0.0", "license": "ISC"}),
        "img/node_modules/left-pad/package.json": json.dumps({"name": "left-pad", "version": "1.0.0"}),
        ".git/package-lock.json": json.dumps({"packages": {"node_modules/should-not-appear": {"version": "1.0.0"}}}),
    }
    for rel, body in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(body)


def make_jar(path: Path, coords: list[tuple[str, str, str]], nested: dict[str, bytes] | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for g, a, v in coords:
            zf.writestr(f"META-INF/maven/{g}/{a}/pom.properties", f"#x\ngroupId={g}\nartifactId={a}\nversion={v}\n")
        for name, data in (nested or {}).items():
            zf.writestr(name, data)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(buf.getvalue())
    return buf.getvalue()


def test_scan_path_all_ecosystems(agent: ModuleType, tmp_path: Path) -> None:
    build_repo(tmp_path)
    inner = make_jar(tmp_path / "tmp_inner.jar", [("org.apache.logging.log4j", "log4j-core", "2.14.1")])
    (tmp_path / "tmp_inner.jar").unlink()
    make_jar(tmp_path / "app/app.jar", [("com.acme", "app", "1.0")], {"BOOT-INF/lib/log4j-core-2.14.1.jar": inner})
    pkgs = agent.scan_path(tmp_path)
    k = keys(pkgs)
    expected = {
        ("PyPI", "requests", "2.19.0"), ("PyPI", "Django", "3.2.1"), ("PyPI", "urllib3", "1.26.4"),
        ("PyPI", "jinja2", "2.10"), ("PyPI", "pytest", "7.0.0"), ("PyPI", "PyYAML", "5.3"),
        ("NPM", "lodash", "4.17.15"), ("NPM", "@scope/b", "1.0.0"), ("NPM", "minimist", "0.0.8"), ("NPM", "x", "1.0.0"),
        ("NPM", "@babel/core", "7.1.0"), ("NPM", "axios", "0.21.0"), ("NPM", "ws", "7.4.5"),
        ("NPM", "express", "4.17.1"), ("NPM", "@types/node", "20.1.0"), ("NPM", "old-style", "1.2.3"),
        ("NPM", "@scope/pkg", "2.0.0"), ("NPM", "left-pad", "1.0.0"),
        ("Go", "golang.org/x/net", "0.7.0"), ("Go", "github.com/x/y", "1.2.3"), ("Go", "github.com/single/dep", "0.1.0"),
        ("Go", "stdlib", "1.21.4"), ("Cargo", "tokio", "1.18.0"),
        ("RubyGems", "actionpack", "6.1.0"), ("RubyGems", "nokogiri", "1.11.0"),
        ("Packagist", "laravel/framework", "8.0.0"), ("NuGet", "Newtonsoft.Json", "12.0.1"),
        ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"), ("Maven", "com.google.guava:guava", "30.0-jre"),
        ("Maven", "com.acme:app", "1.0"),
    }
    assert expected <= k, expected - k
    names = {p.name for p in pkgs}
    assert {"flask", "local", "myapp", "MyLib", "linked", "should-not-appear", "rack", "x/y", "app", "y"}.isdisjoint(names)
    by = {(p.ecosystem, p.name): p for p in pkgs}
    assert by[("NPM", "lodash")].license == "MIT" and by[("PyPI", "PyYAML")].license == "MIT"
    assert by[("Packagist", "laravel/framework")].license == "MIT"
    assert by[("NPM", "lodash")].location == "web/package-lock.json"
    assert by[("Cargo", "tokio")].osv_ecosystem == "crates.io"
    jars = [p for p in pkgs if p.name == "org.apache.logging.log4j:log4j-core"]
    assert any("!/BOOT-INF/lib/" in (p.location or "") for p in jars) or by[("Maven", "org.apache.logging.log4j:log4j-core")]


def test_corrupt_manifests_do_not_abort(agent: ModuleType, tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text("{not json")
    (tmp_path / "Cargo.lock").write_text("[[[bad toml")
    (tmp_path / "broken.jar").write_bytes(b"PK\x03\x04garbage")
    (tmp_path / "requirements.txt").write_text("ok==1.0\n")
    assert keys(agent.scan_path(tmp_path)) == {("PyPI", "ok", "1.0")}


# ---------------------------------------------------------------------------
# Rootfs
# ---------------------------------------------------------------------------

DPKG_STATUS = """Package: libssl3
Status: install ok installed
Version: 3.0.11-1~deb12u1
Source: openssl

Package: bash
Status: install ok installed
Version: 5.2.15-2+b2
Source: bash (5.2.15-2)

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0
"""

APK_DB = """C:Q1abc=
P:libcrypto3
V:3.0.5-r0
o:openssl
L:Apache-2.0

P:busybox
V:1.35.0-r17
L:GPL-2.0-only
"""


def test_scan_rootfs_debian(agent: ModuleType, tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text('ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12"\n')
    (tmp_path / "var/lib/dpkg").mkdir(parents=True)
    (tmp_path / "var/lib/dpkg/status").write_text(DPKG_STATUS)
    (tmp_path / "usr/share/doc/bash").mkdir(parents=True)
    (tmp_path / "usr/share/doc/bash/copyright").write_text("Format: x\n\nFiles: *\nLicense: GPL-3+\n")
    (tmp_path / "proc/1").mkdir(parents=True)
    (tmp_path / "proc/1/requirements.txt").write_text("evil==1.0\n")      # skipped top-level dir
    (tmp_path / "opt/app").mkdir(parents=True)
    (tmp_path / "opt/app/requirements.txt").write_text("requests==2.19.0\n")
    pkgs, osr = agent.scan_rootfs(tmp_path)
    by = {p.name: p for p in pkgs}
    assert osr["ID"] == "debian" and set(by) == {"libssl3", "bash", "requests"}
    assert by["libssl3"].query_name == "openssl" and by["libssl3"].osv_ecosystem == "Debian:12"
    assert by["bash"].query_version == "5.2.15-2" and by["bash"].license == "GPL-3+"


def test_scan_rootfs_alpine(agent: ModuleType, tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text('ID=alpine\nVERSION_ID=3.16.2\n')
    (tmp_path / "lib/apk/db").mkdir(parents=True)
    (tmp_path / "lib/apk/db/installed").write_text(APK_DB)
    pkgs, _ = agent.scan_rootfs(tmp_path)
    by = {p.name: p for p in pkgs}
    assert by["libcrypto3"].osv_ecosystem == "Alpine:v3.16" and by["libcrypto3"].query_name == "openssl"
    assert by["busybox"].license == "GPL-2.0-only"
    assert agent.compare_versions("3.0.5-r0", "3.0.5-r1", "Alpine:v3.16") == -1
    assert agent.compare_versions("3.0.10-r0", "3.0.9-r5", "Alpine:v3.16") == 1


def test_image_export_uses_safe_extraction(agent: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in {"etc/os-release": b"ID=alpine\nVERSION_ID=3.16.2\n",
                           "lib/apk/db/installed": APK_DB.encode()}.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        evil = tarfile.TarInfo("../../escape.txt")
        evil.size = 4
        tar.addfile(evil, io.BytesIO(b"pwnd"))
        link = tarfile.TarInfo("etc/abs-link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/shadow"
        tar.addfile(link)
    tar_bytes = buf.getvalue()

    class FakeProc:
        def __init__(self, *a: object, **k: object) -> None:
            self.stdout = io.BytesIO(tar_bytes)

        def wait(self, timeout: float | None = None) -> int:
            return 0

    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kw: object):  # type: ignore[no-untyped-def]
        calls.append(cmd)
        import subprocess
        return subprocess.CompletedProcess(cmd, 0, stdout="abc123\n", stderr="")

    monkeypatch.setattr(agent.shutil, "which", lambda b: "/usr/bin/podman" if b == "podman" else None)
    monkeypatch.setattr(agent.subprocess, "run", fake_run)
    monkeypatch.setattr(agent.subprocess, "Popen", FakeProc)
    dest = tmp_path / "rootfs"
    dest.mkdir()
    assert agent.export_image("alpine:3.16", dest) == "podman"
    assert (dest / "lib/apk/db/installed").exists()
    assert not (tmp_path.parent / "escape.txt").exists() and not (dest / "etc/abs-link").exists()
    assert calls[0][:3] == ["/usr/bin/podman", "create", "alpine:3.16"] and calls[-1][1:3] == ["rm", "-f"]


def test_host_pip_and_npm_packages_record_install_path(agent: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    def fake_run(cmd: list[str], timeout: int = 60) -> str | None:
        if "freeze" in cmd:
            return "pytest==8.0.0\nzz-openbom-other-env==1.0\n"
        if "list" in cmd:
            return json.dumps([{"name": "zz-openbom-other-env", "version": "1.0", "location": "/opt/venv/lib/site-packages"}])
        if cmd[:3] == ["npm", "root", "-g"]:
            return "/usr/lib/node_modules\n"
        return None

    monkeypatch.setattr(agent, "_run", fake_run)
    monkeypatch.setattr(agent.shutil, "which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr(agent.subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(
        cmd, 0, stdout=json.dumps({"dependencies": {"left-pad": {"version": "1.3.0"}}}), stderr=""))
    agent._npm_global_root.cache_clear()
    progress = agent.Progress(console=agent.Console(file=io.StringIO()))
    try:
        py = {p.name: p.location for p in agent.extract_python_packages(progress, progress.add_task("py"))}
        npm = agent.extract_npm_packages(progress, progress.add_task("npm"))
    finally:
        agent._npm_global_root.cache_clear()
    assert py["pytest"] and py["pytest"].endswith(".dist-info") and py["pytest"].startswith("/")  # this interpreter
    assert py["zz-openbom-other-env"] == "/opt/venv/lib/site-packages"  # pip's view of another environment
    assert [(p.name, p.location) for p in npm] == [("left-pad", "/usr/lib/node_modules/left-pad")]


# ---------------------------------------------------------------------------
# purl + SBOM input
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("purl,eco,name,version,osv_eco", [
    ("pkg:pypi/requests@2.19.0", "PyPI", "requests", "2.19.0", "PyPI"),
    ("pkg:npm/%40babel/core@7.1.0", "NPM", "@babel/core", "7.1.0", "npm"),
    ("pkg:golang/golang.org/x/net@v0.7.0", "Go", "golang.org/x/net", "0.7.0", "Go"),
    ("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar", "Maven",
     "org.apache.logging.log4j:log4j-core", "2.14.1", "Maven"),
    ("pkg:composer/laravel/framework@8.0.0", "Packagist", "laravel/framework", "8.0.0", "Packagist"),
    ("pkg:deb/debian/libssl3@3.0.11-1~deb12u1?arch=amd64&distro=debian-12&upstream=openssl", "Debian", "libssl3",
     "3.0.11-1~deb12u1", "Debian:12"),
    ("pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1?distro=jammy", "Debian", "openssl", "3.0.2-0ubuntu1", "Ubuntu:22.04:LTS"),
    ("pkg:rpm/almalinux/openssl@3.0.1-41.el9_0?epoch=1&distro=almalinux-9.3", "RPM", "openssl", "3.0.1-41.el9_0",
     "AlmaLinux:9"),
    ("pkg:apk/alpine/libcrypto3@3.0.5-r0?distro=3.16.2&upstream=openssl", "Alpine", "libcrypto3", "3.0.5-r0",
     "Alpine:v3.16"),
    ("pkg:rpm/fedora/bash@5.2-1.fc44?distro=fedora-44", "RPM", "bash", "5.2-1.fc44", None),
])
def test_package_from_purl(agent: ModuleType, purl: str, eco: str, name: str, version: str, osv_eco: str | None) -> None:
    p = agent.package_from_purl(purl)
    assert (p.ecosystem, p.name, p.version, p.osv_ecosystem) == (eco, name, version, osv_eco)


def test_purl_roundtrip_through_our_own_exports(agent: ModuleType) -> None:
    P = agent.Package
    pkgs = [P("libssl3", "3.0.11-1~deb12u1", "Debian", osv_ecosystem="Debian:12", osv_name="openssl"),
            P("openssl", "3.0.1-41.el9_0", "RPM", osv_ecosystem="AlmaLinux:9", osv_version="1:3.0.1-41.el9_0"),
            P("libcrypto3", "3.0.5-r0", "Alpine", osv_ecosystem="Alpine:v3.16", osv_name="openssl"),
            P("golang.org/x/net", "0.7.0", "Go", osv_ecosystem="Go"),
            P("org.apache.logging.log4j:log4j-core", "2.14.1", "Maven", osv_ecosystem="Maven")]
    for p in pkgs:
        back = agent.package_from_purl(agent.package_purl(p))
        assert (back.name, back.version, back.osv_ecosystem, back.query_name, back.query_version) == \
               (p.name, p.version, p.osv_ecosystem, p.query_name, p.query_version), agent.package_purl(p)


def test_parse_cyclonedx_and_spdx_documents(agent: ModuleType) -> None:
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"component": {"name": "my-image"}},
           "components": [
               {"type": "library", "name": "requests", "version": "2.19.0", "purl": "pkg:pypi/requests@2.19.0",
                "licenses": [{"license": {"id": "Apache-2.0"}}]},
               {"type": "library", "name": "parent", "purl": "pkg:npm/parent@1.0.0",
                "components": [{"type": "library", "purl": "pkg:npm/child@2.0.0"}]},
               {"type": "file", "name": "README"},
               {"type": "library", "name": "nopurl"}]}
    pkgs, meta = agent.parse_sbom_document(cdx)
    assert keys(pkgs) == {("PyPI", "requests", "2.19.0"), ("NPM", "parent", "1.0.0"), ("NPM", "child", "2.0.0")}
    assert meta["name"] == "my-image" and next(p for p in pkgs if p.name == "requests").license == "Apache-2.0"

    spdx = {"spdxVersion": "SPDX-2.3", "name": "repo", "packages": [
        {"name": "lodash", "licenseConcluded": "MIT", "externalRefs": [
            {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.15"}]},
        {"name": "root", "licenseConcluded": "NOASSERTION"}]}
    pkgs, meta = agent.parse_sbom_document(spdx)
    assert keys(pkgs) == {("NPM", "lodash", "4.17.15")} and meta["format"] == "SPDX-2.3"
    with pytest.raises(ValueError):
        agent.parse_sbom_document({"hello": "world"})


def test_own_cyclonedx_and_spdx_reimport(agent: ModuleType) -> None:
    from tests.test_agent_pipeline import sample_report
    report = sample_report(agent)
    for doc in (agent.to_cyclonedx(report), agent.to_spdx(report)):
        pkgs, _ = agent.parse_sbom_document(json.loads(json.dumps(doc)))
        assert keys(pkgs) == keys(report.packages)


# ---------------------------------------------------------------------------
# Licenses
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("MIT License", "MIT"), ("License :: OSI Approved :: Apache Software License", "Apache-2.0"),
    (["MIT", "Apache-2.0"], "MIT OR Apache-2.0"), ({"license": {"id": "BSD-3-Clause"}}, "BSD-3-Clause"),
    ({"expression": "MIT OR GPL-2.0"}, "MIT OR GPL-2.0"), ("UNKNOWN", None), ("", None), (None, None),
    ("Permission is hereby granted, free of charge, to any person obtaining a copy\n" * 3, "MIT"),
    ("GPLv3+", "GPL-3.0-or-later"),
])
def test_normalize_license(agent: ModuleType, raw: object, expected: str | None) -> None:
    assert agent.normalize_license(raw) == expected


@pytest.mark.parametrize("expr,denied,hit", [
    ("GPL-3.0", ["GPL-3.0"], "GPL-3.0"), ("GPL-3.0-or-later", ["GPL-3.0"], "GPL-3.0"),
    ("MIT OR GPL-3.0", ["GPL-3.0"], None),          # dual-licensed: MIT alternative is fine
    ("MIT AND GPL-3.0", ["GPL-3.0"], "GPL-3.0"),    # both apply
    ("LGPL-2.1", ["GPL"], None),                    # GPL prefix must not catch LGPL
    ("AGPL-3.0", ["AGPL"], "AGPL"), ("Apache-2.0", ["GPL", "AGPL"], None), ("", ["GPL"], None),
])
def test_license_violation(agent: ModuleType, expr: str, denied: list[str], hit: str | None) -> None:
    assert agent.license_violation(expr, denied) == hit


# ---------------------------------------------------------------------------
# VEX + ignore
# ---------------------------------------------------------------------------

def _results(agent: ModuleType):  # type: ignore[no-untyped-def]
    P, V = agent.Package, agent.VulnDetail
    return [
        agent.VulnResult(P("requests", "2.19.0", "PyPI", osv_ecosystem="PyPI"),
                         [V("GHSA-x84v-xcm2-53pg", "HIGH", "", None, "", cves=["CVE-2018-18074"]),
                          V("GHSA-other", "LOW", "", None, "")]),
        agent.VulnResult(P("urllib3", "1.26.4", "PyPI", osv_ecosystem="PyPI"),
                         [V("GHSA-q2q7", "MEDIUM", "", None, "", cves=["CVE-2021-33503"])]),
    ]


def test_openvex_suppression(agent: ModuleType) -> None:
    vex = {"@context": "https://openvex.dev/ns/v0.2.0", "statements": [
        {"vulnerability": {"name": "CVE-2018-18074"}, "products": [{"@id": "pkg:pypi/requests"}],
         "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path"},
        {"vulnerability": {"name": "CVE-2021-33503"}, "products": [{"@id": "pkg:pypi/urllib3@9.9.9"}],
         "status": "not_affected"},  # different version → must not match
        {"vulnerability": {"name": "GHSA-other"}, "status": "affected"},
    ]}
    results = _results(agent)
    sup = agent.apply_suppressions(results, agent.load_vex(vex))
    assert [s["vuln_id"] for s in sup] == ["GHSA-x84v-xcm2-53pg"]
    assert sup[0]["justification"] == "vulnerable_code_not_in_execute_path"
    assert [v.vuln_id for r in results for v in r.vulns] == ["GHSA-other", "GHSA-q2q7"]


def test_cyclonedx_vex_and_ignore_file(agent: ModuleType) -> None:
    cdx_vex = {"bomFormat": "CycloneDX", "components": [{"bom-ref": "r1", "purl": "pkg:pypi/urllib3@1.26.4"}],
               "vulnerabilities": [{"id": "CVE-2021-33503", "analysis": {"state": "false_positive"},
                                    "affects": [{"ref": "r1"}]}]}
    ignore = ("GHSA-other requests until=2999-01-01  # accepted risk\n"
              "GHSA-x84v-xcm2-53pg until=2000-01-01 # expired, must still report\n")
    results = _results(agent)
    sups = agent.load_vex(cdx_vex) + agent.load_ignore_file(ignore)
    sup = agent.apply_suppressions(results, sups)
    assert {s["vuln_id"] for s in sup} == {"GHSA-q2q7", "GHSA-other"}
    assert [v.vuln_id for r in results for v in r.vulns] == ["GHSA-x84v-xcm2-53pg"]
    with pytest.raises(ValueError):
        agent.load_vex({"foo": 1})


# ---------------------------------------------------------------------------
# EOL
# ---------------------------------------------------------------------------

def test_eol_targets_and_evaluation(agent: ModuleType) -> None:
    t = agent.eol_targets({"ID": "debian", "VERSION_ID": "12", "PRETTY_NAME": "Debian 12"})
    assert t == [("debian", "12", "Debian 12")]
    assert agent.eol_targets({"ID": "alpine", "VERSION_ID": "3.16.2"})[0][:2] == ("alpine-linux", "3.16")
    assert agent.eol_targets({"ID": "rocky", "VERSION_ID": "9.4"})[0][:2] == ("rocky-linux", "9")
    assert agent.eol_targets({"ID": "unknownos", "VERSION_ID": "1"}) == []
    now = datetime(2026, 10, 4, tzinfo=timezone.utc)
    assert agent.evaluate_eol({"eol": "2024-05-23"}, now)[0] is True
    is_eol, _, days = agent.evaluate_eol({"eol": "2027-06-02"}, now)
    assert is_eol is False and days == 241
    assert agent.evaluate_eol({"eol": True}, now)[0] is True and agent.evaluate_eol({"eol": False}, now)[0] is False


async def test_check_eol_mocked(agent: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert "endoflife.date/api/alpine-linux/3.16.json" in str(request.url)
        return httpx.Response(200, json={"eol": "2024-05-23", "latest": "3.16.9"})
    patch_httpx(monkeypatch, httpx.MockTransport(handler))
    res = await agent.check_eol([("alpine-linux", "3.16", "Alpine 3.16")])
    assert res[0]["is_eol"] is True and res[0]["latest"] == "3.16.9"
    assert agent.build_alert_text(agent.build_report([agent.Package("a", "1", "PyPI")], [], None)) is None
    report = agent.build_report([agent.Package("a", "1", "PyPI")], [], None)
    report.eol = res
    assert "End-of-life" in (agent.build_alert_text(report) or "")


# ---------------------------------------------------------------------------
# Malicious packages (OSV MAL-*)
# ---------------------------------------------------------------------------

def test_mal_advisory_is_critical_and_flagged(agent: ModuleType) -> None:
    mal = {"id": "MAL-2025-6812", "summary": "Malicious code in eslint-plugin-react_editor (npm)",
           "database_specific": {"malicious-packages-origins": [{"source": "ossf-package-analysis"}]},
           "affected": [{"package": {"name": "eslint-plugin-react_editor", "ecosystem": "npm"}, "versions": ["71.71.72"]}]}
    d = agent.parse_vuln_details([mal], "npm", "eslint-plugin-react_editor", "71.71.72")[0]
    assert d.is_malicious and d.severity == "CRITICAL" and d.recommendation.startswith("REMOVE")
    report = agent.build_report([agent.Package("eslint-plugin-react_editor", "71.71.72", "NPM")],
                                [agent.VulnResult(agent.Package("eslint-plugin-react_editor", "71.71.72", "NPM"), [d])])
    assert report.to_dict()["osv_summary"]["malicious_hits"] == 1
    assert "KNOWN MALICIOUS" in (agent.build_alert_text(report) or "")
    assert agent.exit_code_for(report, "high") == 2
    # alias of a GHSA record still marks malicious
    ghsa = {"id": "GHSA-mal1", "aliases": ["MAL-2024-1"], "database_specific": {"severity": "LOW"}}
    assert agent.parse_vuln_details([ghsa], "npm", "x")[0].is_malicious


# ---------------------------------------------------------------------------
# SARIF + SPDX + full run on a repo
# ---------------------------------------------------------------------------

def test_sarif_and_spdx_structure(agent: ModuleType) -> None:
    from tests.test_agent_pipeline import sample_report
    report = sample_report(agent)
    report.packages[0].location = "requirements.txt"
    report.packages[1].license = "Custom Weird License"
    sarif = agent.to_sarif(report)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and {r["id"] for r in run["tool"]["driver"]["rules"]} == \
        {"GHSA-j8r2-6x86-q33q", "MALICIOUS_HEURISTIC"}
    res = {r["ruleId"]: r for r in run["results"]}
    assert res["GHSA-j8r2-6x86-q33q"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "requirements.txt"
    assert res["MALICIOUS_HEURISTIC"]["level"] == "error"
    assert next(r for r in run["tool"]["driver"]["rules"] if r["id"].startswith("GHSA"))["properties"]["security-severity"] == "6.1"

    spdx = agent.to_spdx(report)
    assert spdx["spdxVersion"] == "SPDX-2.3" and len(spdx["packages"]) == len(report.packages) + 1
    lic = {p["name"]: p["licenseDeclared"] for p in spdx["packages"]}
    assert lic["lodash"].startswith("LicenseRef-") and spdx["hasExtractedLicensingInfos"][0]["extractedText"] == \
        "Custom Weird License"
    assert sum(1 for r in spdx["relationships"] if r["relationshipType"] == "CONTAINS") == len(report.packages)


async def test_run_scan_on_repo_path(agent: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("requests==2.28.0\nreqeusts==1.0.0\n")
    (repo / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/gpl-thing": {"version": "1.0.0", "license": "GPL-3.0"}}}))
    (repo / ".openbomignore").write_text("TYPOSQUAT_SUSPECT reqeusts  # reviewed\n")
    fake_extractors(agent, monkeypatch, [])  # host extractors must not run for a path target
    from tests.test_agent_pipeline import osv_handler
    patch_httpx(monkeypatch, httpx.MockTransport(osv_handler([])))
    out = tmp_path / "out"
    args = agent.parse_args(["--path", str(repo), "--heuristics", "all", "--license-deny", "GPL",
                             "--ignore", str(repo / ".openbomignore"), "--no-eol", "--diff",
                             "--sarif", str(out / "r.sarif"), "--spdx", str(out / "s.spdx.json"),
                             "--output-dir", str(out), "-o", str(out / "scan.json")])
    args.check_osv = True  # main() implies --check-osv for custom targets
    rc, report = await agent.run_scan(args)
    data = json.loads((out / "scan.json").read_text())
    assert rc == 2 and data["hostname"] == "path:repo" and data["scan_target"]["type"] == "path"
    assert data["license_violations"][0]["package"] == "gpl-thing"
    assert data["suppressed"][0]["vuln_id"] == "TYPOSQUAT_SUSPECT"
    ids = {v["vuln_id"] for f in data["osv_vulnerabilities"] for v in f["vulns"]}
    assert ids == {"GHSA-j8r2-6x86-q33q"}
    assert json.loads((out / "r.sarif").read_text())["runs"][0]["results"]
    assert json.loads((out / "s.spdx.json").read_text())["packages"]
    assert agent.diff_state_path(f"path:{repo.resolve()}").exists()
    assert not agent.diff_state_path().exists()  # host baseline untouched


def test_main_implies_check_osv_for_targets(agent: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen = {}

    async def fake_run(args):  # type: ignore[no-untyped-def]
        seen["check_osv"] = args.check_osv
        return 0, None
    monkeypatch.setattr(agent, "run_scan", fake_run)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert agent.main(["--path", str(tmp_path)]) == 0 and seen["check_osv"] is True


def test_menu_project_scan_option(agent: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from rich import prompt
    seen: dict = {}

    async def fake_run(args):  # type: ignore[no-untyped-def]
        seen.update(path=args.path, check=args.check_osv, diff=args.diff)
        return 0, None
    monkeypatch.setattr(agent, "run_scan", fake_run)
    answers = iter(["p", str(tmp_path), "0"])
    monkeypatch.setattr(prompt.Prompt, "ask", classmethod(lambda cls, *a, **k: next(answers)))
    assert agent.interactive_menu(agent.parse_args(["--menu", "--output-dir", str(tmp_path)])) == 0
    assert seen == {"path": [tmp_path], "check": True, "diff": True}
