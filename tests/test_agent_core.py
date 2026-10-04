"""Unit tests for the agent's pure logic: versions, CVSS, OSV parsing, OS mapping, extract parsers."""

from __future__ import annotations

import pytest

from tests.conftest import AGENT as A


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("a,b,expected", [
    ("1.0", "1.0", 0), ("1.0", "2.0", -1), ("2.0.1", "2.0", 1), ("1.0a", "1.0", 1), ("1.0", "1.0a", -1),
    ("1.0~rc1", "1.0", -1), ("1.0^git1", "1.0", 1), ("1.0^git1", "1.0.1", -1), ("1.010", "1.9", 1),
    ("2.0", "2_0", 0), ("1.0a", "1.0.1", -1), ("5.14.0-427.el9", "5.14.0-70.el9", 1),
])
def test_rpmvercmp(a: str, b: str, expected: int) -> None:
    assert A._rpmvercmp(a, b) == expected
    assert A._rpmvercmp(b, a) == -expected


@pytest.mark.parametrize("a,b,expected", [
    ("1:3.0.1-41.el9_0", "1:3.0.1-43.el9_0", -1), ("1:1.0-1", "2.0-1", 1), ("3.0.1-41.el9_0", "3.0.1-41.el9_0", 0),
])
def test_compare_rpm_evr(a: str, b: str, expected: int) -> None:
    assert A.compare_rpm(a, b) == expected


@pytest.mark.parametrize("a,b,expected", [
    ("1.0~rc1", "1.0", -1), ("1:1.0", "2.0", 1), ("1.0-1", "1.0-2", -1),
    ("3.0.11-1~deb12u1", "3.0.11-1~deb12u2", -1), ("1.0+b1", "1.0", 1), ("2.30-1ubuntu1", "2.30-1", 1),
    ("1.2.3", "1.2.3", 0), ("0.9.8zg-1", "0.9.8h-1", 1),
])
def test_compare_dpkg(a: str, b: str, expected: int) -> None:
    assert A.compare_dpkg(a, b) == expected
    assert A.compare_dpkg(b, a) == -expected


@pytest.mark.parametrize("a,b,expected", [
    ("1.2.3", "1.2.10", -1), ("1.0.0-alpha", "1.0.0", -1), ("1.0.0-alpha.1", "1.0.0-alpha.beta", -1),
    ("1.0.0-beta.11", "1.0.0-beta.2", 1), ("v2.0.0", "2.0.0", 0),
])
def test_compare_semver(a: str, b: str, expected: int) -> None:
    assert A.compare_semver(a, b) == expected


def test_compare_versions_dispatch_and_fallback() -> None:
    assert A.compare_versions("2.0.0rc1", "2.0.0", "PyPI") == -1
    assert A.compare_versions("1:1.0-1", "2.0-1", "AlmaLinux:9") == 1
    assert A.compare_versions("1.0~rc1", "1.0", "Debian:12") == -1
    assert A.compare_versions("4.17.15", "4.17.21", "npm") == -1
    # mixed numeric/alpha segments must not raise
    assert A.compare_versions("1.a.3", "1.2.3", "Unknown") in (-1, 1)


# ---------------------------------------------------------------------------
# CVSS + severity
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("vector,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_cvss3_base_score(vector: str, score: float) -> None:
    assert A.cvss3_base_score(vector) == score


@pytest.mark.parametrize("vector", ["", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N", "CVSS:3.1/AV:N/AC:L", "garbage"])
def test_cvss3_rejects_malformed(vector: str) -> None:
    assert A.cvss3_base_score(vector) is None


def test_severity_uses_highest_cvss_entry() -> None:
    rec = {"severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H"},
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        {"type": "Ubuntu", "score": "medium"},
    ]}
    assert A._extract_cvss_score(rec) == 9.8
    assert A._extract_severity(rec) == "CRITICAL"


@pytest.mark.parametrize("rec,expected", [
    ({"database_specific": {"severity": "MODERATE"}}, "MEDIUM"),
    ({"severity": [{"type": "Ubuntu", "score": "high"}]}, "HIGH"),
    ({"summary": "Important: openssl security update"}, "HIGH"),
    ({"summary": "Critical: kernel security update"}, "CRITICAL"),
    ({"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}]}, "UNKNOWN"),
    ({}, "UNKNOWN"),
])
def test_qualitative_severity(rec: dict, expected: str) -> None:
    assert A._extract_severity(rec) == expected


# ---------------------------------------------------------------------------
# OSV record parsing
# ---------------------------------------------------------------------------

UBUNTU_REC = {
    "id": "UBUNTU-CVE-2022-1292", "upstream": ["CVE-2022-1292"], "related": ["USN-5402-1"],
    "affected": [
        {"package": {"name": "openssl", "ecosystem": "Ubuntu:Pro:14.04:LTS"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.1f-1ubuntu2.27+esm10"}]}]},
        {"package": {"name": "openssl", "ecosystem": "Ubuntu:22.04:LTS"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.2-0ubuntu1.5"}]}]},
    ],
}


def test_fixed_version_prefers_exact_ecosystem() -> None:
    assert A._extract_fixed_version(UBUNTU_REC, "Ubuntu:22.04:LTS", "openssl", "3.0.2-0ubuntu1") == "3.0.2-0ubuntu1.5"


def test_fixed_version_picks_range_containing_installed() -> None:
    rec = {"affected": [{"package": {"name": "Django", "ecosystem": "PyPI"}, "ranges": [
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.5"},
                                         {"introduced": "2.0"}, {"fixed": "2.0.3"}]},
        {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc123"}]},
    ]}]}
    assert A._extract_fixed_version(rec, "PyPI", "django", "2.0.1") == "2.0.3"
    assert A._extract_fixed_version(rec, "PyPI", "django", "1.0") == "1.2.5"
    assert A._extract_fixed_version(rec, "PyPI", "django", "3.0") is None  # never suggest a downgrade
    assert A._extract_fixed_version(rec, "PyPI", "django") == "1.2.5"


def test_fixed_version_handles_rpm_epoch() -> None:
    rec = {"affected": [{"package": {"name": "openssl", "ecosystem": "AlmaLinux:9"}, "ranges": [
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:3.0.1-43.el9_0"}]}]}]}
    assert A._extract_fixed_version(rec, "AlmaLinux:9", "openssl", "1:3.0.1-41.el9_0") == "1:3.0.1-43.el9_0"
    assert A._extract_fixed_version(rec, "AlmaLinux:9", "openssl", "1:3.0.7-1.el9") is None


def test_cve_extraction_covers_distro_fields() -> None:
    assert A._extract_cve_aliases(UBUNTU_REC) == ["CVE-2022-1292"]
    alsa = {"id": "ALSA-2023:0946", "related": ["CVE-2022-4203", "CVE-2022-4304", "RHSA-2023:0946"]}
    assert A._extract_cve_aliases(alsa) == ["CVE-2022-4203", "CVE-2022-4304"]
    ghsa = {"id": "GHSA-29mw-wpgm-hmr9", "aliases": ["CVE-2020-28500"]}
    assert A._extract_cve_aliases(ghsa) == ["CVE-2020-28500"]


def test_parse_vuln_details_dedupes_and_skips_withdrawn() -> None:
    recs = [
        {"id": "GHSA-1", "summary": "x", "database_specific": {"severity": "HIGH"},
         "references": [{"url": "https://www.exploit-db.com/exploits/1"}, {"url": "https://example.com"}]},
        {"id": "GHSA-1", "summary": "dup"},
        {"id": "GHSA-2", "withdrawn": "2024-01-01T00:00:00Z"},
        {"id": "PYSEC-3"},
    ]
    details = A.parse_vuln_details(recs, "PyPI", "pkg", "1.0")
    assert [d.vuln_id for d in details] == ["GHSA-1", "PYSEC-3"]
    assert details[0].severity == "HIGH" and details[0].poc_links == ["https://www.exploit-db.com/exploits/1"]
    assert details[1].severity == "UNKNOWN" and details[1].summary == "No description available"
    assert A.parse_vuln_details([], "PyPI", "pkg") == []


def test_alias_duplicates_are_merged() -> None:
    pysec = {"id": "PYSEC-2026-161", "aliases": ["GHSA-86qp-5c8j-p5mr", "CVE-2026-0001"],
             "references": [{"url": "https://github.com/x/CVE-2026-0001-poc"}]}
    ghsa = {"id": "GHSA-86qp-5c8j-p5mr", "aliases": ["CVE-2026-0001"],
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"}],
            "affected": [{"package": {"name": "starlette", "ecosystem": "PyPI"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]}]}
    details = A.parse_vuln_details([pysec, ghsa], "PyPI", "starlette", "0.50.0")
    assert len(details) == 1
    d = details[0]
    assert d.vuln_id == "GHSA-86qp-5c8j-p5mr" and d.severity == "MEDIUM" and d.fixed_version == "1.0.1"
    assert d.poc_links == ["https://github.com/x/CVE-2026-0001-poc"] and d.cves == ["CVE-2026-0001"]


# ---------------------------------------------------------------------------
# OS mapping + extraction parsers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ('ID=debian\nVERSION_ID="12"\nVERSION="12 (bookworm)"', "Debian:12"),
    ('ID=ubuntu\nVERSION_ID="22.04"\nVERSION="22.04.4 LTS (Jammy Jellyfish)"', "Ubuntu:22.04:LTS"),
    ('ID=ubuntu\nVERSION_ID="24.10"\nVERSION="24.10 (Oracular Oriole)"', "Ubuntu:24.10"),
    ('ID="almalinux"\nVERSION_ID="9.4"', "AlmaLinux:9"),
    ('ID="rocky"\nVERSION_ID="8.10"', "Rocky Linux:8"),
    ('ID=fedora\nVERSION_ID=44', None),
    ('ID=kali\nID_LIKE=debian\nVERSION_CODENAME=kali-rolling', None),
    ("", None),
])
def test_osv_ecosystem_for_os(text: str, expected: str | None) -> None:
    assert A.osv_ecosystem_for_os(A.parse_os_release(text)) == expected


def test_parse_rpm_output_epoch_and_gpg_pubkey() -> None:
    raw = "openssl\t1\t3.0.1-41.el9_0\nbash\t(none)\t5.1.8-6.el9\ngpg-pubkey\t(none)\tabc-123\nbroken line\n"
    pkgs = A.parse_rpm_output(raw, "RPM", "AlmaLinux:9")
    assert [(p.name, p.version, p.query_version) for p in pkgs] == [
        ("openssl", "3.0.1-41.el9_0", "1:3.0.1-41.el9_0"), ("bash", "5.1.8-6.el9", "5.1.8-6.el9")]
    # no OSV feed (Fedora) → no query coordinates
    fedora = A.parse_rpm_output(raw, "RPM", None)
    assert all(p.osv_ecosystem is None and p.osv_version is None for p in fedora)


def test_parse_dpkg_output_source_package_and_status() -> None:
    raw = ("libssl3\t3.0.11-1~deb12u2\topenssl\t3.0.11-1~deb12u2\tii \n"
           "bash\t5.2.15-2+b2\tbash\t5.2.15-2\tii \n"
           "oldpkg\t1.0\toldpkg\t1.0\trc \n")
    pkgs = A.parse_dpkg_output(raw, "Debian", "Debian:12")
    assert [(p.name, p.query_name, p.query_version) for p in pkgs] == [
        ("libssl3", "openssl", "3.0.11-1~deb12u2"), ("bash", "bash", "5.2.15-2")]


def test_container_packages_keep_bare_query_name() -> None:
    pkgs = A.parse_rpm_output("curl\t(none)\t7.76.1-29.el9\n", "Podman-RPM", "Rocky Linux:9", " [abc123def456]")
    assert pkgs[0].name == "curl [abc123def456]" and pkgs[0].query_name == "curl"


def test_package_to_dict_is_compact() -> None:
    p = A.Package(name="x", version="1", ecosystem="PyPI")
    assert p.to_dict() == {"name": "x", "version": "1", "ecosystem": "PyPI", "diff_label": None}
