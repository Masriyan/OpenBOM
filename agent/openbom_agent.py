#!/usr/bin/env python3
"""OpenBOM Endpoint Agent v4 — Ultimate Threat Hunting Edition.

Multi-ecosystem supply-chain scanner with EPSS exploit prediction,
CISA KEV cross-referencing, PoC/exploit link tracking, heuristic
IOC detection on new packages, delta scanning, container introspection,
and SIEM webhook alerting.

Usage:
    python3 openbom_agent.py --scan-only
    python3 openbom_agent.py --check-osv
    python3 openbom_agent.py --check-osv --report --diff
    python3 openbom_agent.py --check-osv --report --diff --webhook-url https://hooks.slack.com/...
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import site
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
OSV_BATCH_SIZE = 1000
OSV_ENRICH_CONCURRENCY = 20

EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH_SIZE = 100

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_PATH = Path("/tmp/openbom_kev_cache.json")
KEV_CACHE_TTL = 24 * 3600  # 24 hours

DEFAULT_LOG_PATH = Path("/var/log/openbom_agent.log")
FALLBACK_LOG_PATH = Path("logs/openbom_agent.log")
DEFAULT_OUTPUT_DIR = Path("output")
CACHE_PATH = Path("/tmp/openbom_osv_cache.json")
CACHE_TTL_SECONDS = 12 * 3600
DIFF_STATE_PATH = Path("/tmp/openbom_last_state.json")
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

POC_URL_PATTERNS = re.compile(
    r"exploit-db\.com|packetstormsecurity\.com|/poc[/\-_]|/exploit[/\-_]|"
    r"github\.com/[^/]+/[^/]*(poc|exploit|cve-\d{4})",
    re.IGNORECASE,
)

HEURISTIC_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("eval(base64)", re.compile(r"""eval\s*\(\s*(?:base64|__import__\s*\(\s*['"]base64['"])""", re.IGNORECASE)),
    ("os.system(url)", re.compile(r"""os\.system\s*\(\s*['"](?:https?://|curl |wget )""", re.IGNORECASE)),
    ("exec(base64)", re.compile(r"""exec\s*\(\s*(?:base64|__import__\s*\(\s*['"]base64['"])""", re.IGNORECASE)),
    ("pastebin/ngrok", re.compile(r"""(?:pastebin\.com/raw|ngrok\.io|ngrok-free\.app|paste\.ee)""", re.IGNORECASE)),
    ("subprocess+url", re.compile(r"""subprocess\.\w+\s*\(\s*\[?\s*['"](?:curl|wget|powershell)""", re.IGNORECASE)),
    ("suspicious_import", re.compile(r"""__import__\s*\(\s*['"](?:socket|ctypes|winreg)['"]""", re.IGNORECASE)),
]

console = Console()

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Package:
    name: str
    version: str
    ecosystem: str
    diff_label: str | None = None


@dataclass(slots=True)
class VulnDetail:
    vuln_id: str
    severity: str
    summary: str
    fixed_version: str | None
    recommendation: str
    epss_score: float | None = None
    epss_percentile: float | None = None
    is_kev: bool = False
    kev_description: str | None = None
    poc_links: list[str] = field(default_factory=list)


@dataclass(slots=True)
class VulnResult:
    package: Package
    vulns: list[VulnDetail] = field(default_factory=list)

    @property
    def max_severity(self) -> str:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        if not self.vulns:
            return "UNKNOWN"
        return min(self.vulns, key=lambda v: order.get(v.severity, 99)).severity


@dataclass(slots=True)
class ScanReport:
    hostname: str
    scan_ts: str
    packages: list[Package]
    osv_results: list[VulnResult] | None = None
    diff_summary: dict[str, int] | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "hostname": self.hostname,
            "scan_ts": self.scan_ts,
            "total_packages": len(self.packages),
            "packages": [asdict(p) for p in self.packages],
        }
        if self.diff_summary is not None:
            data["diff_summary"] = self.diff_summary
        if self.osv_results is not None:
            vulnerable = [r for r in self.osv_results if r.vulns]
            metrics = self._severity_metrics(vulnerable)
            kev_count = sum(1 for r in vulnerable for v in r.vulns if v.is_kev)
            poc_count = sum(1 for r in vulnerable for v in r.vulns if v.poc_links)
            data["osv_summary"] = {
                "queried": len(self.osv_results),
                "vulnerable": len(vulnerable),
                "kev_hits": kev_count,
                "poc_count": poc_count,
                **metrics,
            }
            data["osv_vulnerabilities"] = [
                {
                    "package": asdict(r.package),
                    "max_severity": r.max_severity,
                    "vulns": [asdict(v) for v in r.vulns],
                }
                for r in vulnerable
            ]
        return data

    @staticmethod
    def _severity_metrics(vulnerable: list[VulnResult]) -> dict[str, int]:
        counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for r in vulnerable:
            for v in r.vulns:
                counts[v.severity] = counts.get(v.severity, 0) + 1
        return {f"total_{k.lower()}": v for k, v in counts.items()}


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def _configure_logging() -> logging.Logger:
    logger = logging.getLogger("openbom")
    logger.setLevel(logging.DEBUG)
    rich_handler = RichHandler(
        console=console, show_path=False, rich_tracebacks=True,
        tracebacks_show_locals=False, markup=True,
    )
    rich_handler.setLevel(logging.INFO)
    logger.addHandler(rich_handler)

    log_path = DEFAULT_LOG_PATH
    file_fmt = logging.Formatter("[%(asctime)s] %(levelname)-8s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_path)
    except PermissionError:
        log_path = FALLBACK_LOG_PATH
        log_path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_path)
        logger.warning("Cannot write to %s — falling back to %s", DEFAULT_LOG_PATH, log_path)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(file_fmt)
    logger.addHandler(fh)
    return logger


log = _configure_logging()

# ---------------------------------------------------------------------------
# OSV cache
# ---------------------------------------------------------------------------


class OsvCache:
    def __init__(self, path: Path = CACHE_PATH, ttl: int = CACHE_TTL_SECONDS) -> None:
        self._path = path
        self._ttl = ttl
        self._store: dict[str, Any] = self._load()

    def _load(self) -> dict[str, Any]:
        if not self._path.exists():
            return {}
        try:
            data = json.loads(self._path.read_text())
            if isinstance(data, dict):
                return data
        except (json.JSONDecodeError, OSError):
            pass
        return {}

    def _save(self) -> None:
        try:
            self._path.write_text(json.dumps(self._store, default=str) + "\n")
        except OSError as exc:
            log.warning("Failed to write OSV cache: %s", exc)

    @staticmethod
    def _key(name: str, version: str) -> str:
        return hashlib.sha256(f"{name}=={version}".encode()).hexdigest()[:16]

    def get(self, name: str, version: str) -> list[dict[str, Any]] | None:
        entry = self._store.get(self._key(name, version))
        if entry is None:
            return None
        if time.time() - entry.get("ts", 0) > self._ttl:
            return None
        return entry.get("vulns")

    def put(self, name: str, version: str, vulns: list[dict[str, Any]]) -> None:
        self._store[self._key(name, version)] = {"ts": time.time(), "vulns": vulns}

    def flush(self) -> None:
        self._save()

    @property
    def size(self) -> int:
        return len(self._store)


# ---------------------------------------------------------------------------
# CISA KEV catalog
# ---------------------------------------------------------------------------


class KevCatalog:
    """CISA Known Exploited Vulnerabilities catalog with 24h file cache."""

    def __init__(self) -> None:
        self._entries: dict[str, dict[str, Any]] = {}

    async def load(self, progress: Progress, task_id: int) -> None:
        progress.update(task_id, total=1)

        # Try local file cache first
        if KEV_CACHE_PATH.exists():
            try:
                cached = json.loads(KEV_CACHE_PATH.read_text())
                if time.time() - cached.get("_ts", 0) < KEV_CACHE_TTL:
                    self._entries = {v["cveID"]: v for v in cached.get("vulnerabilities", [])}
                    log.info("CISA KEV loaded from cache (%d entries)", len(self._entries))
                    progress.advance(task_id)
                    return
            except (json.JSONDecodeError, OSError, KeyError):
                pass

        try:
            import httpx
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(CISA_KEV_URL)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            log.warning("Failed to fetch CISA KEV catalog: %s", exc)
            progress.advance(task_id)
            return

        vulns = data.get("vulnerabilities", [])
        self._entries = {v["cveID"]: v for v in vulns}
        log.info("CISA KEV catalog loaded (%d entries, version %s)",
                 len(self._entries), data.get("catalogVersion", "?"))

        try:
            cache_data = {"_ts": time.time(), "vulnerabilities": vulns}
            KEV_CACHE_PATH.write_text(json.dumps(cache_data) + "\n")
        except OSError:
            pass

        progress.advance(task_id)

    def lookup(self, cve_id: str) -> dict[str, Any] | None:
        return self._entries.get(cve_id)

    @property
    def size(self) -> int:
        return len(self._entries)


# ---------------------------------------------------------------------------
# Severity extraction & remediation logic
# ---------------------------------------------------------------------------


def _parse_cvss_score(vector: str) -> float | None:
    for part in vector.split("/"):
        if part.startswith("CVSS:"):
            continue
        if ":" in part:
            key, _, val = part.partition(":")
            if key in ("BS", "score"):
                try:
                    return float(val)
                except ValueError:
                    pass
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" in part:
            k, _, v = part.partition(":")
            metrics[k] = v
    ci = metrics.get("C", "N")
    ii = metrics.get("I", "N")
    ai = metrics.get("A", "N")
    if ci == "N" and ii == "N" and ai == "N":
        return 0.0
    base = 0.0
    base += {"N": 3.0, "A": 2.0, "L": 1.5, "P": 0.5}.get(metrics.get("AV", "N"), 1.0)
    base += {"L": 1.5, "H": 0.5}.get(metrics.get("AC", "L"), 1.0)
    base += {"N": 2.0, "L": 1.0, "H": 0.5}.get(metrics.get("PR", "N"), 1.0)
    base += {"N": 1.5, "R": 0.5}.get(metrics.get("UI", "N"), 1.0)
    base += 0.5 if metrics.get("S") == "C" else 0.0
    base += {"H": 1.5, "L": 0.5, "N": 0.0}.get(ci, 0.0)
    base += {"H": 1.5, "L": 0.5, "N": 0.0}.get(ii, 0.0)
    base += {"H": 1.5, "L": 0.5, "N": 0.0}.get(ai, 0.0)
    return min(base, 10.0)


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "UNKNOWN"


def _extract_severity(vuln: dict[str, Any]) -> str:
    for entry in vuln.get("severity") or []:
        score_str = entry.get("score", "")
        if entry.get("type") == "CVSS_V3" and score_str:
            score = _parse_cvss_score(score_str)
            if score is not None:
                return _score_to_severity(score)
    db_severity = vuln.get("database_specific", {}).get("severity")
    if isinstance(db_severity, str) and db_severity.upper() in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return db_severity.upper()
    return "UNKNOWN"


def _extract_fixed_version(vuln: dict[str, Any], ecosystem: str) -> str | None:
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem", "").upper() == ecosystem.upper() or not pkg.get("ecosystem"):
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
    return None


def _extract_cve_aliases(vuln: dict[str, Any]) -> list[str]:
    cves: list[str] = []
    vuln_id = vuln.get("id", "")
    if vuln_id.startswith("CVE-"):
        cves.append(vuln_id)
    for alias in vuln.get("aliases") or []:
        if alias.startswith("CVE-") and alias not in cves:
            cves.append(alias)
    return cves


def _extract_poc_links(vuln: dict[str, Any]) -> list[str]:
    links: list[str] = []
    for ref in vuln.get("references") or []:
        url = ref.get("url", "")
        if url and POC_URL_PATTERNS.search(url):
            links.append(url)
    return links


def _build_recommendation(fixed_version: str | None, pkg_name: str) -> str:
    if fixed_version:
        return f"Upgrade to version {fixed_version}"
    return f"No fixed version available — review {pkg_name} for alternatives or apply compensating controls"


def parse_vuln_details(raw_vulns: list[dict[str, Any]], ecosystem: str, pkg_name: str) -> list[VulnDetail]:
    details: list[VulnDetail] = []
    for v in raw_vulns:
        severity = _extract_severity(v)
        fixed = _extract_fixed_version(v, ecosystem)
        poc_links = _extract_poc_links(v)
        details.append(VulnDetail(
            vuln_id=v.get("id", "UNKNOWN"),
            severity=severity,
            summary=v.get("summary", "No description available")[:200],
            fixed_version=fixed,
            recommendation=_build_recommendation(fixed, pkg_name),
            poc_links=poc_links,
        ))
    return details


# ---------------------------------------------------------------------------
# Package extraction helpers
# ---------------------------------------------------------------------------


def _run(cmd: list[str], timeout: int = 120) -> str | None:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        if result.returncode == 0:
            return result.stdout
        log.debug("Command %s exited %d: %s", cmd, result.returncode, result.stderr.strip())
    except FileNotFoundError:
        log.debug("Binary not found: %s", cmd[0])
    except subprocess.TimeoutExpired:
        log.warning("Command timed out: %s", " ".join(cmd))
    return None


# ---------------------------------------------------------------------------
# Package extraction — OS level
# ---------------------------------------------------------------------------


def extract_os_packages(progress: Progress, task_id: int) -> list[Package]:
    packages: list[Package] = []
    if shutil.which("rpm"):
        log.info("Detected RPM-based system — querying rpm database")
        raw = _run(["rpm", "-qa", "--queryformat", "%{NAME}\\t%{VERSION}-%{RELEASE}\\n"])
        if raw:
            lines = raw.strip().splitlines()
            progress.update(task_id, total=len(lines))
            for line in lines:
                parts = line.split("\t", 1)
                if len(parts) == 2:
                    packages.append(Package(name=parts[0], version=parts[1], ecosystem="RPM"))
                progress.advance(task_id)
            log.info("Extracted %d RPM packages", len(packages))
            return packages
        raw = _run(["dnf", "list", "installed", "-q"])
        if raw:
            lines = raw.strip().splitlines()
            progress.update(task_id, total=len(lines))
            for line in lines:
                tokens = line.split()
                if len(tokens) >= 2 and "." in tokens[0]:
                    packages.append(Package(name=tokens[0].rsplit(".", 1)[0], version=tokens[1], ecosystem="RPM"))
                progress.advance(task_id)
            log.info("Extracted %d RPM packages via dnf", len(packages))
            return packages
    if shutil.which("dpkg-query"):
        log.info("Detected Debian-based system — querying dpkg database")
        raw = _run(["dpkg-query", "-W", "-f=${Package}\\t${Version}\\n"])
        if raw:
            lines = raw.strip().splitlines()
            progress.update(task_id, total=len(lines))
            for line in lines:
                parts = line.split("\t", 1)
                if len(parts) == 2:
                    packages.append(Package(name=parts[0], version=parts[1], ecosystem="Debian"))
                progress.advance(task_id)
            log.info("Extracted %d Debian packages", len(packages))
            return packages
    log.warning("No supported OS package manager found")
    progress.update(task_id, total=1, completed=1)
    return packages


def extract_python_packages(progress: Progress, task_id: int) -> list[Package]:
    packages: list[Package] = []
    pip_bin = shutil.which("pip3") or shutil.which("pip")
    if not pip_bin:
        log.warning("pip not found — skipping Python package extraction")
        progress.update(task_id, total=1, completed=1)
        return packages
    raw = _run([pip_bin, "freeze", "--all"])
    if not raw:
        log.warning("pip freeze returned no data")
        progress.update(task_id, total=1, completed=1)
        return packages
    lines = raw.strip().splitlines()
    progress.update(task_id, total=len(lines))
    for line in lines:
        line = line.strip()
        if "==" in line:
            name, _, version = line.partition("==")
            packages.append(Package(name=name.strip(), version=version.strip(), ecosystem="PyPI"))
        progress.advance(task_id)
    log.info("Extracted %d Python (PyPI) packages", len(packages))
    return packages


def extract_npm_packages(progress: Progress, task_id: int) -> list[Package]:
    packages: list[Package] = []
    if not shutil.which("npm"):
        log.info("npm not found — skipping NPM extraction")
        progress.update(task_id, total=1, completed=1)
        return packages
    raw = _run(["npm", "list", "-g", "--depth=0", "--json"])
    if not raw:
        log.warning("npm list returned no data")
        progress.update(task_id, total=1, completed=1)
        return packages
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        log.warning("npm list returned invalid JSON")
        progress.update(task_id, total=1, completed=1)
        return packages
    deps = data.get("dependencies", {})
    progress.update(task_id, total=max(len(deps), 1))
    for name, info in deps.items():
        packages.append(Package(name=name, version=info.get("version", "unknown"), ecosystem="NPM"))
        progress.advance(task_id)
    log.info("Extracted %d NPM global packages", len(packages))
    return packages


def extract_podman_containers(progress: Progress, task_id: int) -> list[Package]:
    packages: list[Package] = []
    if not shutil.which("podman"):
        log.info("podman not found — skipping container extraction")
        progress.update(task_id, total=1, completed=1)
        return packages
    raw = _run(["podman", "ps", "-q", "--no-trunc"])
    if not raw or not raw.strip():
        log.info("No running Podman containers found")
        progress.update(task_id, total=1, completed=1)
        return packages
    container_ids = raw.strip().splitlines()
    log.info("Found %d running Podman container(s) — scanning packages", len(container_ids))
    progress.update(task_id, total=len(container_ids))
    for cid in container_ids:
        cid = cid.strip()[:12]
        rpm_out = _run(["podman", "exec", cid, "rpm", "-qa", "--queryformat",
                        "%{NAME}\\t%{VERSION}-%{RELEASE}\\n"], timeout=30)
        if rpm_out:
            for line in rpm_out.strip().splitlines():
                parts = line.split("\t", 1)
                if len(parts) == 2:
                    packages.append(Package(name=f"{parts[0]} [{cid}]", version=parts[1], ecosystem="Podman-RPM"))
        else:
            dpkg_out = _run(["podman", "exec", cid, "dpkg-query", "-W",
                             "-f=${Package}\\t${Version}\\n"], timeout=30)
            if dpkg_out:
                for line in dpkg_out.strip().splitlines():
                    parts = line.split("\t", 1)
                    if len(parts) == 2:
                        packages.append(Package(name=f"{parts[0]} [{cid}]", version=parts[1], ecosystem="Podman-DEB"))
        progress.advance(task_id)
    log.info("Extracted %d packages from Podman containers", len(packages))
    return packages


# ---------------------------------------------------------------------------
# Delta / Diff scanning
# ---------------------------------------------------------------------------


def _version_tuple(v: str) -> tuple[int | str, ...]:
    parts: list[int | str] = []
    for seg in re.split(r"[.\-]", v):
        try:
            parts.append(int(seg))
        except ValueError:
            parts.append(seg)
    return tuple(parts)


def compute_diff(current: list[Package], state_path: Path = DIFF_STATE_PATH) -> dict[str, int]:
    prev_map: dict[str, str] = {}
    if state_path.exists():
        try:
            prev_data = json.loads(state_path.read_text())
            for p in prev_data.get("packages", []):
                prev_map[f"{p['ecosystem']}::{p['name']}"] = p["version"]
        except (json.JSONDecodeError, OSError, KeyError):
            log.warning("Could not read previous state from %s — treating all as new", state_path)

    counts = {"new": 0, "removed": 0, "upgraded": 0, "downgraded": 0, "unchanged": 0}
    curr_map: dict[str, Package] = {}
    for pkg in current:
        key = f"{pkg.ecosystem}::{pkg.name}"
        curr_map[key] = pkg
        if key not in prev_map:
            pkg.diff_label = "[NEW]"
            counts["new"] += 1
        elif prev_map[key] == pkg.version:
            counts["unchanged"] += 1
        else:
            try:
                if _version_tuple(pkg.version) < _version_tuple(prev_map[key]):
                    pkg.diff_label = "[DOWNGRADED]"
                    counts["downgraded"] += 1
                else:
                    pkg.diff_label = "[UPGRADED]"
                    counts["upgraded"] += 1
            except TypeError:
                pkg.diff_label = "[UPGRADED]"
                counts["upgraded"] += 1
    for key in prev_map:
        if key not in curr_map:
            counts["removed"] += 1

    state_data = {"ts": datetime.now(timezone.utc).isoformat(), "packages": [asdict(p) for p in current]}
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(state_data, default=str) + "\n")
    except OSError as exc:
        log.warning("Could not save diff state: %s", exc)
    return counts


# ---------------------------------------------------------------------------
# Heuristic IOC scanner (zero-day catcher for [NEW] packages)
# ---------------------------------------------------------------------------


def _find_package_dir(pkg_name: str, ecosystem: str) -> Path | None:
    """Locate the installed package directory on disk."""
    if ecosystem == "PyPI":
        normalized = pkg_name.lower().replace("-", "_")
        candidates = site.getsitepackages() + [site.getusersitepackages()]
        for sp in candidates:
            sp_path = Path(sp)
            if not sp_path.is_dir():
                continue
            for d in sp_path.iterdir():
                if d.is_dir() and d.name.lower().replace("-", "_").startswith(normalized):
                    return d
    elif ecosystem == "NPM":
        npm_root = _run(["npm", "root", "-g"])
        if npm_root:
            candidate = Path(npm_root.strip()) / pkg_name
            if candidate.is_dir():
                return candidate
    return None


def scan_heuristics(
    pkg: Package,
    progress: Progress,
    task_id: int,
) -> VulnDetail | None:
    """Scan source files of a [NEW] package for suspicious patterns."""

    pkg_dir = _find_package_dir(pkg.name, pkg.ecosystem)
    if pkg_dir is None or not pkg_dir.is_dir():
        progress.advance(task_id)
        return None

    suffixes = {".py", ".js"} if pkg.ecosystem in ("PyPI", "NPM") else {".py"}
    findings: list[str] = []
    files_scanned = 0
    max_files = 500
    max_file_size = 512 * 1024

    try:
        for fpath in pkg_dir.rglob("*"):
            if files_scanned >= max_files:
                break
            if not fpath.is_file() or fpath.suffix not in suffixes:
                continue
            if fpath.stat().st_size > max_file_size:
                continue
            files_scanned += 1
            try:
                content = fpath.read_text(errors="ignore")
            except OSError:
                continue
            for label, pattern in HEURISTIC_PATTERNS:
                if pattern.search(content):
                    rel = fpath.relative_to(pkg_dir)
                    findings.append(f"{label} in {rel}")
    except OSError:
        pass

    progress.advance(task_id)

    if not findings:
        return None

    log.warning("Heuristic IOC detected in %s==%s: %s", pkg.name, pkg.version, "; ".join(findings[:5]))
    return VulnDetail(
        vuln_id="MALICIOUS_HEURISTIC",
        severity="CRITICAL",
        summary=f"Suspicious code patterns detected: {'; '.join(findings[:5])}",
        fixed_version=None,
        recommendation=f"IMMEDIATE ACTION: Quarantine {pkg.name} — manual review required",
    )


# ---------------------------------------------------------------------------
# OSV.dev integration (async batch query with enrichment)
# ---------------------------------------------------------------------------


async def _fetch_vuln_detail(
    client: Any, vuln_id: str, semaphore: asyncio.Semaphore,
) -> dict[str, Any] | None:
    async with semaphore:
        try:
            resp = await client.get(f"{OSV_VULN_URL}{vuln_id}")
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            log.debug("Failed to fetch vuln %s: %s", vuln_id, exc)
            return None


async def _enrich_vulns(
    client: Any, pkg_vuln_map: dict[str, list[str]],
    progress: Progress, enrich_task: int,
) -> dict[str, dict[str, Any]]:
    all_ids: set[str] = set()
    for ids in pkg_vuln_map.values():
        all_ids.update(ids)
    if not all_ids:
        return {}
    progress.update(enrich_task, total=len(all_ids))
    log.info("Enriching %d unique vulnerability records …", len(all_ids))
    semaphore = asyncio.Semaphore(OSV_ENRICH_CONCURRENCY)
    enriched: dict[str, dict[str, Any]] = {}
    tasks = {vid: asyncio.create_task(_fetch_vuln_detail(client, vid, semaphore)) for vid in all_ids}
    for vid, task in tasks.items():
        result = await task
        if result is not None:
            enriched[vid] = result
        progress.advance(enrich_task)
    return enriched


async def query_osv_batch(
    packages: list[Package], progress: Progress, task_id: int,
    cache: OsvCache | None = None,
) -> tuple[list[VulnResult], dict[str, dict[str, Any]]]:
    enriched_all: dict[str, dict[str, Any]] = {}
    try:
        import httpx
    except ImportError:
        log.error("httpx is required for OSV queries — install with: pip install httpx")
        progress.update(task_id, total=1, completed=1)
        return [], enriched_all

    pypi_pkgs = [p for p in packages if p.ecosystem == "PyPI"]
    if not pypi_pkgs:
        log.info("No PyPI packages to check against OSV")
        progress.update(task_id, total=1, completed=1)
        return [], enriched_all

    progress.update(task_id, total=len(pypi_pkgs))
    results: list[VulnResult] = []
    to_query: list[Package] = []

    if cache is not None:
        for pkg in pypi_pkgs:
            cached = cache.get(pkg.name, pkg.version)
            if cached is not None:
                for rv in cached:
                    vid = rv.get("id", "")
                    if vid:
                        enriched_all[vid] = rv
                details = parse_vuln_details(cached, pkg.ecosystem, pkg.name)
                results.append(VulnResult(package=pkg, vulns=details))
                progress.advance(task_id)
            else:
                to_query.append(pkg)
        if results:
            log.info("Cache hit for %d/%d packages", len(results), len(pypi_pkgs))
    else:
        to_query = pypi_pkgs

    if not to_query:
        return results, enriched_all

    log.info("Querying OSV.dev for %d PyPI packages …", len(to_query))
    pkg_vuln_ids: dict[int, list[str]] = {}

    async with httpx.AsyncClient(timeout=30.0) as client:
        for offset in range(0, len(to_query), OSV_BATCH_SIZE):
            chunk = to_query[offset : offset + OSV_BATCH_SIZE]
            payload = {"queries": [
                {"package": {"name": p.name, "ecosystem": "PyPI"}, "version": p.version}
                for p in chunk
            ]}
            try:
                resp = await client.post(OSV_BATCH_URL, json=payload)
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                log.error("OSV batch query failed: %s", exc)
                for i in range(len(chunk)):
                    pkg_vuln_ids[offset + i] = []
                continue
            for i, entry in enumerate(data.get("results", [])):
                pkg_vuln_ids[offset + i] = [v.get("id", "") for v in entry.get("vulns", []) if v.get("id")]

        all_vuln_id_map: dict[str, list[str]] = {}
        for idx, vids in pkg_vuln_ids.items():
            all_vuln_id_map[f"{to_query[idx].name}=={to_query[idx].version}"] = vids

        enrich_task = progress.add_task("[magenta]Enriching vulnerability data …", total=None)
        enriched = await _enrich_vulns(client, all_vuln_id_map, progress, enrich_task)
        enriched_all.update(enriched)

        for idx in range(len(to_query)):
            pkg = to_query[idx]
            vids = pkg_vuln_ids.get(idx, [])
            full_vulns = [enriched[vid] for vid in vids if vid in enriched]
            if cache is not None:
                cache.put(pkg.name, pkg.version, full_vulns)
            results.append(VulnResult(package=pkg, vulns=parse_vuln_details(full_vulns, pkg.ecosystem, pkg.name)))
            progress.advance(task_id)

    if cache is not None:
        cache.flush()
        log.info("OSV cache updated (%d entries)", cache.size)

    vulnerable_count = sum(1 for r in results if r.vulns)
    log.info("OSV check complete — %d/%d packages have known vulnerabilities", vulnerable_count, len(results))
    return results, enriched_all


# ---------------------------------------------------------------------------
# EPSS + KEV enrichment
# ---------------------------------------------------------------------------


def _collect_cve_map(
    osv_results: list[VulnResult],
    enriched_vulns: dict[str, dict[str, Any]],
) -> dict[str, list[VulnDetail]]:
    cve_to_details: dict[str, list[VulnDetail]] = {}
    for result in osv_results:
        for vd in result.vulns:
            cves: list[str] = []
            if vd.vuln_id.startswith("CVE-"):
                cves.append(vd.vuln_id)
            raw = enriched_vulns.get(vd.vuln_id)
            if raw:
                for alias in _extract_cve_aliases(raw):
                    if alias not in cves:
                        cves.append(alias)
            for cve in cves:
                cve_to_details.setdefault(cve, []).append(vd)
    return cve_to_details


async def query_epss(
    osv_results: list[VulnResult],
    enriched_vulns: dict[str, dict[str, Any]],
    progress: Progress, task_id: int,
) -> None:
    try:
        import httpx
    except ImportError:
        progress.update(task_id, total=1, completed=1)
        return

    cve_map = _collect_cve_map(osv_results, enriched_vulns)
    if not cve_map:
        log.info("No CVE aliases found — skipping EPSS lookup")
        progress.update(task_id, total=1, completed=1)
        return

    all_cves = list(cve_map.keys())
    progress.update(task_id, total=len(all_cves))
    log.info("Querying EPSS scores for %d CVEs …", len(all_cves))

    async with httpx.AsyncClient(timeout=20.0) as client:
        for offset in range(0, len(all_cves), EPSS_BATCH_SIZE):
            chunk = all_cves[offset : offset + EPSS_BATCH_SIZE]
            try:
                resp = await client.get(EPSS_API_URL, params={"cve": ",".join(chunk)})
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                log.warning("EPSS query failed: %s", exc)
                progress.advance(task_id, advance=len(chunk))
                continue
            for entry in data.get("data", []):
                cve_id = entry.get("cve", "")
                try:
                    score = float(entry.get("epss", 0))
                    percentile = float(entry.get("percentile", 0))
                except (ValueError, TypeError):
                    score, percentile = 0.0, 0.0
                for vd in cve_map.get(cve_id, []):
                    if vd.epss_score is None or score > vd.epss_score:
                        vd.epss_score = score
                        vd.epss_percentile = percentile
            progress.advance(task_id, advance=len(chunk))

    scored = sum(1 for dlist in cve_map.values() for vd in dlist if vd.epss_score is not None)
    log.info("EPSS enrichment complete — scored %d vuln entries", scored)


def apply_kev(
    osv_results: list[VulnResult],
    enriched_vulns: dict[str, dict[str, Any]],
    kev: KevCatalog,
) -> int:
    """Cross-reference KEV catalog and set is_kev + kev_description on matching VulnDetails. Returns match count."""
    cve_map = _collect_cve_map(osv_results, enriched_vulns)
    hits = 0
    for cve_id, details in cve_map.items():
        entry = kev.lookup(cve_id)
        if entry:
            for vd in details:
                vd.is_kev = True
                vd.kev_description = entry.get("shortDescription", "")[:200]
            hits += 1
    return hits


# ---------------------------------------------------------------------------
# Webhook alerting
# ---------------------------------------------------------------------------


async def send_webhook_alert(webhook_url: str, report: ScanReport) -> None:
    try:
        import httpx
    except ImportError:
        log.error("httpx required for webhook — skipping alert")
        return
    if report.osv_results is None:
        return

    critical_pkgs: list[str] = []
    kev_hits: list[str] = []
    for r in report.osv_results:
        for v in r.vulns:
            if v.severity == "CRITICAL":
                critical_pkgs.append(f"{r.package.name}=={r.package.version}")
                break
        for v in r.vulns:
            if v.is_kev:
                kev_hits.append(f"{v.vuln_id} on {r.package.name}")

    if not critical_pkgs and not kev_hits:
        log.info("No CRITICAL/KEV findings — webhook alert not triggered")
        return

    lines = [f"*OpenBOM Alert* — `{report.hostname}`"]
    if critical_pkgs:
        lines.append(f"*{len(critical_pkgs)} CRITICAL* package(s):")
        lines.extend(f"  • `{p}`" for p in critical_pkgs[:15])
    if kev_hits:
        lines.append(f"\n*{len(kev_hits)} CISA KEV* match(es):")
        lines.extend(f"  • `{h}`" for h in kev_hits[:10])
    lines.append(f"\nScan time: {report.scan_ts}")

    payload = {"text": "\n".join(lines), "title": f"OpenBOM Alert — {report.hostname}"}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(webhook_url, json=payload)
            resp.raise_for_status()
        log.info("Webhook alert sent to %s", webhook_url[:50])
    except Exception as exc:
        log.error("Webhook delivery failed: %s", exc)


# ---------------------------------------------------------------------------
# Rich terminal output
# ---------------------------------------------------------------------------


def render_summary_table(report: ScanReport) -> None:
    console.print()

    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold cyan")
    info.add_column()
    info.add_row("Hostname", report.hostname)
    info.add_row("Scan Time", report.scan_ts)
    info.add_row("Total Packages", str(len(report.packages)))
    eco_counts: dict[str, int] = {}
    for p in report.packages:
        eco_counts[p.ecosystem] = eco_counts.get(p.ecosystem, 0) + 1
    for eco, cnt in sorted(eco_counts.items()):
        info.add_row(f"{eco} Packages", str(cnt))
    console.print(Panel(info, title="[bold]OpenBOM Scan Summary[/bold]", border_style="blue", expand=False))

    if report.diff_summary:
        ds = report.diff_summary
        diff_parts: list[str] = []
        if ds.get("new"):
            diff_parts.append(f"[green]+{ds['new']} new[/green]")
        if ds.get("removed"):
            diff_parts.append(f"[red]-{ds['removed']} removed[/red]")
        if ds.get("upgraded"):
            diff_parts.append(f"[cyan]{ds['upgraded']} upgraded[/cyan]")
        if ds.get("downgraded"):
            diff_parts.append(f"[yellow]{ds['downgraded']} downgraded[/yellow]")
        if ds.get("unchanged"):
            diff_parts.append(f"[dim]{ds['unchanged']} unchanged[/dim]")
        if diff_parts:
            console.print(Panel("  ".join(diff_parts), title="[bold]Delta from Last Scan[/bold]",
                                border_style="yellow", expand=False))

    if report.osv_results is None:
        return

    vulnerable = [r for r in report.osv_results if r.vulns]
    if not vulnerable:
        console.print(Panel("[bold green]No known vulnerabilities found.[/bold green]",
                            title="OSV Results", border_style="green", expand=False))
        return

    d = report.to_dict()
    summary = d.get("osv_summary", {})

    # --- KEV alert panel ---
    kev_findings = [(r, v) for r in vulnerable for v in r.vulns if v.is_kev]
    if kev_findings:
        kev_lines: list[str] = []
        for r, v in kev_findings:
            kev_lines.append(
                f"  [blink bold bright_red]>>> {v.vuln_id}[/blink bold bright_red]"
                f" on [bold]{r.package.name}=={r.package.version}[/bold]"
            )
            if v.kev_description:
                kev_lines.append(f"      [dim]{v.kev_description[:120]}[/dim]")
        console.print(Panel(
            "\n".join(kev_lines),
            title=f"[blink bold bright_red]CISA KEV — {len(kev_findings)} ACTIVELY EXPLOITED[/blink bold bright_red]",
            border_style="bright_red",
            expand=False,
        ))

    # --- Heuristic IOC panel ---
    heuristic_findings = [(r, v) for r in vulnerable for v in r.vulns if v.vuln_id == "MALICIOUS_HEURISTIC"]
    if heuristic_findings:
        h_lines: list[str] = []
        for r, v in heuristic_findings:
            h_lines.append(
                f"  [blink bold bright_red]MALWARE[/blink bold bright_red]"
                f" [bold]{r.package.name}=={r.package.version}[/bold]"
            )
            h_lines.append(f"      [yellow]{v.summary[:140]}[/yellow]")
        console.print(Panel(
            "\n".join(h_lines),
            title="[blink bold bright_red]HEURISTIC IOC — POSSIBLE SUPPLY-CHAIN ATTACK[/blink bold bright_red]",
            border_style="bright_red",
            expand=False,
        ))

    # --- Severity metrics ---
    sev_table = Table(title="Vulnerability Metrics", show_header=True, header_style="bold")
    sev_table.add_column("Severity", justify="center")
    sev_table.add_column("Count", justify="center")
    for sev, color in [("CRITICAL", "bold red"), ("HIGH", "red"), ("MEDIUM", "yellow"), ("LOW", "green")]:
        cnt = summary.get(f"total_{sev.lower()}", 0)
        if cnt > 0:
            sev_table.add_row(Text(sev, style=color), Text(str(cnt), style=color))
    unknown_cnt = summary.get("total_unknown", 0)
    if unknown_cnt > 0:
        sev_table.add_row(Text("UNKNOWN", style="dim"), str(unknown_cnt))
    if summary.get("kev_hits"):
        sev_table.add_row(Text("CISA KEV", style="blink bold bright_red"), Text(str(summary["kev_hits"]), style="bold bright_red"))
    if summary.get("poc_count"):
        sev_table.add_row(Text("Has PoC", style="bold yellow"), Text(str(summary["poc_count"]), style="bold yellow"))
    console.print(sev_table)
    console.print()

    # --- Detailed findings ---
    detail_table = Table(title="Vulnerable Packages", show_header=True, header_style="bold magenta", show_lines=True)
    detail_table.add_column("#", justify="right", style="dim", width=4)
    detail_table.add_column("Package", style="bold", min_width=16)
    detail_table.add_column("Version", min_width=8)
    detail_table.add_column("Vuln ID", min_width=20)
    detail_table.add_column("Severity", justify="center", min_width=10)
    detail_table.add_column("EPSS", justify="center", min_width=7)
    detail_table.add_column("Intel", justify="center", min_width=8)
    detail_table.add_column("Recommendation", min_width=24)

    sev_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green", "UNKNOWN": "dim"}

    idx = 0
    for r in vulnerable:
        pkg_label = r.package.name
        if r.package.diff_label:
            pkg_label = f"{r.package.diff_label} {pkg_label}"
        for v in r.vulns:
            idx += 1
            color = sev_colors.get(v.severity, "white")
            if v.epss_score is not None:
                pct = v.epss_score * 100
                epss_style = "bold red" if pct >= 10 else ("yellow" if pct >= 1 else "dim")
                epss_obj = Text(f"{pct:.1f}%", style=epss_style)
            else:
                epss_obj = Text("—", style="dim")

            intel_parts: list[str] = []
            if v.is_kev:
                intel_parts.append("[blink bold bright_red]KEV[/blink bold bright_red]")
            if v.poc_links:
                intel_parts.append(f"[bold yellow]PoC({len(v.poc_links)})[/bold yellow]")
            if v.vuln_id == "MALICIOUS_HEURISTIC":
                intel_parts.append("[blink bold bright_red]IOC[/blink bold bright_red]")
            intel_text = Text.from_markup(" ".join(intel_parts)) if intel_parts else Text("—", style="dim")

            detail_table.add_row(
                str(idx), pkg_label, r.package.version, v.vuln_id,
                Text(v.severity, style=color), epss_obj, intel_text, v.recommendation,
            )

    console.print(detail_table)
    console.print()

    high_epss = [(r, v) for r in vulnerable for v in r.vulns if v.epss_score is not None and v.epss_score >= 0.1]
    if high_epss:
        console.print(Panel(
            "\n".join(
                f"  [bold red]{v.vuln_id}[/bold red] on {r.package.name}=={r.package.version}"
                f" — EPSS [bold]{v.epss_score * 100:.1f}%[/bold]"
                for r, v in sorted(high_epss, key=lambda x: x[1].epss_score or 0, reverse=True)
            ),
            title=f"[bold red]High Exploit Probability ({len(high_epss)} findings with EPSS > 10%)[/bold red]",
            border_style="red", expand=False,
        ))


# ---------------------------------------------------------------------------
# Enterprise reporting — HTML + PDF
# ---------------------------------------------------------------------------


def generate_html_report(report: ScanReport) -> str:
    from jinja2 import Environment, FileSystemLoader

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    template = env.get_template("report_template.html")

    d = report.to_dict()
    eco_counts: dict[str, int] = {}
    for p in d["packages"]:
        eco_counts[p["ecosystem"]] = eco_counts.get(p["ecosystem"], 0) + 1

    return template.render(
        hostname=d["hostname"],
        scan_ts=d["scan_ts"],
        total_packages=d["total_packages"],
        ecosystem_counts=eco_counts,
        os_packages=sum(v for k, v in eco_counts.items() if k not in ("PyPI", "NPM")),
        pypi_packages=eco_counts.get("PyPI", 0),
        npm_packages=eco_counts.get("NPM", 0),
        summary=d.get("osv_summary", {}),
        vulnerabilities=d.get("osv_vulnerabilities", []),
        diff_summary=d.get("diff_summary"),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )


def write_enterprise_reports(report: ScanReport, output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d")
    html_path = output_dir / f"report_openbom_{ts}.html"
    html_content = generate_html_report(report)
    html_path.write_text(html_content)
    log.info("HTML report written to %s", html_path)

    pdf_path = output_dir / f"report_openbom_{ts}.pdf"
    try:
        from weasyprint import HTML
        HTML(string=html_content).write_pdf(str(pdf_path))
        log.info("PDF report written to %s", pdf_path)
    except ImportError:
        log.warning("weasyprint not installed — PDF generation skipped (pip install weasyprint)")
        pdf_path = Path("/dev/null")
    except Exception as exc:
        log.error("PDF generation failed: %s", exc)
        pdf_path = Path("/dev/null")
    return html_path, pdf_path


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------


def build_report(
    all_pkgs: list[Package],
    osv_results: list[VulnResult] | None = None,
    diff_summary: dict[str, int] | None = None,
) -> ScanReport:
    return ScanReport(
        hostname=socket.gethostname(),
        scan_ts=datetime.now(timezone.utc).isoformat(),
        packages=all_pkgs,
        osv_results=osv_results,
        diff_summary=diff_summary,
    )


def write_json_report(report: ScanReport, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(report.to_dict(), indent=2, default=str) + "\n")
    log.info("JSON report written to %s", dest)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="openbom_agent",
        description="OpenBOM Endpoint Agent v4 — Ultimate Threat Hunting",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--scan-only", action="store_true", help="Collect SBOM only (no network calls)")
    mode.add_argument("--check-osv", action="store_true", help="Collect SBOM + validate via OSV/EPSS/KEV")

    parser.add_argument("-o", "--output", type=Path, default=None, help="JSON report output path")
    parser.add_argument("--report", action="store_true", help="Generate HTML and PDF enterprise reports")
    parser.add_argument("--no-cache", action="store_true", help="Bypass OSV response cache")
    parser.add_argument("--diff", action="store_true", help="Compare against previous scan state")
    parser.add_argument("--webhook-url", type=str, default=None, help="POST critical/KEV alerts to this URL")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug-level console logging")
    return parser.parse_args(argv)


async def _async_main(args: argparse.Namespace) -> int:
    console.print(Panel(
        "[bold cyan]OpenBOM[/bold cyan] Endpoint Agent v4.0 — Ultimate Threat Hunting",
        subtitle=f"mode={'check-osv' if args.check_osv else 'scan-only'}",
        border_style="bright_blue", expand=False,
    ))

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(), console=console, transient=False,
    ) as progress:

        # --- Extraction ---
        os_task = progress.add_task("[cyan]Extracting OS packages …", total=None)
        os_pkgs = extract_os_packages(progress, os_task)
        py_task = progress.add_task("[green]Extracting Python packages …", total=None)
        py_pkgs = extract_python_packages(progress, py_task)
        npm_task = progress.add_task("[blue]Extracting NPM packages …", total=None)
        npm_pkgs = extract_npm_packages(progress, npm_task)
        podman_task = progress.add_task("[yellow]Scanning Podman containers …", total=None)
        podman_pkgs = extract_podman_containers(progress, podman_task)

        all_pkgs = os_pkgs + py_pkgs + npm_pkgs + podman_pkgs
        if not all_pkgs:
            log.warning("No packages found — nothing to report")
            return 1

        # --- Diff ---
        diff_summary: dict[str, int] | None = None
        if args.diff:
            diff_summary = compute_diff(all_pkgs)
            log.info("Diff: +%d new, -%d removed, %d upgraded, %d downgraded",
                     diff_summary["new"], diff_summary["removed"],
                     diff_summary["upgraded"], diff_summary["downgraded"])

        # --- Heuristic IOC scan on [NEW] packages ---
        new_pkgs = [p for p in all_pkgs if p.diff_label == "[NEW]" and p.ecosystem in ("PyPI", "NPM")]
        heuristic_results: list[VulnResult] = []
        if new_pkgs:
            h_task = progress.add_task("[bright_red]Heuristic IOC scan …", total=len(new_pkgs))
            for pkg in new_pkgs:
                finding = scan_heuristics(pkg, progress, h_task)
                if finding:
                    heuristic_results.append(VulnResult(package=pkg, vulns=[finding]))
        else:
            if args.diff:
                log.info("No [NEW] packages — heuristic IOC scan skipped")

        # --- OSV + EPSS + KEV ---
        osv_results: list[VulnResult] | None = None
        enriched_vulns: dict[str, dict[str, Any]] = {}
        kev = KevCatalog()

        if args.check_osv:
            cache = None if args.no_cache else OsvCache()
            osv_task = progress.add_task("[yellow]Querying OSV.dev …", total=None)
            osv_results, enriched_vulns = await query_osv_batch(all_pkgs, progress, osv_task, cache)

            # EPSS + KEV run in parallel
            kev_task = progress.add_task("[bright_red]Loading CISA KEV catalog …", total=None)
            epss_task = progress.add_task("[red]Querying EPSS scores …", total=None)
            await asyncio.gather(
                kev.load(progress, kev_task),
                query_epss(osv_results, enriched_vulns, progress, epss_task),
            )

            if kev.size > 0:
                kev_hits = apply_kev(osv_results, enriched_vulns, kev)
                log.info("KEV cross-reference: %d match(es) against %d catalog entries", kev_hits, kev.size)

            # Merge heuristic results into osv_results
            if heuristic_results:
                osv_results.extend(heuristic_results)
        elif heuristic_results:
            osv_results = heuristic_results

    # --- Terminal summary ---
    report = build_report(all_pkgs, osv_results, diff_summary)
    render_summary_table(report)

    # --- JSON report ---
    dest = args.output
    if dest is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        dest = DEFAULT_OUTPUT_DIR / f"sbom_{ts}.json"
    write_json_report(report, dest)

    # --- Enterprise HTML/PDF ---
    if args.report:
        if not args.check_osv:
            log.warning("--report requires --check-osv to produce vulnerability data")
        else:
            html_path, pdf_path = write_enterprise_reports(report, DEFAULT_OUTPUT_DIR)
            if pdf_path != Path("/dev/null"):
                console.print(Panel(
                    f"[bold green]Reports generated:[/bold green]\n  HTML: {html_path}\n  PDF:  {pdf_path}",
                    border_style="green", expand=False,
                ))

    if args.webhook_url and args.check_osv:
        await send_webhook_alert(args.webhook_url, report)

    if args.check_osv and osv_results:
        vuln_count = sum(1 for r in osv_results if r.vulns)
        return 2 if vuln_count > 0 else 0
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.verbose:
        for handler in log.handlers:
            if isinstance(handler, RichHandler):
                handler.setLevel(logging.DEBUG)
    try:
        return asyncio.run(_async_main(args))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
