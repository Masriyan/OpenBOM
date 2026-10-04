#!/usr/bin/env python3
"""OpenBOM Endpoint Agent v5 — Supply-Chain Threat Hunting.

Multi-ecosystem supply-chain scanner with OSV.dev vulnerability matching
(PyPI, npm, Debian, Ubuntu, AlmaLinux, Rocky Linux), EPSS exploit
prediction, CISA KEV cross-referencing, PoC/exploit link tracking,
heuristic IOC + typosquat detection, delta scanning, container
introspection, CycloneDX export, backend push and webhook alerting.

Usage:
    python3 openbom_agent.py                       # interactive menu
    python3 openbom_agent.py --scan-only
    python3 openbom_agent.py --check-osv --diff --report
    python3 openbom_agent.py --check-osv --diff --server-url http://openbom:8000
    python3 openbom_agent.py --push-file output/sbom_20260525_120258.json --server-url http://openbom:8000
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import functools
import hashlib
import importlib.metadata
import json
import logging
import os
import re
import shutil
import site
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from rich.console import Console
from rich.logging import RichHandler
from rich.markup import escape
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

AGENT_VERSION = "5.1.0"

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
OSV_BATCH_SIZE = 1000
OSV_ENRICH_CONCURRENCY = 20

EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH_SIZE = 100

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_TTL = 24 * 3600  # 24 hours
CACHE_TTL_SECONDS = 12 * 3600

HTTP_RETRIES = 3
RETRYABLE_STATUS = {429, 500, 502, 503, 504}

DEFAULT_LOG_PATH = Path("/var/log/openbom_agent.log")
FALLBACK_LOG_PATH = Path("logs/openbom_agent.log")
DEFAULT_OUTPUT_DIR = Path("output")
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
ALL_ECOSYSTEM_GROUPS = ("os", "pypi", "npm", "podman", "docker")

HEURISTIC_IDS = {"MALICIOUS_HEURISTIC", "TYPOSQUAT_SUSPECT"}

POC_URL_PATTERNS = re.compile(
    r"exploit-db\.com|packetstormsecurity\.com|/poc[/\-_]|/exploit[/\-_]|"
    r"github\.com/[^/]+/[^/]*(poc|exploit|cve-\d{4})",
    re.IGNORECASE,
)
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")
RHEL_STYLE_SEVERITY = re.compile(r"^\s*(Critical|Important|Moderate|Low)\s*:", re.IGNORECASE)

QUALITATIVE_SEVERITY = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "IMPORTANT": "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "NEGLIGIBLE": "LOW",
}

console = Console()
log = logging.getLogger("openbom")

# ---------------------------------------------------------------------------
# Heuristic IOC rules
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IocRule:
    """A source-code indicator.

    strong=True  — malicious on its own (obfuscated exec, reverse shell, miner): reported as CRITICAL.
    strong=False — common in legitimate code (credential paths in AWS SDKs, clipboard helpers shelling
                   out to powershell, Telegram integrations): only reported (HIGH) when at least
                   two different weak categories co-occur in the same package.
    """

    label: str
    strong: bool
    pattern: re.Pattern[str]


HEURISTIC_RULES: list[IocRule] = [
    IocRule("eval(base64)", True, re.compile(
        r"""eval\s*\(\s*(?:base64|__import__\s*\(\s*['"]base64['"]|Buffer\.from\s*\(|atob\s*\()""", re.IGNORECASE)),
    IocRule("exec(base64)", True, re.compile(
        r"""exec\s*\(\s*(?:base64|__import__\s*\(\s*['"]base64['"]|zlib\.decompress|marshal\.loads)""", re.IGNORECASE)),
    IocRule("os.system(url)", True, re.compile(
        r"""os\.system\s*\(\s*['"](?:https?://|curl |wget )""", re.IGNORECASE)),
    IocRule("reverse_shell", True, re.compile(
        r"""/dev/tcp/[\w.\-]+/\d+|pty\.spawn\s*\(\s*['"]/bin/(?:ba)?sh""", re.IGNORECASE)),
    IocRule("crypto_miner", True, re.compile(r"""stratum\+tcp://|\bxmrig\b|coinhive""", re.IGNORECASE)),
    IocRule("subprocess+download", False, re.compile(
        r"""subprocess\.\w+\s*\(\s*\[?\s*['"](?:curl|wget|powershell)""", re.IGNORECASE)),
    IocRule("child_process+download", False, re.compile(
        r"""\.(?:exec|execSync|spawn|spawnSync)\s*\(\s*['"`](?:curl|wget|powershell|bash -c|sh -c)""", re.IGNORECASE)),
    IocRule("paste/tunnel C2", False, re.compile(
        r"""pastebin\.com/raw|ngrok\.io|ngrok-free\.app|paste\.ee|transfer\.sh|pipedream\.net|interact\.sh|oast\.(?:fun|live|me|pro|site)""",
        re.IGNORECASE)),
    IocRule("chat exfil webhook", False, re.compile(
        r"""discord(?:app)?\.com/api/webhooks/|api\.telegram\.org/bot""", re.IGNORECASE)),
    IocRule("credential_access", False, re.compile(
        r"""\.ssh/id_(?:rsa|ed25519|ecdsa)\b|\.aws/credentials|Login Data|\.config/google-chrome""", re.IGNORECASE)),
    IocRule("suspicious_import", False, re.compile(
        r"""__import__\s*\(\s*['"](?:socket|ctypes|winreg)['"]""", re.IGNORECASE)),
]

HEURISTIC_SUFFIXES = {".py", ".pth", ".js", ".mjs", ".cjs", ".sh"}
PTH_ALLOWLIST = re.compile(r"(?:distutils-precedence|-nspkg|_virtualenv|__editable__.*)\.pth$")
NPM_INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare")
SUSPICIOUS_INSTALL_SCRIPT = re.compile(
    r"""curl\s|wget\s|\|\s*(?:ba)?sh\b|node\s+-e|base64|https?://|powershell|/dev/tcp""", re.IGNORECASE,
)
DOWNLOAD_EXEC_SCRIPT = re.compile(r"""(?:curl|wget)\s[^|;&]*\|\s*(?:ba)?sh\b|/dev/tcp/""", re.IGNORECASE)
TEST_PATH = re.compile(r"(?:^|/)(?:tests?|testing|__tests__|spec)/")
HEURISTIC_MAX_WEAK_HITS = 20
HEURISTIC_MAX_FILES = 800
HEURISTIC_MAX_FILE_SIZE = 512 * 1024
HEURISTIC_MAX_FINDINGS = 10

# ---------------------------------------------------------------------------
# Typosquat reference lists (normalised names)
# ---------------------------------------------------------------------------

POPULAR_PACKAGES: dict[str, frozenset[str]] = {
    "PyPI": frozenset({
        "requests", "urllib3", "numpy", "pandas", "boto3", "botocore", "setuptools", "certifi",
        "charset-normalizer", "python-dateutil", "pyyaml", "typing-extensions", "cryptography",
        "packaging", "jinja2", "markupsafe", "pyasn1", "s3transfer", "jmespath", "click", "flask",
        "django", "pytest", "colorama", "pillow", "scipy", "matplotlib", "protobuf", "grpcio",
        "pydantic", "sqlalchemy", "psycopg2", "pymysql", "redis", "celery", "werkzeug",
        "beautifulsoup4", "selenium", "scrapy", "tensorflow", "torch", "keras", "scikit-learn",
        "opencv-python", "openai", "anthropic", "httpx", "aiohttp", "fastapi", "uvicorn", "paramiko",
        "pycryptodome", "pyjwt", "oauthlib", "docker", "kubernetes", "ansible", "virtualenv",
        "pyopenssl", "filelock", "platformdirs", "wrapt", "decorator", "psutil", "pygments",
        "httplib2", "websocket-client", "python-dotenv", "xmltodict", "simplejson", "chardet",
        "termcolor", "colorlog", "loguru", "requests-oauthlib", "google-auth", "tornado", "gunicorn",
    }),
    "NPM": frozenset({
        "lodash", "react", "react-dom", "express", "axios", "chalk", "commander", "debug", "moment",
        "request", "typescript", "webpack", "babel-core", "eslint", "prettier", "jquery", "angular",
        "dotenv", "cross-env", "colors", "async", "underscore", "bluebird", "yargs", "minimist",
        "rimraf", "mkdirp", "semver", "socket.io", "mongoose", "body-parser", "jsonwebtoken",
        "bcrypt", "nodemon", "mocha", "electron", "puppeteer", "node-fetch", "inquirer", "fs-extra",
        "coffee-script", "event-stream", "ua-parser-js", "ts-node", "rollup", "esbuild", "gulp",
        "grunt", "karma", "tailwindcss", "postcss", "autoprefixer", "nodemailer", "dayjs", "date-fns",
        "classnames", "prop-types", "redux", "nanoid", "crypto-js", "discord.js", "tslib", "core-js",
        "mysql", "sequelize", "eslint-scope", "node-ipc", "coa", "faker", "cross-spawn",
    }),
}
TYPOSQUAT_ALLOWLIST: dict[str, frozenset[str]] = {
    # Legitimate, well-known packages that happen to be one edit away from a popular name
    "PyPI": frozenset({"pyaml", "requests-oauthlib", "colorlog", "termcolor", "jinja", "pillow-heif", "gsutil",
                       "pycryptodomex", "unicorn", "scapy", "torchx", "psycopg", "fastai", "cchardet", "dockerx",
                       "requests3", "httpx2", "paramiko-ng", "pyjwt2"}),
    "NPM": frozenset({"preact", "color", "requests", "mysql2", "classname", "chalk-template", "eslint-scope",
                      "react-is", "rollup-plugin", "async-each", "debug-log", "colors-option"}),
}

# ---------------------------------------------------------------------------
# State directory + safe file I/O
# ---------------------------------------------------------------------------


def state_dir() -> Path:
    """Private directory for caches and the diff baseline.

    Never /tmp: a world-writable location lets other local users poison the
    OSV/KEV caches (hiding findings) or plant symlinks the agent would follow.
    """
    env = os.environ.get("OPENBOM_STATE_DIR")
    if env:
        return Path(env).expanduser()
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return Path("/var/lib/openbom")
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "openbom"


def osv_cache_path() -> Path:
    return state_dir() / "osv_cache.json"


def kev_cache_path() -> Path:
    return state_dir() / "kev_cache.json"


def diff_state_path(target: str | None = None) -> Path:
    """Diff baseline per scan target — scanning a repo or image must not clobber the host baseline."""
    if not target:
        return state_dir() / "last_state.json"
    return state_dir() / f"last_state_{hashlib.sha256(target.encode()).hexdigest()[:16]}.json"


def _ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    st = path.stat()
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        raise PermissionError(f"{path} is owned by uid {st.st_uid}, refusing to use it")
    if st.st_mode & 0o022:
        with contextlib.suppress(OSError):
            path.chmod(0o700)


def _atomic_write(path: Path, text: str, mode: int = 0o600) -> None:
    """Write via temp file + rename so readers never see partial files and symlinks are replaced, not followed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _read_private_json(path: Path) -> Any | None:
    """Read JSON from the state dir, ignoring files that other users could have planted."""
    try:
        st = path.lstat()
    except OSError:
        return None
    if path.is_symlink() or (hasattr(os, "geteuid") and st.st_uid != os.geteuid()):
        log.warning("Ignoring untrusted state file %s (symlink or foreign owner)", path)
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return None


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Package:
    name: str
    version: str
    ecosystem: str
    diff_label: str | None = None
    # OSV query coordinates — differ from the display name/version for distro
    # packages (Debian source package, RPM epoch) and container packages.
    osv_ecosystem: str | None = None
    osv_name: str | None = None
    osv_version: str | None = None
    license: str | None = None
    # Where the package lives: manifest/lockfile/archive relative to the target root for path/rootfs/image
    # scans, absolute dist-info / node_modules directory for host pip/npm packages.
    location: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in fields(self)
                if getattr(self, f.name) is not None or f.name == "diff_label"}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Package:
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})

    @property
    def query_name(self) -> str:
        return self.osv_name or self.name

    @property
    def query_version(self) -> str:
        return self.osv_version or self.version


@dataclass(slots=True)
class VulnDetail:
    vuln_id: str
    severity: str
    summary: str
    fixed_version: str | None
    recommendation: str
    cvss_score: float | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    is_kev: bool = False
    kev_description: str | None = None
    is_heuristic: bool = False
    is_malicious: bool = False  # OpenSSF malicious-packages advisory (OSV MAL-*)
    poc_links: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VulnDetail:
        known = {f.name for f in fields(cls)}
        clean = {k: v for k, v in data.items() if k in known}
        clean.setdefault("severity", "UNKNOWN")
        clean.setdefault("summary", "")
        clean.setdefault("fixed_version", None)
        clean.setdefault("recommendation", "")
        if clean.get("vuln_id") in HEURISTIC_IDS:
            clean["is_heuristic"] = True
        if str(clean.get("vuln_id", "")).startswith("MAL-"):
            clean["is_malicious"] = True
        return cls(**clean)


@dataclass(slots=True)
class VulnResult:
    package: Package
    vulns: list[VulnDetail] = field(default_factory=list)

    @property
    def max_severity(self) -> str:
        if not self.vulns:
            return "UNKNOWN"
        return min(self.vulns, key=lambda v: SEVERITY_ORDER.get(v.severity, 99)).severity


@dataclass(slots=True)
class ScanReport:
    hostname: str
    scan_ts: str
    packages: list[Package]
    osv_results: list[VulnResult] | None = None
    diff_summary: dict[str, int] | None = None
    removed_packages: list[str] | None = None
    os_info: dict[str, str] | None = None
    queried: int = 0
    agent_version: str = AGENT_VERSION
    scan_target: dict[str, str] | None = None
    eol: list[dict[str, Any]] | None = None
    license_violations: list[dict[str, str]] | None = None
    suppressed: list[dict[str, str]] | None = None

    @property
    def vulnerable(self) -> list[VulnResult]:
        return [r for r in self.osv_results or [] if r.vulns]

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "hostname": self.hostname,
            "scan_ts": self.scan_ts,
            "agent_version": self.agent_version,
            "os": self.os_info or {},
            "total_packages": len(self.packages),
            "packages": [self._package_dict(p) for p in self.packages],
        }
        for key in ("scan_target", "eol", "license_violations", "suppressed"):
            value = getattr(self, key)
            if value is not None:
                data[key] = value
        if self.diff_summary is not None:
            data["diff_summary"] = self.diff_summary
            data["removed_packages"] = self.removed_packages or []
        if self.osv_results is not None:
            vulnerable = self.vulnerable
            metrics = self._severity_metrics(vulnerable)
            data["osv_summary"] = {
                "queried": self.queried,
                "vulnerable": len(vulnerable),
                "kev_hits": sum(1 for r in vulnerable for v in r.vulns if v.is_kev),
                "poc_count": sum(1 for r in vulnerable for v in r.vulns if v.poc_links),
                "heuristic_hits": sum(1 for r in vulnerable for v in r.vulns if v.is_heuristic),
                "malicious_hits": sum(1 for r in vulnerable for v in r.vulns if v.is_malicious),
                **metrics,
            }
            data["osv_vulnerabilities"] = [
                {
                    "package": r.package.to_dict(),
                    "max_severity": r.max_severity,
                    "vulns": [asdict(v) for v in r.vulns],
                }
                for r in vulnerable
            ]
        return data

    def _package_dict(self, p: Package) -> dict[str, Any]:
        d = p.to_dict()
        purl = package_purl(p, self.os_info)
        if purl:
            d["purl"] = purl
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanReport:
        osv_results: list[VulnResult] | None = None
        if "osv_vulnerabilities" in data or "osv_summary" in data:
            osv_results = [
                VulnResult(
                    package=Package.from_dict(f["package"]),
                    vulns=[VulnDetail.from_dict(v) for v in f.get("vulns", [])],
                )
                for f in data.get("osv_vulnerabilities") or []
            ]
        return cls(
            hostname=data.get("hostname", "unknown"),
            scan_ts=data.get("scan_ts", ""),
            packages=[Package.from_dict(p) for p in data.get("packages", [])],
            osv_results=osv_results,
            diff_summary=data.get("diff_summary"),
            removed_packages=data.get("removed_packages"),
            os_info=data.get("os") or None,
            queried=(data.get("osv_summary") or {}).get("queried", 0),
            agent_version=data.get("agent_version", "unknown"),
            scan_target=data.get("scan_target"),
            eol=data.get("eol"),
            license_violations=data.get("license_violations"),
            suppressed=data.get("suppressed"),
        )

    @staticmethod
    def _severity_metrics(vulnerable: list[VulnResult]) -> dict[str, int]:
        counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for r in vulnerable:
            for v in r.vulns:
                key = v.severity if v.severity in counts else "UNKNOWN"
                counts[key] += 1
        return {f"total_{k.lower()}": v for k, v in counts.items()}


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def _configure_logging(verbose: bool = False) -> None:
    """Attach console + file handlers. Called from main() so importing the module has no side effects."""
    if any(getattr(h, "_openbom", False) for h in log.handlers):
        for h in log.handlers:
            if isinstance(h, RichHandler):
                h.setLevel(logging.DEBUG if verbose else logging.INFO)
        return
    log.setLevel(logging.DEBUG)
    log.propagate = False
    rich_handler = RichHandler(
        console=console, show_path=False, rich_tracebacks=True,
        tracebacks_show_locals=False, markup=False,
    )
    rich_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    rich_handler._openbom = True  # type: ignore[attr-defined]
    log.addHandler(rich_handler)

    file_fmt = logging.Formatter("[%(asctime)s] %(levelname)-8s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    fh: logging.Handler | None = None
    for candidate in (DEFAULT_LOG_PATH, FALLBACK_LOG_PATH):
        try:
            candidate.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(candidate)
            if candidate != DEFAULT_LOG_PATH:
                log.debug("Cannot write to %s — logging to %s", DEFAULT_LOG_PATH, candidate)
            break
        except OSError:
            continue
    if fh is not None:
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(file_fmt)
        fh._openbom = True  # type: ignore[attr-defined]
        log.addHandler(fh)


# ---------------------------------------------------------------------------
# Version comparison (rpm, dpkg, PEP 440, semver)
# ---------------------------------------------------------------------------


def _sign(n: int) -> int:
    return (n > 0) - (n < 0)


def _rpmvercmp(a: str, b: str) -> int:
    """Port of rpm's rpmvercmp() — segment-wise compare with ~ and ^ semantics."""
    if a == b:
        return 0
    ia = ib = 0
    la, lb = len(a), len(b)
    while ia < la or ib < lb:
        while ia < la and not a[ia].isalnum() and a[ia] not in "~^":
            ia += 1
        while ib < lb and not b[ib].isalnum() and b[ib] not in "~^":
            ib += 1
        if (ia < la and a[ia] == "~") or (ib < lb and b[ib] == "~"):
            if ia >= la or a[ia] != "~":
                return 1
            if ib >= lb or b[ib] != "~":
                return -1
            ia += 1
            ib += 1
            continue
        if (ia < la and a[ia] == "^") or (ib < lb and b[ib] == "^"):
            if ia >= la:
                return -1
            if ib >= lb:
                return 1
            if a[ia] != "^":
                return 1
            if b[ib] != "^":
                return -1
            ia += 1
            ib += 1
            continue
        if ia >= la or ib >= lb:
            break
        if a[ia].isdigit():
            ja = ia
            while ja < la and a[ja].isdigit():
                ja += 1
            jb = ib
            while jb < lb and b[jb].isdigit():
                jb += 1
            if jb == ib:
                return 1
            sa, sb = a[ia:ja].lstrip("0"), b[ib:jb].lstrip("0")
            if len(sa) != len(sb):
                return 1 if len(sa) > len(sb) else -1
            if sa != sb:
                return 1 if sa > sb else -1
        else:
            ja = ia
            while ja < la and a[ja].isalpha():
                ja += 1
            jb = ib
            while jb < lb and b[jb].isalpha():
                jb += 1
            if jb == ib:
                return -1
            sa, sb = a[ia:ja], b[ib:jb]
            if sa != sb:
                return 1 if sa > sb else -1
        ia, ib = ja, jb
    if ia >= la and ib >= lb:
        return 0
    return -1 if ia >= la else 1


def _split_evr(evr: str) -> tuple[int, str, str]:
    epoch = 0
    if ":" in evr:
        e, _, evr = evr.partition(":")
        epoch = int(e) if e.isdigit() else 0
    version, _, release = evr.rpartition("-") if "-" in evr else (evr, "", "")
    return epoch, version, release


def compare_rpm(a: str, b: str) -> int:
    ea, va, ra = _split_evr(a)
    eb, vb, rb = _split_evr(b)
    if ea != eb:
        return _sign(ea - eb)
    return _rpmvercmp(va, vb) or _rpmvercmp(ra, rb)


def _dpkg_order(c: str) -> int:
    if c == "~":
        return -1
    if not c or c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _dpkg_verrevcmp(a: str, b: str) -> int:
    ia = ib = 0
    la, lb = len(a), len(b)
    while ia < la or ib < lb:
        first_diff = 0
        while (ia < la and not a[ia].isdigit()) or (ib < lb and not b[ib].isdigit()):
            ac = _dpkg_order(a[ia]) if ia < la else 0
            bc = _dpkg_order(b[ib]) if ib < lb else 0
            if ac != bc:
                return _sign(ac - bc)
            ia += 1
            ib += 1
        while ia < la and a[ia] == "0":
            ia += 1
        while ib < lb and b[ib] == "0":
            ib += 1
        while ia < la and a[ia].isdigit() and ib < lb and b[ib].isdigit():
            if not first_diff:
                first_diff = int(a[ia]) - int(b[ib])
            ia += 1
            ib += 1
        if ia < la and a[ia].isdigit():
            return 1
        if ib < lb and b[ib].isdigit():
            return -1
        if first_diff:
            return _sign(first_diff)
    return 0


def _split_dpkg(v: str) -> tuple[int, str, str]:
    epoch = 0
    if ":" in v:
        e, _, rest = v.partition(":")
        if e.isdigit():
            epoch, v = int(e), rest
    upstream, sep, revision = v.rpartition("-")
    if not sep:
        upstream, revision = v, ""
    return epoch, upstream, revision


def compare_dpkg(a: str, b: str) -> int:
    ea, ua, ra = _split_dpkg(a)
    eb, ub, rb = _split_dpkg(b)
    if ea != eb:
        return _sign(ea - eb)
    return _dpkg_verrevcmp(ua, ub) or _dpkg_verrevcmp(ra, rb)


def _version_tuple(v: str) -> tuple[tuple[int, int | str], ...]:
    """Total-order fallback key: numeric segments sort before alpha ones, never raises."""
    key: list[tuple[int, int | str]] = []
    for seg in re.split(r"[.\-+_]", v):
        if seg.isdigit():
            key.append((1, int(seg)))
        elif seg:
            key.append((0, seg))
    return tuple(key)


def compare_semver(a: str, b: str) -> int:
    def parse(v: str) -> tuple[tuple[int, ...], list[str]]:
        v = v.strip().lstrip("vV=").split("+", 1)[0]
        core, _, pre = v.partition("-")
        nums: list[int] = []
        for part in core.split("."):
            m = re.match(r"\d+", part)
            nums.append(int(m.group()) if m else 0)
        while len(nums) < 3:
            nums.append(0)
        return tuple(nums), pre.split(".") if pre else []

    (na, pa), (nb, pb) = parse(a), parse(b)
    if na != nb:
        return 1 if na > nb else -1
    if not pa and not pb:
        return 0
    if not pa:
        return 1
    if not pb:
        return -1
    for x, y in zip(pa, pb):
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            return _sign(int(x) - int(y))
        if x.isdigit():
            return -1
        if y.isdigit():
            return 1
        return 1 if x > y else -1
    return _sign(len(pa) - len(pb))


def compare_apk(a: str, b: str) -> int:
    """Alpine versions: '<version>-r<rel>'; upstream part is dotted with optional suffixes."""
    va, _, ra = a.partition("-r")
    vb, _, rb = b.partition("-r")
    c = _rpmvercmp(va, vb)
    if c:
        return c
    return _sign((int(ra) if ra.isdigit() else 0) - (int(rb) if rb.isdigit() else 0))


def compare_pep440(a: str, b: str) -> int:
    try:
        from packaging.version import InvalidVersion, Version
        try:
            va, vb = Version(a), Version(b)
            return (va > vb) - (va < vb)
        except InvalidVersion:
            pass
    except ImportError:
        pass
    ka, kb = _version_tuple(a), _version_tuple(b)
    return (ka > kb) - (ka < kb)


def compare_versions(a: str, b: str, ecosystem: str) -> int:
    """Return -1/0/1. Never raises — unknown ecosystems fall back to a generic ordering."""
    eco = ecosystem.split(":")[0].lower()
    try:
        if eco in {"rpm", "podman-rpm", "almalinux", "rocky linux", "red hat", "opensuse", "suse"}:
            return compare_rpm(a, b)
        if eco in {"debian", "ubuntu", "podman-deb"}:
            return compare_dpkg(a, b)
        if eco == "pypi":
            return compare_pep440(a, b)
        if eco in ("npm", "go", "crates.io", "cargo", "nuget", "packagist"):
            return compare_semver(a, b)
        if eco == "alpine":
            return compare_apk(a, b)
    except (ValueError, IndexError):
        pass
    ka, kb = _version_tuple(a), _version_tuple(b)
    return (ka > kb) - (ka < kb)


# ---------------------------------------------------------------------------
# OSV cache
# ---------------------------------------------------------------------------


class OsvCache:
    def __init__(self, path: Path | None = None, ttl: int = CACHE_TTL_SECONDS) -> None:
        self._path = path or osv_cache_path()
        self._ttl = ttl
        self._enabled = True
        try:
            _ensure_private_dir(self._path.parent)
        except OSError as exc:
            log.warning("OSV cache disabled: %s", exc)
            self._enabled = False
        self._store: dict[str, Any] = self._load() if self._enabled else {}

    def _load(self) -> dict[str, Any]:
        data = _read_private_json(self._path)
        if not isinstance(data, dict):
            return {}
        now = time.time()
        return {k: v for k, v in data.items()
                if isinstance(v, dict) and now - v.get("ts", 0) <= self._ttl}

    @staticmethod
    def _key(ecosystem: str, name: str, version: str) -> str:
        return f"{ecosystem}|{name}|{version}"

    def get(self, ecosystem: str, name: str, version: str) -> list[dict[str, Any]] | None:
        entry = self._store.get(self._key(ecosystem, name, version))
        if entry is None or time.time() - entry.get("ts", 0) > self._ttl:
            return None
        return entry.get("vulns")

    def put(self, ecosystem: str, name: str, version: str, vulns: list[dict[str, Any]]) -> None:
        self._store[self._key(ecosystem, name, version)] = {"ts": time.time(), "vulns": vulns}

    def flush(self) -> None:
        if not self._enabled:
            return
        try:
            _atomic_write(self._path, json.dumps(self._store, default=str) + "\n")
        except OSError as exc:
            log.warning("Failed to write OSV cache: %s", exc)

    @property
    def size(self) -> int:
        return len(self._store)


# ---------------------------------------------------------------------------
# CISA KEV catalog
# ---------------------------------------------------------------------------


class KevCatalog:
    """CISA Known Exploited Vulnerabilities catalog with 24h file cache."""

    def __init__(self, cache_path: Path | None = None) -> None:
        self._entries: dict[str, dict[str, Any]] = {}
        self._cache_path = cache_path or kev_cache_path()

    def _load_cache(self, max_age: float | None) -> bool:
        cached = _read_private_json(self._cache_path)
        if not isinstance(cached, dict):
            return False
        if max_age is not None and time.time() - cached.get("_ts", 0) >= max_age:
            return False
        try:
            self._entries = {v["cveID"]: v for v in cached.get("vulnerabilities", [])}
        except (KeyError, TypeError):
            return False
        return bool(self._entries)

    async def load(self, progress: Progress | None = None, task_id: Any = None) -> None:
        if progress is not None:
            progress.update(task_id, total=1)
        try:
            if self._load_cache(KEV_CACHE_TTL):
                log.info("CISA KEV loaded from cache (%d entries)", len(self._entries))
                return
            try:
                import httpx
                async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                    resp = await http_request(client, "GET", CISA_KEV_URL)
                    data = resp.json()
            except Exception as exc:
                if self._load_cache(None):
                    log.warning("Failed to refresh CISA KEV (%s) — using stale cache (%d entries)",
                                exc, len(self._entries))
                else:
                    log.warning("Failed to fetch CISA KEV catalog: %s", exc)
                return

            vulns = [v for v in data.get("vulnerabilities", []) if isinstance(v, dict) and "cveID" in v]
            self._entries = {v["cveID"]: v for v in vulns}
            log.info("CISA KEV catalog loaded (%d entries, version %s)",
                     len(self._entries), data.get("catalogVersion", "?"))
            try:
                _ensure_private_dir(self._cache_path.parent)
                _atomic_write(self._cache_path, json.dumps({"_ts": time.time(), "vulnerabilities": vulns}) + "\n")
            except OSError as exc:
                log.debug("Could not write KEV cache: %s", exc)
        finally:
            if progress is not None:
                progress.update(task_id, completed=1)

    def lookup(self, cve_id: str) -> dict[str, Any] | None:
        return self._entries.get(cve_id)

    @property
    def size(self) -> int:
        return len(self._entries)


# ---------------------------------------------------------------------------
# HTTP helper with retry/backoff
# ---------------------------------------------------------------------------


async def http_request(client: Any, method: str, url: str, retries: int = HTTP_RETRIES, **kwargs: Any) -> Any:
    """Request with exponential backoff on transport errors, 429 and 5xx. Raises on final failure."""
    import httpx

    last_exc: Exception | None = None
    for attempt in range(retries):
        try:
            resp = await client.request(method, url, **kwargs)
            if resp.status_code in RETRYABLE_STATUS and attempt < retries - 1:
                retry_after = resp.headers.get("retry-after", "")
                delay = float(retry_after) if retry_after.isdigit() else 2 ** attempt
                log.debug("%s %s -> %d, retrying in %.1fs", method, url, resp.status_code, delay)
                await asyncio.sleep(min(delay, 30))
                continue
            resp.raise_for_status()
            return resp
        except httpx.TransportError as exc:
            last_exc = exc
            if attempt < retries - 1:
                await asyncio.sleep(2 ** attempt)
                continue
            raise
    raise last_exc or RuntimeError(f"{method} {url} failed")


# ---------------------------------------------------------------------------
# Severity extraction & remediation logic
# ---------------------------------------------------------------------------

_CVSS3_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_CVSS3_PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}


def _cvss_roundup(value: float) -> float:
    """CVSS v3.1 Roundup: smallest number, to 1 decimal, >= input (float-safe)."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (int_input // 10000 + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """Compute the CVSS v3.0/v3.1 base score from a vector string. Returns None if malformed."""
    if not vector or not vector.upper().startswith("CVSS:3"):
        return None
    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        k, sep, v = part.partition(":")
        if sep:
            metrics[k.upper()] = v.upper()
    try:
        scope = metrics["S"]
        av = _CVSS3_WEIGHTS["AV"][metrics["AV"]]
        ac = _CVSS3_WEIGHTS["AC"][metrics["AC"]]
        pr = _CVSS3_PR[scope][metrics["PR"]]
        ui = _CVSS3_WEIGHTS["UI"][metrics["UI"]]
        c = _CVSS3_WEIGHTS["CIA"][metrics["C"]]
        i = _CVSS3_WEIGHTS["CIA"][metrics["I"]]
        a = _CVSS3_WEIGHTS["CIA"][metrics["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope == "U":
        return _cvss_roundup(min(impact + exploitability, 10.0))
    return _cvss_roundup(min(1.08 * (impact + exploitability), 10.0))


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


def _extract_cvss_score(vuln: dict[str, Any]) -> float | None:
    """Highest CVSS v3 base score across the record and its affected entries."""
    entries = list(vuln.get("severity") or [])
    for affected in vuln.get("affected") or []:
        entries.extend(affected.get("severity") or [])
    scores = [s for e in entries if e.get("type") == "CVSS_V3"
              for s in [cvss3_base_score(e.get("score", ""))] if s is not None]
    return max(scores) if scores else None


def _extract_severity(vuln: dict[str, Any], cvss_score: float | None = None) -> str:
    if cvss_score is None:
        cvss_score = _extract_cvss_score(vuln)
    if cvss_score is not None and cvss_score > 0:
        return _score_to_severity(cvss_score)
    # Qualitative ratings: OSV severity entries (e.g. type "Ubuntu"), GHSA database_specific, RHEL-style summary
    candidates: list[str] = []
    for entry in vuln.get("severity") or []:
        if entry.get("type") not in ("CVSS_V2", "CVSS_V3", "CVSS_V4"):
            candidates.append(str(entry.get("score", "")))
    db = vuln.get("database_specific") or {}
    if isinstance(db, dict) and isinstance(db.get("severity"), str):
        candidates.append(db["severity"])
    for affected in vuln.get("affected") or []:
        for key in ("ecosystem_specific", "database_specific"):
            spec = affected.get(key) or {}
            if isinstance(spec, dict) and isinstance(spec.get("severity"), str):
                candidates.append(spec["severity"])
    m = RHEL_STYLE_SEVERITY.match(vuln.get("summary") or "")
    if m:
        candidates.append(m.group(1))
    mapped = [QUALITATIVE_SEVERITY[c.strip().upper()] for c in candidates if c.strip().upper() in QUALITATIVE_SEVERITY]
    if mapped:
        return min(mapped, key=lambda s: SEVERITY_ORDER[s])
    return "UNKNOWN"


def _normalize_name(name: str, ecosystem: str = "PyPI") -> str:
    if ecosystem.lower() == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def _extract_fixed_version(
    vuln: dict[str, Any], ecosystem: str, pkg_name: str | None = None, installed: str | None = None,
) -> str | None:
    """Pick the fix for the range that actually contains the installed version.

    Prefers affected entries whose ecosystem matches exactly (Ubuntu records
    list one entry per release), then same-family, then any.
    """
    affected_all = vuln.get("affected") or []
    norm_name = _normalize_name(pkg_name, ecosystem) if pkg_name else None

    def name_ok(a: dict[str, Any]) -> bool:
        n = (a.get("package") or {}).get("name")
        return not (n and norm_name) or _normalize_name(n, ecosystem) == norm_name

    eco_l = ecosystem.lower()
    family = eco_l.split(":")[0]
    exact = [a for a in affected_all if (a.get("package") or {}).get("ecosystem", "").lower() == eco_l and name_ok(a)]
    same_family = [a for a in affected_all
                   if (a.get("package") or {}).get("ecosystem", "").lower().split(":")[0] == family and name_ok(a)]
    affected = exact or same_family or [a for a in affected_all if not (a.get("package") or {}).get("ecosystem")]
    if not affected:
        affected = affected_all

    candidates: list[str] = []
    for a in affected:
        for rng in a.get("ranges") or []:
            if rng.get("type") == "GIT":
                continue
            introduced: str | None = None
            for event in rng.get("events") or []:
                if "introduced" in event:
                    introduced = event["introduced"]
                elif "fixed" in event:
                    fixed = event["fixed"]
                    candidates.append(fixed)
                    if installed and introduced is not None:
                        lower_ok = introduced == "0" or compare_versions(installed, introduced, ecosystem) >= 0
                        if lower_ok and compare_versions(installed, fixed, ecosystem) < 0:
                            return fixed
                    introduced = None
    if not candidates:
        return None
    if installed:
        # Never recommend "upgrading" to a version older than what is installed
        newer = [c for c in candidates if compare_versions(c, installed, ecosystem) > 0]
        if not newer:
            return None
        return min(newer, key=functools.cmp_to_key(lambda x, y: compare_versions(x, y, ecosystem)))
    return candidates[0]


def _extract_cve_aliases(vuln: dict[str, Any]) -> list[str]:
    """CVE ids for a record: id, aliases, plus distro 'upstream'/'related' links (Debian, Ubuntu, Alma, Rocky)."""
    cves: list[str] = []
    sources = [vuln.get("id", "")]
    for key in ("aliases", "upstream", "related"):
        sources.extend(vuln.get(key) or [])
    for s in sources:
        for cve in CVE_PATTERN.findall(str(s)):
            if cve not in cves:
                cves.append(cve)
    return cves


def _extract_poc_links(vuln: dict[str, Any]) -> list[str]:
    links: list[str] = []
    for ref in vuln.get("references") or []:
        url = ref.get("url", "")
        if url and POC_URL_PATTERNS.search(url) and url not in links:
            links.append(url)
    return links


def _build_recommendation(fixed_version: str | None, pkg_name: str) -> str:
    if fixed_version:
        return f"Upgrade to version {fixed_version}"
    return f"No fixed version available — review {pkg_name} for alternatives or apply compensating controls"


def _advisory_preference(v: dict[str, Any]) -> tuple[int, str]:
    vid = v.get("id", "")
    rank = 0 if vid.startswith("GHSA-") else 1 if vid.startswith("CVE-") else 3 if vid.startswith("PYSEC-") else 2
    return rank, vid


def parse_vuln_details(
    raw_vulns: list[dict[str, Any]], ecosystem: str, pkg_name: str, installed: str | None = None,
) -> list[VulnDetail]:
    """Build VulnDetails, collapsing advisories that alias each other (GHSA ↔ PYSEC ↔ CVE) into one entry."""
    details: list[VulnDetail] = []
    by_alias: dict[str, VulnDetail] = {}
    for v in sorted(raw_vulns, key=_advisory_preference):
        vid = v.get("id", "UNKNOWN")
        if v.get("withdrawn"):
            continue
        cvss = _extract_cvss_score(v)
        fixed = _extract_fixed_version(v, ecosystem, pkg_name, installed)
        summary = v.get("summary") or (v.get("details") or "No description available").strip().split("\n")[0]
        detail = VulnDetail(
            vuln_id=vid,
            severity=_extract_severity(v, cvss),
            summary=summary[:200],
            fixed_version=fixed,
            recommendation=_build_recommendation(fixed, pkg_name),
            cvss_score=cvss,
            poc_links=_extract_poc_links(v),
            cves=_extract_cve_aliases(v),
        )
        ids = {vid, *(v.get("aliases") or [])}
        if any(str(i).startswith("MAL-") for i in ids):
            mark_malicious(detail, pkg_name)
        existing = next((by_alias[i] for i in ids if i in by_alias), None)
        if existing is not None:
            _merge_duplicate(existing, detail, pkg_name)
        else:
            details.append(detail)
            existing = detail
        for i in ids:
            by_alias.setdefault(i, existing)
    return details


def mark_malicious(detail: VulnDetail, pkg_name: str) -> None:
    """OpenSSF malicious-package advisories carry no CVSS — they must never read as UNKNOWN."""
    detail.is_malicious = True
    detail.severity = "CRITICAL"
    detail.recommendation = (f"REMOVE {pkg_name} NOW — known malicious package (OpenSSF). "
                             "Treat the host as compromised: rotate credentials and investigate.")


def _merge_duplicate(keep: VulnDetail, dup: VulnDetail, pkg_name: str) -> None:
    if dup.is_malicious and not keep.is_malicious:
        mark_malicious(keep, pkg_name)
    if SEVERITY_ORDER.get(dup.severity, 9) < SEVERITY_ORDER.get(keep.severity, 9):
        keep.severity = dup.severity
    if dup.cvss_score is not None and (keep.cvss_score is None or dup.cvss_score > keep.cvss_score):
        keep.cvss_score = dup.cvss_score
    if keep.fixed_version is None and dup.fixed_version:
        keep.fixed_version = dup.fixed_version
        keep.recommendation = _build_recommendation(dup.fixed_version, pkg_name)
    if keep.summary == "No description available":
        keep.summary = dup.summary
    keep.poc_links.extend(u for u in dup.poc_links if u not in keep.poc_links)
    keep.cves.extend(c for c in dup.cves if c not in keep.cves)


# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------


def parse_os_release(text: str) -> dict[str, str]:
    info: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip():
            info[key.strip()] = value.strip().strip('"').strip("'")
    return info


def read_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    for p in (path, Path("/usr/lib/os-release")):
        try:
            return parse_os_release(p.read_text())
        except OSError:
            continue
    return {}


def osv_ecosystem_for_os(info: dict[str, str]) -> str | None:
    """Map /etc/os-release to an OSV distro ecosystem, or None when OSV has no data for the distro."""
    os_id = info.get("ID", "").lower()
    like = info.get("ID_LIKE", "").lower().split()
    version_id = info.get("VERSION_ID", "")
    major = version_id.split(".")[0]
    if os_id == "debian" and major:
        return f"Debian:{major}"
    if os_id == "ubuntu" and version_id:
        lts = "LTS" in info.get("VERSION", "")
        return f"Ubuntu:{version_id}:LTS" if lts else f"Ubuntu:{version_id}"
    if os_id == "almalinux" and major:
        return f"AlmaLinux:{major}"
    if os_id == "rocky" and major:
        return f"Rocky Linux:{major}"
    if os_id == "alpine" and version_id.count(".") >= 1:
        return "Alpine:v" + ".".join(version_id.split(".")[:2])
    if "debian" in like and not like.count("ubuntu") and info.get("VERSION_CODENAME"):
        # Debian derivatives (Kali etc.) don't map cleanly onto a Debian release
        return None
    return None


def _os_summary(info: dict[str, str]) -> dict[str, str]:
    return {
        "id": info.get("ID", ""),
        "version_id": info.get("VERSION_ID", ""),
        "pretty_name": info.get("PRETTY_NAME", ""),
        "osv_ecosystem": osv_ecosystem_for_os(info) or "",
    }


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


RPM_QUERYFORMAT = "%{NAME}\\t%{EPOCH}\\t%{VERSION}-%{RELEASE}\\t%{LICENSE}\\n"
DPKG_SHOWFORMAT = "${Package}\\t${Version}\\t${source:Package}\\t${source:Version}\\t${db:Status-Abbrev}\\n"


def parse_rpm_output(raw: str, ecosystem: str, osv_eco: str | None, suffix: str = "") -> list[Package]:
    packages: list[Package] = []
    for line in raw.strip().splitlines():
        parts = line.split("\t")
        if len(parts) not in (3, 4):
            continue
        name, epoch, vr = parts[:3]
        license_ = parts[3] if len(parts) == 4 else None
        if name == "gpg-pubkey":  # imported signing keys, not software
            continue
        epoch = "" if epoch in ("(none)", "") else epoch
        packages.append(Package(
            name=f"{name}{suffix}", version=vr, ecosystem=ecosystem,
            osv_ecosystem=osv_eco,
            osv_name=name if suffix else None,
            osv_version=f"{epoch}:{vr}" if epoch and osv_eco else None,
            license=normalize_license(license_) if license_ and license_ != "(none)" else None,
        ))
    return packages


def parse_dpkg_output(raw: str, ecosystem: str, osv_eco: str | None, suffix: str = "") -> list[Package]:
    packages: list[Package] = []
    for line in raw.strip().splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        name, version = parts[0], parts[1]
        if len(parts) >= 5 and parts[4] and not parts[4].startswith("ii"):
            continue  # removed / config-files-only / half-installed
        src_name = parts[2] if len(parts) > 2 and parts[2] else name
        src_version = parts[3] if len(parts) > 3 and parts[3] else version
        packages.append(Package(
            name=f"{name}{suffix}", version=version, ecosystem=ecosystem,
            osv_ecosystem=osv_eco,
            osv_name=src_name if osv_eco and (src_name != name or suffix) else None,
            osv_version=src_version if osv_eco and src_version != version else None,
        ))
    return packages


# ---------------------------------------------------------------------------
# Package extraction — OS level
# ---------------------------------------------------------------------------


def extract_os_packages(progress: Progress, task_id: Any, os_info: dict[str, str] | None = None) -> list[Package]:
    os_info = os_info if os_info is not None else read_os_release()
    osv_eco = osv_ecosystem_for_os(os_info)
    packages: list[Package] = []
    if shutil.which("rpm"):
        log.info("Detected RPM-based system — querying rpm database")
        raw = _run(["rpm", "-qa", "--queryformat", RPM_QUERYFORMAT])
        if raw:
            packages = parse_rpm_output(raw, "RPM", osv_eco)
        else:
            raw = _run(["dnf", "list", "installed", "-q"])
            for line in (raw or "").strip().splitlines():
                tokens = line.split()
                if len(tokens) >= 2 and "." in tokens[0]:
                    packages.append(Package(name=tokens[0].rsplit(".", 1)[0], version=tokens[1],
                                            ecosystem="RPM", osv_ecosystem=osv_eco))
        if packages:
            log.info("Extracted %d RPM packages", len(packages))
    if not packages and shutil.which("dpkg-query"):
        log.info("Detected Debian-based system — querying dpkg database")
        raw = _run(["dpkg-query", "-W", f"-f={DPKG_SHOWFORMAT}"])
        if raw:
            packages = parse_dpkg_output(raw, "Debian", osv_eco)
            for p in packages:
                p.license = _debian_copyright_license(Path("/"), p.name)
            log.info("Extracted %d Debian packages", len(packages))
    apk_db = Path("/lib/apk/db/installed")
    if not packages and apk_db.exists():
        log.info("Detected Alpine system — reading apk database")
        with contextlib.suppress(OSError):
            packages = parse_apk_installed(apk_db.read_text(errors="replace"), osv_eco)
            log.info("Extracted %d Alpine packages", len(packages))
    if not packages:
        log.warning("No supported OS package manager found")
    elif osv_eco is None:
        log.info("OSV has no advisory feed for %s — OS packages are inventoried but not vulnerability-checked",
                 os_info.get("PRETTY_NAME", "this distribution"))
    progress.update(task_id, total=max(len(packages), 1), completed=max(len(packages), 1))
    return packages


def extract_python_packages(progress: Progress, task_id: Any) -> list[Package]:
    packages: list[Package] = []
    pip_cmd: list[str] | None = None
    if shutil.which("pip3") or shutil.which("pip"):
        pip_cmd = [shutil.which("pip3") or shutil.which("pip") or "pip3"]
    else:
        pip_cmd = [sys.executable, "-m", "pip"]
    raw = _run([*pip_cmd, "freeze", "--all"])
    if not raw:
        log.warning("pip freeze returned no data — skipping Python package extraction")
        progress.update(task_id, total=1, completed=1)
        return packages
    seen: set[tuple[str, str]] = set()
    licenses = _installed_python_licenses()
    locations = _installed_python_locations(pip_cmd)
    for line in raw.strip().splitlines():
        line = line.strip()
        if "==" in line and not line.startswith("#"):
            name, _, version = line.partition("==")
            key = (name.strip().lower(), version.strip())
            if key not in seen:
                seen.add(key)
                packages.append(Package(name=name.strip(), version=version.strip(), ecosystem="PyPI",
                                        osv_ecosystem="PyPI", license=licenses.get(_normalize_name(name)),
                                        location=locations.get(_normalize_name(name))))
        elif " @ " in line:
            log.debug("Skipping direct-reference requirement (no version): %s", line)
    progress.update(task_id, total=max(len(packages), 1), completed=max(len(packages), 1))
    log.info("Extracted %d Python (PyPI) packages", len(packages))
    return packages


def extract_npm_packages(progress: Progress, task_id: Any) -> list[Package]:
    packages: list[Package] = []
    if not shutil.which("npm"):
        log.info("npm not found — skipping NPM extraction")
        progress.update(task_id, total=1, completed=1)
        return packages
    # npm exits non-zero on peer-dep problems but still prints valid JSON
    try:
        result = subprocess.run(["npm", "list", "-g", "--depth=0", "--json"], capture_output=True,
                                text=True, timeout=120, check=False)
        raw = result.stdout
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("npm list failed: %s", exc)
        raw = ""
    try:
        data = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        log.warning("npm list returned invalid JSON")
        data = {}
    deps = data.get("dependencies", {}) or {}
    npm_root = _npm_global_root()
    for name, info in deps.items():
        version = (info or {}).get("version")
        if not version:
            continue
        license_ = None
        if npm_root is not None:
            with contextlib.suppress(OSError, json.JSONDecodeError, UnicodeDecodeError, AttributeError):
                license_ = normalize_license(json.loads((npm_root / name / "package.json").read_text()).get("license"))
        location = (info or {}).get("path") or (str(npm_root / name) if npm_root is not None else None)
        packages.append(Package(name=name, version=version, ecosystem="NPM", osv_ecosystem="npm", license=license_,
                                location=location if isinstance(location, str) else None))
    progress.update(task_id, total=max(len(packages), 1), completed=max(len(packages), 1))
    log.info("Extracted %d NPM global packages", len(packages))
    return packages


def extract_containers(progress: Progress, task_id: Any, engine: str = "podman") -> list[Package]:
    """Packages inside running containers (rpm, dpkg or apk) via `<engine> exec`."""
    packages: list[Package] = []
    label = engine.capitalize()
    if not shutil.which(engine):
        log.info("%s not found — skipping container extraction", engine)
        progress.update(task_id, total=1, completed=1)
        return packages
    raw = _run([engine, "ps", "-q", "--no-trunc"])
    if not raw or not raw.strip():
        log.info("No running %s containers found", label)
        progress.update(task_id, total=1, completed=1)
        return packages
    container_ids = raw.strip().splitlines()
    log.info("Found %d running %s container(s) — scanning packages", len(container_ids), label)
    progress.update(task_id, total=len(container_ids))
    for cid in container_ids:
        cid = cid.strip()[:12]
        suffix = f" [{cid}]"
        os_text = _run([engine, "exec", cid, "cat", "/etc/os-release"], timeout=30) or ""
        osv_eco = osv_ecosystem_for_os(parse_os_release(os_text))
        rpm_out = _run([engine, "exec", cid, "rpm", "-qa", "--queryformat", RPM_QUERYFORMAT], timeout=60)
        if rpm_out:
            packages.extend(parse_rpm_output(rpm_out, f"{label}-RPM", osv_eco, suffix))
        elif dpkg_out := _run([engine, "exec", cid, "dpkg-query", "-W", f"-f={DPKG_SHOWFORMAT}"], timeout=60):
            packages.extend(parse_dpkg_output(dpkg_out, f"{label}-DEB", osv_eco, suffix))
        elif apk_out := _run([engine, "exec", cid, "cat", "/lib/apk/db/installed"], timeout=60):
            packages.extend(parse_apk_installed(apk_out, osv_eco, f"{label}-APK", suffix))
        progress.advance(task_id)
    log.info("Extracted %d packages from %s containers", len(packages), label)
    return packages


def extract_podman_containers(progress: Progress, task_id: Any) -> list[Package]:
    return extract_containers(progress, task_id, "podman")


def extract_docker_containers(progress: Progress, task_id: Any) -> list[Package]:
    return extract_containers(progress, task_id, "docker")


# ---------------------------------------------------------------------------
# Licenses
# ---------------------------------------------------------------------------

LICENSE_ALIASES = {
    "mit license": "MIT", "mit": "MIT", "the mit license": "MIT", "expat": "MIT",
    "apache 2.0": "Apache-2.0", "apache-2": "Apache-2.0", "apache 2": "Apache-2.0", "apache2": "Apache-2.0",
    "apache software license": "Apache-2.0", "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0", "apache license version 2.0": "Apache-2.0", "asl 2.0": "Apache-2.0",
    "bsd license": "BSD", "bsd": "BSD", "new bsd license": "BSD-3-Clause", "simplified bsd": "BSD-2-Clause",
    "isc license": "ISC", "isc license (iscl)": "ISC",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0", "mpl 2.0": "MPL-2.0", "mplv2.0": "MPL-2.0",
    "gnu general public license v3 (gplv3)": "GPL-3.0", "gplv3": "GPL-3.0", "gplv3+": "GPL-3.0-or-later",
    "gnu general public license v3 or later (gplv3+)": "GPL-3.0-or-later",
    "gnu general public license v2 (gplv2)": "GPL-2.0", "gplv2": "GPL-2.0", "gplv2+": "GPL-2.0-or-later",
    "gnu general public license v2 or later (gplv2+)": "GPL-2.0-or-later",
    "gnu lesser general public license v3 (lgplv3)": "LGPL-3.0", "lgplv3": "LGPL-3.0",
    "gnu lesser general public license v2 or later (lgplv2+)": "LGPL-2.0-or-later",
    "gnu library or lesser general public license (lgpl)": "LGPL", "lgplv2+": "LGPL-2.0-or-later",
    "gnu affero general public license v3": "AGPL-3.0", "gnu affero general public license v3 or later (agplv3+)":
        "AGPL-3.0-or-later",
    "python software foundation license": "PSF-2.0", "psf": "PSF-2.0", "psfl": "PSF-2.0",
    "the unlicense (unlicense)": "Unlicense", "public domain": "Public-Domain", "zlib/libpng": "Zlib",
    "eclipse public license 2.0": "EPL-2.0", "historical permission notice and disclaimer (hpnd)": "HPND",
}
LICENSE_TEXT_HINTS = [
    ("MIT License", "MIT"), ("Permission is hereby granted, free of charge", "MIT"),
    ("Apache License", "Apache-2.0"), ("GNU AFFERO GENERAL PUBLIC LICENSE", "AGPL-3.0"),
    ("GNU LESSER GENERAL PUBLIC LICENSE", "LGPL"), ("GNU GENERAL PUBLIC LICENSE", "GPL"),
    ("Mozilla Public License", "MPL-2.0"), ("BSD", "BSD"), ("ISC License", "ISC"),
]
_NO_LICENSE = {"", "UNKNOWN", "NONE", "NOASSERTION", "NOT FOUND", "OTHER", "OTHER/PROPRIETARY LICENSE"}


def normalize_license(raw: Any) -> str | None:
    """Best-effort mapping of free-form license metadata to a short SPDX-style identifier."""
    if raw is None:
        return None
    if isinstance(raw, (list, tuple)):
        parts = [p for p in (normalize_license(x) for x in raw) if p]
        return " OR ".join(dict.fromkeys(parts)) or None
    if isinstance(raw, dict):
        inner = raw.get("license") if isinstance(raw.get("license"), dict) else None
        return normalize_license(raw.get("expression") or raw.get("type") or raw.get("id") or raw.get("name")
                                 or (inner or {}).get("id") or (inner or {}).get("name"))
    text = str(raw).strip()
    if text.upper() in _NO_LICENSE:
        return None
    if "\n" in text or len(text) > 100:  # full license text pasted into metadata
        head = text[:400]
        for needle, spdx in LICENSE_TEXT_HINTS:
            if needle.lower() in head.lower():
                return spdx
        return None
    if text.lower().startswith("license ::"):
        text = text.split("::")[-1].strip()
    return LICENSE_ALIASES.get(text.lower(), text)


def _license_from_metadata(meta: Any) -> str | None:
    """License from Python core metadata (email.message-like): expression > License > classifiers."""
    expr = meta.get("License-Expression")
    if expr:
        return normalize_license(expr)
    lic = normalize_license(meta.get("License"))
    if lic:
        return lic
    classifiers = [c for c in (meta.get_all("Classifier") or []) if c.startswith("License ::")]
    return normalize_license(classifiers) if classifiers else None


def _installed_python_locations(pip_cmd: list[str]) -> dict[str, str]:
    """Normalized name -> install path, so a finding can be traced to the environment that holds it.

    The exact *.dist-info directory comes from this interpreter's metadata; packages that `pip` sees in
    another environment (pip3 on PATH ≠ sys.executable) fall back to the site-packages dir from `pip list -v`.
    """
    out: dict[str, str] = {}
    try:
        for dist in importlib.metadata.distributions():
            name = dist.metadata.get("Name")
            path = getattr(dist, "_path", None)  # PathDistribution: the .dist-info / .egg-info directory
            if name and path is not None:
                out.setdefault(_normalize_name(name), str(Path(str(path)).resolve()))
    except Exception as exc:  # metadata of broken installs must not break the scan
        log.debug("Could not read Python install locations: %s", exc)
    raw = _run([*pip_cmd, "list", "-v", "--format=json"])
    try:
        for entry in json.loads(raw) if raw and raw.strip() else []:
            name, loc = entry.get("name"), entry.get("location")
            if name and loc and isinstance(loc, str):
                out.setdefault(_normalize_name(name), loc)
    except (json.JSONDecodeError, AttributeError, TypeError):
        log.debug("pip list -v returned unusable JSON")
    return out


@functools.lru_cache(maxsize=1)
def _installed_python_licenses() -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        for dist in importlib.metadata.distributions():
            name = dist.metadata.get("Name")
            lic = _license_from_metadata(dist.metadata) if name else None
            if name and lic:
                out[_normalize_name(name)] = lic
    except Exception as exc:  # metadata of broken installs must not break the scan
        log.debug("Could not read Python license metadata: %s", exc)
    return out


def _license_tokens(expr: str) -> list[list[str]]:
    """Split an expression into OR-alternatives, each a list of AND-ed license ids."""
    alternatives = re.split(r"\s+OR\s+|\s*/\s*|\s+or\s+", expr.replace("(", " ").replace(")", " "))
    return [[t.strip() for t in re.split(r"\s+AND\s+|\s+and\s+|\s*,\s*", alt) if t.strip()]
            for alt in alternatives if alt.strip()]


def license_violation(license_expr: str, denied: list[str]) -> str | None:
    """Return the matching deny rule if *every* OR-alternative contains a denied license."""
    rules = [d.strip().upper() for d in denied if d.strip()]
    if not rules or not license_expr:
        return None
    hit: str | None = None
    for alternative in _license_tokens(license_expr):
        match = next((r for t in alternative for r in rules if t.upper().split(" WITH ")[0].startswith(r)), None)
        if match is None:
            return None  # at least one acceptable alternative
        hit = hit or match
    return hit


def check_licenses(packages: list[Package], denied: list[str]) -> list[dict[str, str]]:
    violations: list[dict[str, str]] = []
    for p in packages:
        rule = license_violation(p.license or "", denied)
        if rule:
            violations.append({"package": p.name, "version": p.version, "ecosystem": p.ecosystem,
                               "license": p.license or "", "rule": rule})
    return violations


async def enrich_licenses_deps_dev(packages: list[Package], progress: Progress, task_id: Any) -> int:
    """Fill missing licenses from deps.dev (Google Open Source Insights). Returns how many were filled."""
    try:
        import httpx
    except ImportError:
        return 0
    targets = [p for p in packages if not p.license and p.ecosystem in DEPS_DEV_SYSTEMS]
    progress.update(task_id, total=max(len(targets), 1))
    if not targets:
        progress.update(task_id, completed=1)
        return 0
    cache_path = state_dir() / "depsdev_cache.json"
    cache = _read_private_json(cache_path) or {}
    if not isinstance(cache, dict):
        cache = {}
    sem = asyncio.Semaphore(OSV_ENRICH_CONCURRENCY)
    filled = 0

    async def one(client: Any, p: Package) -> None:
        nonlocal filled
        key = f"{p.ecosystem}|{p.name}|{p.version}"
        lic = cache.get(key)
        if lic is None:
            version = f"v{p.version}" if p.ecosystem == "Go" and p.name != "stdlib" else p.version
            url = (f"{DEPS_DEV_URL}/systems/{DEPS_DEV_SYSTEMS[p.ecosystem]}/packages/"
                   f"{quote(p.query_name, safe='')}/versions/{quote(version, safe='')}")
            async with sem:
                try:
                    data = (await http_request(client, "GET", url, retries=2)).json()
                    lic = " AND ".join(data.get("licenses") or []) or ""
                except Exception:
                    lic = None
            if lic is not None:
                cache[key] = lic
        if lic:
            p.license = normalize_license(lic)
            filled += 1
        progress.advance(task_id)

    async with httpx.AsyncClient(timeout=20.0) as client:
        await asyncio.gather(*(one(client, p) for p in targets))
    try:
        _ensure_private_dir(cache_path.parent)
        _atomic_write(cache_path, json.dumps(cache) + "\n")
    except OSError:
        pass
    log.info("deps.dev license enrichment: %d/%d packages", filled, len(targets))
    return filled


# ---------------------------------------------------------------------------
# Project / lockfile scanning (repositories, build trees, virtualenvs, JARs)
# ---------------------------------------------------------------------------

LANG_OSV_ECOSYSTEM = {
    "PyPI": "PyPI", "NPM": "npm", "Go": "Go", "Cargo": "crates.io", "RubyGems": "RubyGems",
    "Packagist": "Packagist", "NuGet": "NuGet", "Maven": "Maven",
}
DEPS_DEV_URL = "https://api.deps.dev/v3"
DEPS_DEV_SYSTEMS = {"PyPI": "pypi", "NPM": "npm", "Go": "go", "Cargo": "cargo", "Maven": "maven", "NuGet": "nuget"}
SCAN_SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".tox", ".nox", ".mypy_cache", ".pytest_cache",
                  ".ruff_cache", ".gradle", ".idea", ".vscode", ".cache"}
ROOTFS_SKIP_TOP = {"proc", "sys", "dev", "run", "tmp", "var/tmp", "var/cache", "boot", "lost+found", "mnt", "media"}
SCAN_MAX_FILES = 400_000
ARCHIVE_MAX_BYTES = 200 * 1024 * 1024
NESTED_JAR_MAX_BYTES = 50 * 1024 * 1024


def _lang_pkg(eco: str, name: str, version: str, location: str, license: Any = None) -> Package:
    return Package(name=name, version=version, ecosystem=eco, osv_ecosystem=LANG_OSV_ECOSYSTEM[eco],
                   license=normalize_license(license), location=location)


REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([^\s;#\\,]+)")


def parse_requirements(text: str, loc: str) -> list[Package]:
    out = []
    for line in text.splitlines():
        m = REQ_LINE.match(line)
        if m and not line.lstrip().startswith(("-", "#")):
            out.append(_lang_pkg("PyPI", m.group(1), m.group(2), loc))
    return out


def parse_toml_lock(text: str, loc: str, eco: str) -> list[Package]:
    """poetry.lock, uv.lock, pdm.lock (PyPI) and Cargo.lock (crates.io)."""
    import tomllib
    data = tomllib.loads(text)
    out = []
    for p in data.get("package", []):
        name, version = p.get("name"), p.get("version")
        if not name or not version:
            continue
        source = p.get("source")
        if eco == "Cargo" and not source:
            continue  # workspace-local crate
        if isinstance(source, dict) and ({"editable", "virtual", "directory", "path"} & set(source)
                                         or source.get("type") in ("directory", "file")):
            continue  # the project itself / local path deps (uv: {editable=…}, poetry: type="directory")
        out.append(_lang_pkg(eco, name, version, loc, p.get("license")))
    return out


def parse_pipfile_lock(text: str, loc: str) -> list[Package]:
    data = json.loads(text)
    out = []
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            ver = str((info or {}).get("version", ""))
            if ver.startswith("=="):
                out.append(_lang_pkg("PyPI", name, ver[2:], loc))
    return out


def parse_package_lock(text: str, loc: str) -> list[Package]:
    data = json.loads(text)
    out = []
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfile v2/v3
        for key, info in packages.items():
            if not key or not isinstance(info, dict) or info.get("link") or "node_modules/" not in key:
                continue
            name = info.get("name") or key.rsplit("node_modules/", 1)[-1]
            if info.get("version"):
                out.append(_lang_pkg("NPM", name, info["version"], loc, info.get("license")))
        return out

    def walk(deps: dict[str, Any]) -> None:  # lockfile v1
        for name, info in (deps or {}).items():
            if isinstance(info, dict) and info.get("version") and not str(info["version"]).startswith(("file:", "git")):
                out.append(_lang_pkg("NPM", name, info["version"], loc))
                walk(info.get("dependencies") or {})
    walk(data.get("dependencies") or {})
    return out


def parse_yarn_lock(text: str, loc: str) -> list[Package]:
    out, names = [], []
    for line in text.splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":") and not line.startswith("#"):
            specs = [s.strip().strip('"') for s in line.rstrip()[:-1].split(",")]
            names = sorted({s.rsplit("@", 1)[0] for s in specs if "@" in s[1:]} - {"__metadata"})
            continue
        m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?\s*$', line)
        if m and names:
            version = m.group(1)
            if not version.startswith("0.0.0-use.local"):
                out.extend(_lang_pkg("NPM", n, version, loc) for n in names)
            names = []
    return out


PNPM_KEY = re.compile(r"^  ['\"]?/?((?:@[^/@\s'\"]+/)?[^@\s/'\"]+)[@/]([0-9][^:('\"\s_]*)")


def parse_pnpm_lock(text: str, loc: str) -> list[Package]:
    out, section = [], ""
    for line in text.splitlines():
        if line and not line[0].isspace():
            section = line.split(":", 1)[0].strip()
            continue
        if section == "packages":
            m = PNPM_KEY.match(line)
            if m:
                out.append(_lang_pkg("NPM", m.group(1), m.group(2), loc))
    return out


def parse_go_mod(text: str, loc: str) -> list[Package]:
    out, in_block = [], False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("toolchain go"):
            out.append(_lang_pkg("Go", "stdlib", line.split("go", 1)[1].strip(), loc))
            continue
        body = line[len("require "):] if line.startswith("require ") else (line if in_block else "")
        parts = body.split()
        if len(parts) >= 2 and parts[1].startswith("v"):
            out.append(_lang_pkg("Go", parts[0], parts[1].removeprefix("v").split("+incompatible")[0], loc))
    return out


def parse_gemfile_lock(text: str, loc: str) -> list[Package]:
    out, in_specs = [], False
    for line in text.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if line and not line[0].isspace():
            in_specs = False
        m = re.match(r"^    ([A-Za-z0-9_.\-]+) \(([^)]+)\)\s*$", line) if in_specs else None
        if m:
            version = re.sub(r"-(?:x86|x64|arm|aarch|java|universal|mingw|mswin)[\w.\-]*$", "", m.group(2))
            out.append(_lang_pkg("RubyGems", m.group(1), version, loc))
    return out


def parse_composer_lock(text: str, loc: str) -> list[Package]:
    data = json.loads(text)
    return [_lang_pkg("Packagist", p["name"], str(p["version"]).removeprefix("v"), loc, p.get("license"))
            for section in ("packages", "packages-dev") for p in data.get(section) or []
            if p.get("name") and p.get("version") and not str(p["version"]).startswith("dev-")]


def parse_nuget_lock(text: str, loc: str) -> list[Package]:
    data = json.loads(text)
    out = []
    for deps in (data.get("dependencies") or {}).values():
        for name, info in (deps or {}).items():
            if isinstance(info, dict) and info.get("resolved") and info.get("type") != "Project":
                out.append(_lang_pkg("NuGet", name, info["resolved"], loc))
    return out


def parse_pom(text: str, loc: str) -> list[Package]:
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    out = []
    for dep in root.iter():
        if not dep.tag.endswith("}dependency") and dep.tag != "dependency":
            continue
        vals = {child.tag.split("}")[-1]: (child.text or "").strip() for child in dep}
        g, a, v = vals.get("groupId"), vals.get("artifactId"), vals.get("version")
        if g and a and v and "${" not in v and "${" not in g:
            out.append(_lang_pkg("Maven", f"{g}:{a}", v, loc))
    return out


def parse_gradle_lock(text: str, loc: str) -> list[Package]:
    out = []
    for line in text.splitlines():
        m = re.match(r"^([\w.\-]+):([\w.\-]+):([^=\s]+)=", line)
        if m:
            out.append(_lang_pkg("Maven", f"{m.group(1)}:{m.group(2)}", m.group(3), loc))
    return out


def parse_python_metadata(text: str, loc: str) -> list[Package]:
    """*.dist-info/METADATA or *.egg-info/PKG-INFO — installed packages in venvs / site-packages."""
    from email.parser import HeaderParser
    meta = HeaderParser().parsestr(text)
    name, version = meta.get("Name"), meta.get("Version")
    return [_lang_pkg("PyPI", name, version, loc, _license_from_metadata(meta))] if name and version else []


def parse_jar(path: Path, loc: str, data: bytes | None = None, depth: int = 0) -> list[Package]:
    """Maven coordinates from META-INF/maven/**/pom.properties, including nested (fat/shaded) jars."""
    import io
    import zipfile
    out: list[Package] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data) if data is not None else path)
    except (zipfile.BadZipFile, OSError, ValueError):
        return out
    with zf:
        for info in zf.infolist():
            name = info.filename
            if name.startswith("META-INF/maven/") and name.endswith("/pom.properties") and info.file_size < 65536:
                props: dict[str, str] = {}
                for line in zf.read(info).decode("utf-8", "replace").splitlines():
                    k, sep, v = line.partition("=")
                    if sep and not k.startswith("#"):
                        props[k.strip()] = v.strip()
                if props.get("groupId") and props.get("artifactId") and props.get("version"):
                    out.append(_lang_pkg("Maven", f"{props['groupId']}:{props['artifactId']}", props["version"], loc))
            elif (name.endswith((".jar", ".war")) and depth < 2 and info.file_size <= NESTED_JAR_MAX_BYTES):
                out.extend(parse_jar(path, f"{loc}!/{name}", zf.read(info), depth + 1))
    return out


LOCKFILE_PARSERS: dict[str, Any] = {
    "poetry.lock": lambda t, loc: parse_toml_lock(t, loc, "PyPI"),
    "uv.lock": lambda t, loc: parse_toml_lock(t, loc, "PyPI"),
    "pdm.lock": lambda t, loc: parse_toml_lock(t, loc, "PyPI"),
    "Pipfile.lock": parse_pipfile_lock,
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "go.mod": parse_go_mod,
    "Cargo.lock": lambda t, loc: parse_toml_lock(t, loc, "Cargo"),
    "Gemfile.lock": parse_gemfile_lock,
    "composer.lock": parse_composer_lock,
    "packages.lock.json": parse_nuget_lock,
    "pom.xml": parse_pom,
    "gradle.lockfile": parse_gradle_lock,
}


def _parse_node_modules(nm_dir: Path, root: Path) -> list[Package]:
    """Top-level installed npm packages (incl. @scope/*) — used when no lockfile exists, e.g. in images."""
    out: list[Package] = []
    try:
        entries = sorted(nm_dir.iterdir())
    except OSError:
        return out
    candidates: list[Path] = []
    for e in entries:
        if e.name.startswith("@") and e.is_dir():
            with contextlib.suppress(OSError):
                candidates.extend(sorted(e.iterdir()))
        elif not e.name.startswith("."):
            candidates.append(e)
    for pkg_dir in candidates:
        manifest = pkg_dir / "package.json"
        try:
            data = json.loads(manifest.read_text())
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        if isinstance(data, dict) and data.get("name") and data.get("version"):
            out.append(_lang_pkg("NPM", data["name"], str(data["version"]),
                                 manifest.relative_to(root).as_posix(), data.get("license")))
    return out


def scan_path(root: Path, skip_top: set[str] | frozenset[str] = frozenset()) -> list[Package]:
    """Walk a directory tree and parse every supported manifest, lockfile, Python metadata and Java archive."""
    root = root.resolve()
    found: dict[tuple[str, str, str], Package] = {}
    files_seen = 0

    def add(pkgs: list[Package]) -> None:
        for p in pkgs:
            found.setdefault((p.ecosystem, p.name.lower() if p.ecosystem != "Go" else p.name, p.version), p)

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        rel_dir = here.relative_to(root).as_posix()
        dirnames[:] = sorted(d for d in dirnames if d not in SCAN_SKIP_DIRS
                             and (f"{rel_dir}/{d}".lstrip("./") not in skip_top))
        if "node_modules" in dirnames:
            dirnames.remove("node_modules")
            add(_parse_node_modules(here / "node_modules", root))
        for fn in filenames:
            files_seen += 1
            if files_seen > SCAN_MAX_FILES:
                log.warning("Path scan stopped after %d files", SCAN_MAX_FILES)
                return list(found.values())
            fpath = here / fn
            loc = fpath.relative_to(root).as_posix()
            try:
                if fn in LOCKFILE_PARSERS:
                    add(LOCKFILE_PARSERS[fn](fpath.read_text(errors="replace"), loc))
                elif fn.startswith("requirements") and fn.endswith(".txt"):
                    add(parse_requirements(fpath.read_text(errors="replace"), loc))
                elif (fn == "METADATA" and here.name.endswith(".dist-info")) or \
                        (fn == "PKG-INFO" and here.name.endswith(".egg-info")):
                    add(parse_python_metadata(fpath.read_text(errors="replace"), loc))
                elif fn.endswith((".jar", ".war", ".ear")) and not fpath.is_symlink() \
                        and fpath.stat().st_size <= ARCHIVE_MAX_BYTES:
                    add(parse_jar(fpath, loc))
            except Exception as exc:  # one malformed manifest must not abort the scan
                log.debug("Failed to parse %s: %s", loc, exc)
    return list(found.values())


# ---------------------------------------------------------------------------
# Root filesystem + container image scanning
# ---------------------------------------------------------------------------


def parse_dpkg_status(text: str, osv_eco: str | None, root: Path | None = None) -> list[Package]:
    out: list[Package] = []
    for block in text.split("\n\n"):
        fields_: dict[str, str] = {}
        for line in block.splitlines():
            if line and not line[0].isspace() and ":" in line:
                k, _, v = line.partition(":")
                fields_[k] = v.strip()
        name, version, status = fields_.get("Package"), fields_.get("Version"), fields_.get("Status", "")
        if not name or not version or not status.endswith(" installed"):
            continue
        src_name, src_version = name, version
        if fields_.get("Source"):
            src = fields_["Source"].split()
            src_name = src[0]
            if len(src) > 1:
                src_version = src[1].strip("()")
        out.append(Package(
            name=name, version=version, ecosystem="Debian", osv_ecosystem=osv_eco,
            osv_name=src_name if osv_eco and src_name != name else None,
            osv_version=src_version if osv_eco and src_version != version else None,
            license=_debian_copyright_license(root, name) if root else None,
        ))
    return out


def _debian_copyright_license(root: Path | None, pkg: str) -> str | None:
    if root is None:
        return None
    try:
        with open(root / "usr/share/doc" / pkg / "copyright", errors="replace") as fh:
            head = fh.read(65536)
    except OSError:
        return None
    m = re.search(r"^License:\s*(\S[^\n]*)$", head, re.MULTILINE)
    return normalize_license(m.group(1)) if m else None


def parse_apk_installed(text: str, osv_eco: str | None, ecosystem: str = "Alpine", suffix: str = "") -> list[Package]:
    out: list[Package] = []
    for block in text.split("\n\n"):
        f: dict[str, str] = {}
        for line in block.splitlines():
            if len(line) > 2 and line[1] == ":":
                f.setdefault(line[0], line[2:].strip())
        if f.get("P") and f.get("V"):
            origin = f.get("o")
            out.append(Package(
                name=f"{f['P']}{suffix}", version=f["V"], ecosystem=ecosystem, osv_ecosystem=osv_eco,
                osv_name=origin if osv_eco and (origin and origin != f["P"] or suffix) else
                (f["P"] if suffix and osv_eco else None),
                license=normalize_license(f.get("L")),
            ))
    return out


def scan_rootfs(root: Path) -> tuple[list[Package], dict[str, str]]:
    """Inventory an unpacked root filesystem (container image, chroot, mounted disk)."""
    root = root.resolve()
    os_release: dict[str, str] = {}
    for rel in ("etc/os-release", "usr/lib/os-release"):
        with contextlib.suppress(OSError):
            os_release = parse_os_release((root / rel).read_text())
            break
    osv_eco = osv_ecosystem_for_os(os_release)
    pkgs: list[Package] = []
    with contextlib.suppress(OSError):
        pkgs += parse_dpkg_status((root / "var/lib/dpkg/status").read_text(errors="replace"), osv_eco, root)
    with contextlib.suppress(OSError):
        pkgs += parse_apk_installed((root / "lib/apk/db/installed").read_text(errors="replace"), osv_eco)
    if any((root / d).exists() for d in ("var/lib/rpm", "usr/lib/sysimage/rpm")):
        if shutil.which("rpm"):
            raw = _run(["rpm", "--root", str(root), "-qa", "--queryformat", RPM_QUERYFORMAT])
            pkgs += parse_rpm_output(raw or "", "RPM", osv_eco)
        else:
            log.warning("RPM database found in %s but no rpm binary on this host — OS packages skipped", root)
    lang = scan_path(root, ROOTFS_SKIP_TOP)
    log.info("Rootfs %s: %d OS packages, %d language packages (%s)", root, len(pkgs), len(lang),
             os_release.get("PRETTY_NAME", "unknown OS"))
    return pkgs + lang, os_release


def _safe_tar_filter(member: Any, dest: str) -> Any:
    """tarfile 'data' filter, but skip (instead of abort on) unsafe members such as absolute symlinks."""
    import tarfile
    if member.ischr() or member.isblk() or member.isfifo():
        return None
    try:
        return tarfile.data_filter(member, dest)
    except tarfile.FilterError:
        return None


def export_image(ref: str, dest: Path) -> str:
    """Unpack a container image's filesystem into dest using podman or docker. Returns the engine used."""
    import tarfile
    engine = shutil.which("podman") or shutil.which("docker")
    if not engine:
        raise RuntimeError("image scanning needs podman or docker on PATH")
    created = subprocess.run([engine, "create", ref, "openbom-noop"], capture_output=True, text=True,
                             timeout=900, check=False)
    if created.returncode != 0:
        raise RuntimeError(f"{Path(engine).name} create {ref} failed: {created.stderr.strip()[:300]}")
    cid = created.stdout.strip().splitlines()[-1]
    try:
        proc = subprocess.Popen([engine, "export", cid], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        assert proc.stdout is not None
        with tarfile.open(fileobj=proc.stdout, mode="r|") as tar:
            tar.extractall(dest, filter=_safe_tar_filter)
        proc.wait(timeout=60)
    finally:
        subprocess.run([engine, "rm", "-f", cid], capture_output=True, timeout=120, check=False)
    return Path(engine).name


# ---------------------------------------------------------------------------
# SBOM input (CycloneDX / SPDX from Syft, Trivy, cdxgen, …)
# ---------------------------------------------------------------------------

DEBIAN_CODENAMES = {"trixie": "13", "bookworm": "12", "bullseye": "11", "buster": "10", "stretch": "9"}
UBUNTU_CODENAMES = {"plucky": "25.04", "oracular": "24.10", "noble": "24.04:LTS", "mantic": "23.10",
                    "jammy": "22.04:LTS", "focal": "20.04:LTS", "bionic": "18.04:LTS"}
PURL_TYPES = {"pypi": "PyPI", "npm": "NPM", "golang": "Go", "cargo": "Cargo", "gem": "RubyGems",
              "composer": "Packagist", "nuget": "NuGet", "maven": "Maven"}


def parse_purl(purl: str) -> dict[str, Any] | None:
    from urllib.parse import unquote
    if not purl or not purl.startswith("pkg:"):
        return None
    rest = purl[4:].split("#", 1)[0]
    rest, _, query = rest.partition("?")
    qualifiers = {}
    for pair in query.split("&") if query else []:
        k, _, v = pair.partition("=")
        qualifiers[k.lower()] = unquote(v)
    version = None
    head, at, tail = rest.rpartition("@")
    if at and "/" not in tail:
        rest, version = head, unquote(tail)
    parts = [unquote(p) for p in rest.strip("/").split("/")]
    if len(parts) < 2:
        return None
    return {"type": parts[0].lower(), "namespace": "/".join(parts[1:-1]) or None, "name": parts[-1],
            "version": version, "qualifiers": qualifiers}


def _distro_osv_ecosystem(namespace: str | None, distro: str | None) -> str | None:
    ns = (namespace or "").lower()
    d = (distro or "").lower()
    ver = re.sub(r"^[a-z\-]+?-(?=\d)", "", d)  # "debian-12" → "12", "almalinux-9.3" → "9.3"
    major = ver.split(".")[0] if ver[:1].isdigit() else ""
    if ns == "debian":
        major = major or DEBIAN_CODENAMES.get(d, "")
        return f"Debian:{major}" if major else None
    if ns == "ubuntu":
        if d in UBUNTU_CODENAMES:
            return f"Ubuntu:{UBUNTU_CODENAMES[d]}"
        m = re.match(r"(\d+\.\d+)", ver)
        return f"Ubuntu:{m.group(1)}:LTS" if m and m.group(1).endswith(".04") and int(m.group(1)[:2]) % 2 == 0 \
            else (f"Ubuntu:{m.group(1)}" if m else None)
    if ns in ("almalinux", "alma") and major:
        return f"AlmaLinux:{major}"
    if ns in ("rocky", "rocky-linux", "rockylinux") and major:
        return f"Rocky Linux:{major}"
    if ns == "alpine":
        m = re.match(r"(\d+\.\d+)", ver)
        return f"Alpine:v{m.group(1)}" if m else None
    return None


def package_from_purl(purl: str, license: Any = None, location: str | None = None) -> Package | None:
    p = parse_purl(purl)
    if not p or not p["version"]:
        return None
    t, ns, name, version, q = p["type"], p["namespace"], p["name"], p["version"], p["qualifiers"]
    if t in PURL_TYPES:
        eco = PURL_TYPES[t]
        if t == "golang" and name != "stdlib":
            version = version.removeprefix("v")
        full = name
        if t == "maven" and ns:
            full = f"{ns}:{name}"
        elif t in ("npm", "golang", "composer") and ns:
            full = f"{ns}/{name}"
        pkg = _lang_pkg(eco, full, version, location or "sbom", license)
        return pkg
    if t in ("deb", "rpm", "apk"):
        osv_eco = _distro_osv_ecosystem(ns, q.get("distro"))
        upstream = re.split(r"[@\s(]", q.get("upstream", ""))[0] or None
        eco = {"deb": "Debian", "rpm": "RPM", "apk": "Alpine"}[t]
        osv_version = f"{q['epoch']}:{version}" if t == "rpm" and q.get("epoch") and osv_eco else None
        return Package(name=name, version=version, ecosystem=eco, osv_ecosystem=osv_eco,
                       osv_name=upstream if osv_eco and upstream and upstream != name else None,
                       osv_version=osv_version, license=normalize_license(license), location=location)
    return None


def parse_sbom_document(data: dict[str, Any]) -> tuple[list[Package], dict[str, str]]:
    """Packages + metadata from a CycloneDX or SPDX JSON document."""
    pkgs: list[Package] = []
    skipped = 0
    meta: dict[str, str] = {}
    if data.get("bomFormat") == "CycloneDX":
        meta = {"format": f"CycloneDX {data.get('specVersion', '')}".strip(),
                "name": ((data.get("metadata") or {}).get("component") or {}).get("name", "")}
        stack = list(data.get("components") or [])
        while stack:
            c = stack.pop(0)
            stack.extend(c.get("components") or [])
            pkg = package_from_purl(c.get("purl", ""), c.get("licenses"), "sbom")
            if pkg:
                pkgs.append(pkg)
            elif c.get("type") in (None, "library", "framework", "application", "operating-system"):
                skipped += 1
    elif str(data.get("spdxVersion", "")).startswith("SPDX-"):
        meta = {"format": data["spdxVersion"], "name": data.get("name", "")}
        for sp in data.get("packages") or []:
            purl = next((r.get("referenceLocator") for r in sp.get("externalRefs") or []
                         if r.get("referenceType") == "purl"), None)
            lic = sp.get("licenseConcluded") if sp.get("licenseConcluded") not in (None, "NOASSERTION", "NONE") \
                else sp.get("licenseDeclared")
            pkg = package_from_purl(purl or "", lic, "sbom")
            if pkg:
                pkgs.append(pkg)
            else:
                skipped += 1
    else:
        raise ValueError("not a CycloneDX or SPDX JSON document")
    if skipped:
        log.info("SBOM: %d component(s) without a usable purl were skipped", skipped)
    dedup: dict[tuple[str, str, str], Package] = {}
    for p in pkgs:
        dedup.setdefault((p.ecosystem, p.name, p.version), p)
    return list(dedup.values()), meta


# ---------------------------------------------------------------------------
# End-of-life detection (endoflife.date)
# ---------------------------------------------------------------------------

EOL_API = "https://endoflife.date/api"
EOL_PRODUCTS = {"fedora": "fedora", "debian": "debian", "ubuntu": "ubuntu", "almalinux": "almalinux",
                "rocky": "rocky-linux", "rhel": "rhel", "centos": "centos-stream", "alpine": "alpine-linux",
                "amzn": "amazon-linux", "opensuse-leap": "opensuse", "sles": "sles", "ol": "oracle-linux"}


def eol_targets(os_release: dict[str, str], include_runtimes: bool = False) -> list[tuple[str, str, str]]:
    """(endoflife.date product, release cycle, label) tuples to check."""
    targets: list[tuple[str, str, str]] = []
    os_id = os_release.get("ID", "").lower()
    ver = os_release.get("VERSION_ID", "")
    product = EOL_PRODUCTS.get(os_id)
    if product and ver:
        if os_id in ("debian", "almalinux", "rocky", "rhel", "centos", "ol"):
            cycle = ver.split(".")[0]
        elif os_id == "alpine":
            cycle = ".".join(ver.split(".")[:2])
        else:
            cycle = ver
        targets.append((product, cycle, os_release.get("PRETTY_NAME", f"{os_id} {ver}")))
    if include_runtimes:
        targets.append(("python", f"{sys.version_info.major}.{sys.version_info.minor}",
                        f"Python {sys.version_info.major}.{sys.version_info.minor} (agent interpreter)"))
        node = _run(["node", "--version"], timeout=10) if shutil.which("node") else None
        if node and node.strip().lstrip("v").split(".")[0].isdigit():
            major = node.strip().lstrip("v").split(".")[0]
            targets.append(("nodejs", major, f"Node.js {major}"))
    return targets


def evaluate_eol(entry: dict[str, Any], today: datetime | None = None) -> tuple[bool, str, int | None]:
    """Return (is_eol, eol_date_or_flag, days_left) from an endoflife.date cycle record."""
    today = today or datetime.now(timezone.utc)
    eol = entry.get("eol")
    if isinstance(eol, bool):
        return eol, str(eol).lower(), None
    try:
        eol_date = datetime.fromisoformat(str(eol)).replace(tzinfo=timezone.utc)
    except ValueError:
        return False, str(eol), None
    days = (eol_date - today).days
    return days < 0, str(eol), days


async def check_eol(targets: list[tuple[str, str, str]]) -> list[dict[str, Any]]:
    try:
        import httpx
    except ImportError:
        return []
    cache_path = state_dir() / "eol_cache.json"
    cache = _read_private_json(cache_path)
    cache = cache if isinstance(cache, dict) else {}
    results: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
        for product, cycle, label in targets:
            key = f"{product}/{cycle}"
            entry = cache.get(key)
            if not entry or time.time() - entry.get("_ts", 0) > KEV_CACHE_TTL:
                try:
                    entry = (await http_request(client, "GET", f"{EOL_API}/{product}/{cycle}.json", retries=2)).json()
                    entry["_ts"] = time.time()
                    cache[key] = entry
                except Exception as exc:
                    log.debug("EOL lookup %s failed: %s", key, exc)
                    continue
            is_eol, eol, days = evaluate_eol(entry)
            results.append({"product": product, "cycle": cycle, "label": label, "eol": eol,
                            "is_eol": is_eol, "days_left": days, "latest": entry.get("latest")})
    try:
        _ensure_private_dir(cache_path.parent)
        _atomic_write(cache_path, json.dumps(cache) + "\n")
    except OSError:
        pass
    for r in results:
        if r["is_eol"]:
            log.warning("END OF LIFE: %s reached EOL on %s", r["label"], r["eol"])
    return results


# ---------------------------------------------------------------------------
# Suppressions: OpenVEX / CycloneDX VEX / ignore file
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Suppression:
    vuln: str
    status: str
    justification: str = ""
    product: str | None = None  # purl (prefix) or package name; None = all packages
    until: datetime | None = None
    source: str = ""


def load_vex(data: dict[str, Any], source: str = "vex") -> list[Suppression]:
    out: list[Suppression] = []
    if "statements" in data:  # OpenVEX
        for st in data.get("statements") or []:
            status = st.get("status", "")
            if status not in ("not_affected", "fixed"):
                continue
            vuln = st.get("vulnerability")
            vid = vuln.get("name") or vuln.get("@id") if isinstance(vuln, dict) else vuln
            products = [pr.get("@id") if isinstance(pr, dict) else pr for pr in st.get("products") or []] or [None]
            for prod in products:
                out.append(Suppression(str(vid), status, st.get("justification") or st.get("impact_statement", ""),
                                       prod, source=source))
    elif data.get("bomFormat") == "CycloneDX":
        refs = {c.get("bom-ref"): c.get("purl") for c in data.get("components") or []}
        for v in data.get("vulnerabilities") or []:
            analysis = v.get("analysis") or {}
            if analysis.get("state") not in ("not_affected", "false_positive", "resolved"):
                continue
            products = [refs.get(a.get("ref")) or a.get("ref") for a in v.get("affects") or []] or [None]
            for prod in products:
                out.append(Suppression(v.get("id", ""), analysis["state"],
                                       analysis.get("justification") or analysis.get("detail", ""), prod,
                                       source=source))
    else:
        raise ValueError("unsupported VEX document (expected OpenVEX or CycloneDX VEX)")
    return out


def load_ignore_file(text: str, source: str = ".openbomignore") -> list[Suppression]:
    """Lines: `VULN-ID [package-or-purl] [until=YYYY-MM-DD] [# reason]`."""
    out: list[Suppression] = []
    for raw in text.splitlines():
        line, _, reason = raw.partition("#")
        parts = line.split()
        if not parts:
            continue
        until = None
        product = None
        for token in parts[1:]:
            if token.startswith("until="):
                with contextlib.suppress(ValueError):
                    until = datetime.fromisoformat(token[6:]).replace(tzinfo=timezone.utc)
            else:
                product = token
        out.append(Suppression(parts[0], "ignored", reason.strip(), product, until, source))
    return out


def _purl_core(purl: str) -> tuple[str, str | None]:
    """'pkg:type/ns/name@ver?q' → ('pkg:type/ns/name', 'ver')."""
    base = purl.split("?", 1)[0].split("#", 1)[0]
    head, at, tail = base.rpartition("@")
    if at and "/" not in tail:
        return head.lower(), tail
    return base.lower(), None


def apply_suppressions(results: list[VulnResult], sups: list[Suppression],
                       os_info: dict[str, str] | None = None) -> list[dict[str, str]]:
    """Remove findings covered by VEX/ignore entries; returns what was suppressed (for the report)."""
    now = datetime.now(timezone.utc)
    active = []
    for s in sups:
        if s.until and s.until < now:
            log.warning("Ignore entry for %s expired on %s — finding will be reported", s.vuln, s.until.date())
        else:
            active.append(s)
    suppressed: list[dict[str, str]] = []
    if not active:
        return suppressed
    for r in results:
        purl = package_purl(r.package, os_info) or ""
        core, ver = _purl_core(purl) if purl else ("", None)
        keep: list[VulnDetail] = []
        for v in r.vulns:
            ids = {v.vuln_id, *v.cves}
            match = None
            for s in active:
                if s.vuln not in ids:
                    continue
                if s.product is None:
                    match = s
                elif s.product.startswith("pkg:"):
                    s_core, s_ver = _purl_core(s.product)
                    if s_core == core and (s_ver is None or s_ver == ver):
                        match = s
                elif s.product.lower() == r.package.name.lower():
                    match = s
                if match:
                    break
            if match:
                suppressed.append({"vuln_id": v.vuln_id, "package": r.package.name, "version": r.package.version,
                                   "status": match.status, "justification": match.justification,
                                   "source": match.source})
            else:
                keep.append(v)
        r.vulns = keep
    if suppressed:
        log.info("Suppressed %d finding(s) via VEX/ignore rules", len(suppressed))
    return suppressed


# ---------------------------------------------------------------------------
# Delta / Diff scanning
# ---------------------------------------------------------------------------


def compute_diff(
    current: list[Package], state_path: Path | None = None,
) -> tuple[dict[str, int], list[str]]:
    """Label packages vs. the previous baseline. Returns (counts, removed package keys).

    Multi-version packages (kernel, kernel-core…) are compared as version sets,
    so co-installed versions are not misreported as upgrades/downgrades.
    """
    state_path = state_path or diff_state_path()
    prev: dict[str, set[str]] = {}
    has_baseline = False
    prev_data = _read_private_json(state_path)
    if isinstance(prev_data, dict):
        try:
            for p in prev_data.get("packages", []):
                prev.setdefault(f"{p['ecosystem']}::{p['name']}", set()).add(p["version"])
            has_baseline = True
        except (KeyError, TypeError):
            log.warning("Could not read previous state from %s — treating all as new", state_path)
            prev = {}

    counts = {"new": 0, "removed": 0, "upgraded": 0, "downgraded": 0, "unchanged": 0}
    curr: dict[str, set[str]] = {}
    for pkg in current:
        curr.setdefault(f"{pkg.ecosystem}::{pkg.name}", set()).add(pkg.version)

    for pkg in current:
        key = f"{pkg.ecosystem}::{pkg.name}"
        if key not in prev:
            pkg.diff_label = "[NEW]"
            counts["new"] += 1
        elif pkg.version in prev[key]:
            pkg.diff_label = None
            counts["unchanged"] += 1
        else:
            newest_prev = max(prev[key], key=functools.cmp_to_key(
                lambda a, b: compare_versions(a, b, pkg.ecosystem)))
            if compare_versions(pkg.version, newest_prev, pkg.ecosystem) < 0:
                pkg.diff_label = "[DOWNGRADED]"
                counts["downgraded"] += 1
            else:
                pkg.diff_label = "[UPGRADED]"
                counts["upgraded"] += 1

    removed = sorted(k for k in prev if k not in curr)
    counts["removed"] = len(removed)
    if not has_baseline:
        log.info("No previous baseline found — this scan becomes the baseline (all packages labelled [NEW])")

    state_data = {"ts": datetime.now(timezone.utc).isoformat(),
                  "packages": [{"name": p.name, "version": p.version, "ecosystem": p.ecosystem} for p in current]}
    try:
        _ensure_private_dir(state_path.parent)
        _atomic_write(state_path, json.dumps(state_data) + "\n")
    except OSError as exc:
        log.warning("Could not save diff state: %s", exc)
    return counts, removed


# ---------------------------------------------------------------------------
# Heuristic IOC scanner + typosquat detection
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def _npm_global_root() -> Path | None:
    out = _run(["npm", "root", "-g"])
    return Path(out.strip()) if out and out.strip() else None


def _package_files(pkg: Package) -> tuple[Path | None, list[Path]]:
    """Return (root dir, files) belonging to an installed package."""
    if pkg.ecosystem == "PyPI":
        try:
            dist = importlib.metadata.distribution(pkg.name)
            files = [Path(str(dist.locate_file(f))) for f in (dist.files or [])]
            files = [f for f in files if f.suffix in HEURISTIC_SUFFIXES]
            if files:
                root = Path(os.path.commonpath([str(f.parent) for f in files]))
                return root, files
        except (importlib.metadata.PackageNotFoundError, ValueError, OSError):
            pass
        normalized = _normalize_name(pkg.name).replace("-", "_")
        for sp in [*site.getsitepackages(), site.getusersitepackages()]:
            candidate = Path(sp) / normalized
            if candidate.is_dir():
                return candidate, []
        return None, []
    if pkg.ecosystem == "NPM":
        root = _npm_global_root()
        if root is not None and (root / pkg.name).is_dir():
            return root / pkg.name, []
    return None, []


def _iter_candidate_files(root: Path, explicit: list[Path]) -> list[Path]:
    if explicit:
        return explicit[:HEURISTIC_MAX_FILES]
    out: list[Path] = []
    try:
        for fpath in root.rglob("*"):
            if len(out) >= HEURISTIC_MAX_FILES:
                break
            if fpath.suffix in HEURISTIC_SUFFIXES and not fpath.is_symlink() and fpath.is_file():
                out.append(fpath)
    except OSError:
        pass
    return out


Hit = tuple[bool, str, str]  # (strong, category, description)


def scan_content(content: str, rel: str) -> list[Hit]:
    """Return (strong, category, description) for every rule matching the given file content."""
    hits: list[Hit] = []
    if rel.endswith(".pth") and not PTH_ALLOWLIST.search(rel):
        for lineno, line in enumerate(content.splitlines(), 1):
            if line.lstrip().startswith("import "):
                hits.append((False, ".pth auto-exec", f".pth auto-exec in {rel}:{lineno}"))
                break
    for rule in HEURISTIC_RULES:
        m = rule.pattern.search(content)
        if m:
            lineno = content.count("\n", 0, m.start()) + 1
            hits.append((rule.strong, rule.label, f"{rule.label} in {rel}:{lineno}"))
    return hits


def _check_npm_install_scripts(root: Path) -> list[Hit]:
    try:
        manifest = json.loads((root / "package.json").read_text())
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return []
    scripts = manifest.get("scripts") or {}
    hits: list[Hit] = []
    for hook in NPM_INSTALL_HOOKS:
        cmd = scripts.get(hook)
        if isinstance(cmd, str) and SUSPICIOUS_INSTALL_SCRIPT.search(cmd):
            strong = bool(DOWNLOAD_EXEC_SCRIPT.search(cmd))
            hits.append((strong, "npm install hook", f"npm {hook} script runs '{cmd[:80]}'"))
    return hits


def evaluate_hits(hits: list[Hit]) -> tuple[str, list[str]] | None:
    """Decide whether hits amount to a detection. Returns (severity, descriptions) or None."""
    strong = [d for s, _, d in hits if s]
    weak = [(c, d) for s, c, d in hits if not s]
    if strong:
        return "CRITICAL", strong + [d for _, d in weak]
    if len({c for c, _ in weak}) >= 2:
        return "HIGH", [d for _, d in weak]
    return None


def scan_heuristics(pkg: Package, progress: Progress | None = None, task_id: Any = None) -> VulnDetail | None:
    """Scan the installed source of a package for malware IOC patterns."""
    hits: list[Hit] = []
    try:
        root, explicit = _package_files(pkg)
        if root is None or not root.is_dir():
            return None
        if pkg.ecosystem == "NPM":
            hits.extend(_check_npm_install_scripts(root))
        for fpath in _iter_candidate_files(root, explicit):
            try:
                if fpath.stat().st_size > HEURISTIC_MAX_FILE_SIZE:
                    continue
                content = fpath.read_text(errors="ignore")
            except OSError:
                continue
            try:
                rel = fpath.relative_to(root).as_posix()
            except ValueError:
                rel = fpath.name
            in_tests = bool(TEST_PATH.search(rel))
            for hit in scan_content(content, rel):
                # weak indicators inside test suites are overwhelmingly fixtures, not payloads
                if hit[0] or (not in_tests and sum(1 for h in hits if not h[0]) < HEURISTIC_MAX_WEAK_HITS):
                    hits.append(hit)
            if sum(1 for h in hits if h[0]) >= HEURISTIC_MAX_FINDINGS:
                break
    finally:
        if progress is not None:
            progress.advance(task_id)

    verdict = evaluate_hits(hits)
    if verdict is None:
        if hits:
            log.debug("Weak heuristic indicators in %s==%s (below threshold): %s",
                      pkg.name, pkg.version, "; ".join(d for _, _, d in hits[:5]))
        return None
    severity, descriptions = verdict
    log.warning("Heuristic IOC detected in %s==%s: %s", pkg.name, pkg.version, "; ".join(descriptions[:5]))
    return VulnDetail(
        vuln_id="MALICIOUS_HEURISTIC",
        severity=severity,
        summary=f"Suspicious code patterns detected: {'; '.join(descriptions[:5])}"[:400],
        fixed_version=None,
        recommendation=f"IMMEDIATE ACTION: Quarantine {pkg.name} — manual review required"
        if severity == "CRITICAL" else f"Review {pkg.name}: multiple suspicious indicators co-occur",
        is_heuristic=True,
    )


def _osa_distance(a: str, b: str, limit: int = 2) -> int:
    """Optimal string alignment distance (Levenshtein + adjacent transposition), capped at limit+1."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


def check_typosquat(pkg: Package) -> VulnDetail | None:
    """Flag PyPI/NPM packages whose name is one edit away from a popular package."""
    popular = POPULAR_PACKAGES.get(pkg.ecosystem)
    if not popular or pkg.name.startswith("@"):
        return None
    name = _normalize_name(pkg.name, pkg.ecosystem)
    if name in popular or name in TYPOSQUAT_ALLOWLIST.get(pkg.ecosystem, frozenset()) or len(name) < 5:
        return None
    for target in sorted(popular):
        if len(target) >= 5 and _osa_distance(name, target, 1) == 1:
            return VulnDetail(
                vuln_id="TYPOSQUAT_SUSPECT",
                severity="MEDIUM",
                summary=f"Package name '{pkg.name}' is one edit away from popular package '{target}'",
                fixed_version=None,
                recommendation=f"Verify '{pkg.name}' is intentional; if you meant '{target}', uninstall it and audit the host",
                is_heuristic=True,
            )
    return None


# ---------------------------------------------------------------------------
# OSV.dev integration (async batch query with enrichment)
# ---------------------------------------------------------------------------


async def _fetch_vuln_detail(client: Any, vuln_id: str, semaphore: asyncio.Semaphore) -> dict[str, Any] | None:
    async with semaphore:
        try:
            resp = await http_request(client, "GET", f"{OSV_VULN_URL}{quote(vuln_id, safe='')}")
            return resp.json()
        except Exception as exc:
            log.debug("Failed to fetch vuln %s: %s", vuln_id, exc)
            return None


async def _enrich_vulns(
    client: Any, vuln_ids: set[str], progress: Progress, enrich_task: Any,
) -> dict[str, dict[str, Any]]:
    if not vuln_ids:
        progress.update(enrich_task, total=1, completed=1)
        return {}
    progress.update(enrich_task, total=len(vuln_ids))
    log.info("Enriching %d unique vulnerability records …", len(vuln_ids))
    semaphore = asyncio.Semaphore(OSV_ENRICH_CONCURRENCY)
    enriched: dict[str, dict[str, Any]] = {}

    async def one(vid: str) -> None:
        result = await _fetch_vuln_detail(client, vid, semaphore)
        if result is not None:
            enriched[vid] = result
        progress.advance(enrich_task)

    await asyncio.gather(*(one(vid) for vid in vuln_ids))
    return enriched


async def _query_remaining_pages(client: Any, pkg: Package, page_token: str) -> list[str]:
    """Follow next_page_token for packages with more vulns than one batch page."""
    ids: list[str] = []
    while page_token:
        payload = {"package": {"name": pkg.query_name, "ecosystem": pkg.osv_ecosystem},
                   "version": pkg.query_version, "page_token": page_token}
        try:
            data = (await http_request(client, "POST", OSV_QUERY_URL, json=payload)).json()
        except Exception as exc:
            log.warning("OSV pagination failed for %s: %s", pkg.name, exc)
            break
        ids.extend(v["id"] for v in data.get("vulns", []) if v.get("id"))
        page_token = data.get("next_page_token", "")
    return ids


async def query_osv_batch(
    packages: list[Package], progress: Progress, task_id: Any, cache: OsvCache | None = None,
) -> tuple[list[VulnResult], dict[str, dict[str, Any]]]:
    enriched_all: dict[str, dict[str, Any]] = {}
    try:
        import httpx
    except ImportError:
        log.error("httpx is required for OSV queries — install with: pip install httpx")
        progress.update(task_id, total=1, completed=1)
        return [], enriched_all

    queryable = [p for p in packages if p.osv_ecosystem]
    if not queryable:
        log.info("No packages in OSV-supported ecosystems")
        progress.update(task_id, total=1, completed=1)
        return [], enriched_all

    eco_counts: dict[str, int] = {}
    for p in queryable:
        eco_counts[p.osv_ecosystem or ""] = eco_counts.get(p.osv_ecosystem or "", 0) + 1
    log.info("OSV-checkable packages: %s", ", ".join(f"{k}={v}" for k, v in sorted(eco_counts.items())))

    progress.update(task_id, total=len(queryable))
    results: list[VulnResult] = []
    to_query: list[Package] = []

    for pkg in queryable:
        cached = cache.get(pkg.osv_ecosystem or "", pkg.query_name, pkg.query_version) if cache else None
        if cached is not None:
            for rv in cached:
                if rv.get("id"):
                    enriched_all[rv["id"]] = rv
            results.append(VulnResult(package=pkg, vulns=parse_vuln_details(
                cached, pkg.osv_ecosystem or pkg.ecosystem, pkg.query_name, pkg.query_version)))
            progress.advance(task_id)
        else:
            to_query.append(pkg)
    if cache is not None and results:
        log.info("Cache hit for %d/%d packages", len(results), len(queryable))
    if not to_query:
        return results, enriched_all

    log.info("Querying OSV.dev for %d packages …", len(to_query))
    pkg_vuln_ids: dict[int, list[str]] = {}
    failed: set[int] = set()

    async with httpx.AsyncClient(timeout=60.0) as client:
        for offset in range(0, len(to_query), OSV_BATCH_SIZE):
            chunk = to_query[offset: offset + OSV_BATCH_SIZE]
            payload = {"queries": [
                {"package": {"name": p.query_name, "ecosystem": p.osv_ecosystem}, "version": p.query_version}
                for p in chunk
            ]}
            try:
                data = (await http_request(client, "POST", OSV_BATCH_URL, json=payload)).json()
            except Exception as exc:
                log.error("OSV batch query failed (%d packages will be reported as unchecked): %s", len(chunk), exc)
                failed.update(range(offset, offset + len(chunk)))
                continue
            for i, entry in enumerate(data.get("results", [])):
                ids = [v.get("id", "") for v in entry.get("vulns", []) or [] if v.get("id")]
                if entry.get("next_page_token"):
                    ids.extend(await _query_remaining_pages(client, chunk[i], entry["next_page_token"]))
                pkg_vuln_ids[offset + i] = ids

        enrich_task = progress.add_task("[magenta]Enriching vulnerability data …", total=None)
        all_ids = {vid for ids in pkg_vuln_ids.values() for vid in ids}
        enriched = await _enrich_vulns(client, all_ids, progress, enrich_task)
        enriched_all.update(enriched)

    missing = all_ids - enriched.keys()
    if missing:
        log.warning("%d vulnerability record(s) could not be enriched — reported with UNKNOWN severity", len(missing))

    for idx, pkg in enumerate(to_query):
        if idx in failed:
            progress.advance(task_id)
            continue
        vids = pkg_vuln_ids.get(idx, [])
        full_vulns = [enriched.get(vid, {"id": vid}) for vid in vids]
        # Only cache complete answers: a failed enrichment must not hide a vuln for 12h
        if cache is not None and all(vid in enriched for vid in vids):
            cache.put(pkg.osv_ecosystem or "", pkg.query_name, pkg.query_version, full_vulns)
        results.append(VulnResult(package=pkg, vulns=parse_vuln_details(
            full_vulns, pkg.osv_ecosystem or pkg.ecosystem, pkg.query_name, pkg.query_version)))
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
    osv_results: list[VulnResult], enriched_vulns: dict[str, dict[str, Any]] | None = None,
) -> dict[str, list[VulnDetail]]:
    cve_to_details: dict[str, list[VulnDetail]] = {}
    for result in osv_results:
        for vd in result.vulns:
            cves = list(vd.cves)
            for cve in CVE_PATTERN.findall(vd.vuln_id):
                if cve not in cves:
                    cves.append(cve)
            raw = (enriched_vulns or {}).get(vd.vuln_id)
            if raw:
                for alias in _extract_cve_aliases(raw):
                    if alias not in cves:
                        cves.append(alias)
            vd.cves = cves
            for cve in cves:
                cve_to_details.setdefault(cve, []).append(vd)
    return cve_to_details


async def query_epss(
    osv_results: list[VulnResult], enriched_vulns: dict[str, dict[str, Any]],
    progress: Progress, task_id: Any,
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

    all_cves = sorted(cve_map)
    progress.update(task_id, total=len(all_cves))
    log.info("Querying EPSS scores for %d CVEs …", len(all_cves))

    async with httpx.AsyncClient(timeout=30.0) as client:
        for offset in range(0, len(all_cves), EPSS_BATCH_SIZE):
            chunk = all_cves[offset: offset + EPSS_BATCH_SIZE]
            try:
                data = (await http_request(client, "GET", EPSS_API_URL, params={"cve": ",".join(chunk)})).json()
            except Exception as exc:
                log.warning("EPSS query failed: %s", exc)
                progress.advance(task_id, advance=len(chunk))
                continue
            for entry in data.get("data", []):
                try:
                    score = float(entry.get("epss", 0))
                    percentile = float(entry.get("percentile", 0))
                except (ValueError, TypeError):
                    continue
                for vd in cve_map.get(entry.get("cve", ""), []):
                    if vd.epss_score is None or score > vd.epss_score:
                        vd.epss_score = score
                        vd.epss_percentile = percentile
            progress.advance(task_id, advance=len(chunk))

    scored = sum(1 for dlist in cve_map.values() for vd in dlist if vd.epss_score is not None)
    log.info("EPSS enrichment complete — scored %d vuln entries", scored)


def apply_kev(
    osv_results: list[VulnResult], enriched_vulns: dict[str, dict[str, Any]] | None, kev: KevCatalog,
) -> int:
    """Cross-reference KEV catalog and set is_kev + kev_description on matching VulnDetails. Returns match count."""
    cve_map = _collect_cve_map(osv_results, enriched_vulns)
    hits = 0
    for cve_id, details in cve_map.items():
        entry = kev.lookup(cve_id)
        if entry:
            for vd in details:
                vd.is_kev = True
                vd.kev_description = f"{cve_id}: {entry.get('shortDescription', '')}"[:240]
            hits += 1
    return hits


# ---------------------------------------------------------------------------
# Alerting + backend push
# ---------------------------------------------------------------------------


def build_alert_text(report: ScanReport) -> str | None:
    critical_pkgs: list[str] = []
    kev_hits: list[str] = []
    ioc_hits: list[str] = []
    mal_hits: list[str] = []
    for r in report.vulnerable:
        mal_hits.extend(f"{v.vuln_id} — {r.package.name}=={r.package.version}" for v in r.vulns if v.is_malicious)
        if any(v.severity == "CRITICAL" and not (v.is_heuristic or v.is_malicious) for v in r.vulns):
            critical_pkgs.append(f"{r.package.name}=={r.package.version}")
        kev_hits.extend(f"{v.vuln_id} on {r.package.name}" for v in r.vulns if v.is_kev)
        ioc_hits.extend(f"{v.vuln_id} on {r.package.name}=={r.package.version}" for v in r.vulns if v.is_heuristic)
    eol_hits = [f"{e['product']} {e['cycle']} (EOL {e['eol']})" for e in report.eol or [] if e.get("is_eol")]
    if not (critical_pkgs or kev_hits or ioc_hits or mal_hits or eol_hits):
        return None
    lines = [f"*OpenBOM Alert* — `{report.hostname}`"]
    if mal_hits:
        lines.append(f"*{len(mal_hits)} KNOWN MALICIOUS* package(s) — treat host as compromised:")
        lines.extend(f"  • `{h}`" for h in mal_hits[:10])
    if ioc_hits:
        lines.append(f"*{len(ioc_hits)} heuristic/supply-chain* detection(s):")
        lines.extend(f"  • `{h}`" for h in ioc_hits[:10])
    if kev_hits:
        lines.append(f"*{len(kev_hits)} CISA KEV* match(es):")
        lines.extend(f"  • `{h}`" for h in kev_hits[:10])
    if critical_pkgs:
        lines.append(f"*{len(critical_pkgs)} CRITICAL* package(s):")
        lines.extend(f"  • `{p}`" for p in critical_pkgs[:15])
    if eol_hits:
        lines.append("*End-of-life* software: " + ", ".join(eol_hits))
    lines.append(f"Scan time: {report.scan_ts}")
    return "\n".join(lines)


async def send_webhook_alert(webhook_url: str, report: ScanReport) -> bool:
    try:
        import httpx
    except ImportError:
        log.error("httpx required for webhook — skipping alert")
        return False
    text = build_alert_text(report)
    if text is None:
        log.info("No CRITICAL/KEV/IOC findings — webhook alert not triggered")
        return False
    # "text" for Slack/Teams/Mattermost, "content" for Discord
    payload = {"text": text, "content": text[:1900], "title": f"OpenBOM Alert — {report.hostname}"}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            await http_request(client, "POST", webhook_url, json=payload)
        host = re.sub(r"^https?://([^/]+).*$", r"\1", webhook_url)
        log.info("Webhook alert sent to %s", host)  # never log the full URL — it embeds the secret
        return True
    except Exception as exc:
        log.error("Webhook delivery failed: %s", type(exc).__name__)
        return False


async def push_to_server(server_url: str, payload: dict[str, Any], api_key: str | None = None) -> dict[str, Any] | None:
    """POST a scan to the OpenBOM backend. Returns the ingest response or None on failure."""
    try:
        import httpx
    except ImportError:
        log.error("httpx required to push results")
        return None
    url = server_url.rstrip("/") + "/api/v1/ingest"
    headers = {"Content-Type": "application/json", "User-Agent": f"openbom-agent/{AGENT_VERSION}"}
    if api_key:
        headers["X-API-Key"] = api_key
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await http_request(client, "POST", url, json=payload, headers=headers)
            body = resp.json()
        log.info("Pushed scan to %s — %s packages, %s vulnerability links",
                 server_url, body.get("packages_processed"), body.get("vulnerabilities_linked"))
        return body
    except Exception as exc:
        detail = ""
        resp = getattr(exc, "response", None)
        if resp is not None:
            detail = f" (HTTP {resp.status_code}: {resp.text[:200]})"
        log.error("Push to %s failed: %s%s", server_url, type(exc).__name__, detail)
        return None


# ---------------------------------------------------------------------------
# CycloneDX export
# ---------------------------------------------------------------------------


_OSV_DISTRO_PURL = {"Debian": "debian", "Ubuntu": "ubuntu", "AlmaLinux": "almalinux", "Rocky Linux": "rocky",
                    "Alpine": "alpine"}


def _distro_qualifier(pkg: Package, os_info: dict[str, str] | None) -> tuple[str, str | None]:
    """(purl namespace, distro qualifier) — derived from the OSV ecosystem so re-imports map back to OSV."""
    if pkg.osv_ecosystem and ":" in pkg.osv_ecosystem:
        family, _, ver = pkg.osv_ecosystem.partition(":")
        ns = _OSV_DISTRO_PURL.get(family)
        if ns:
            return ns, f"{ns}-{ver.split(':')[0].lstrip('v')}"
    info = os_info or {}
    ns = info.get("id") or "linux"
    return ns, f"{ns}-{info['version_id']}" if info.get("version_id") else None


def _purl(ptype: str, segments: list[str], version: str, qualifiers: dict[str, str | None] | None = None) -> str:
    path = "/".join(quote(seg, safe="") for seg in segments)
    q = "&".join(f"{k}={quote(v, safe='')}" for k, v in sorted((qualifiers or {}).items()) if v)
    return f"pkg:{ptype}/{path}@{quote(version, safe='')}" + (f"?{q}" if q else "")


def package_purl(pkg: Package, os_info: dict[str, str] | None = None) -> str | None:
    name = re.sub(r" \[[0-9a-f]+\]$", "", pkg.name)
    base = pkg.ecosystem.rsplit("-", 1)[-1] if pkg.ecosystem.startswith(("Podman-", "Docker-")) else pkg.ecosystem
    if base == "PyPI":
        return _purl("pypi", [_normalize_name(name)], pkg.version)
    if base == "NPM":
        return _purl("npm", name.split("/", 1) if name.startswith("@") else [name], pkg.version)
    if base == "Go":
        return _purl("golang", name.split("/"), pkg.version if name == "stdlib" else f"v{pkg.version}")
    if base == "Cargo":
        return _purl("cargo", [name], pkg.version)
    if base == "RubyGems":
        return _purl("gem", [name], pkg.version)
    if base == "Packagist":
        return _purl("composer", name.split("/", 1), pkg.version)
    if base == "NuGet":
        return _purl("nuget", [name], pkg.version)
    if base == "Maven":
        return _purl("maven", name.split(":", 1), pkg.version)
    ns, distro = _distro_qualifier(pkg, os_info)
    upstream = pkg.osv_name if pkg.osv_name and pkg.osv_name != name else None
    if base == "RPM":
        epoch = pkg.osv_version.split(":", 1)[0] if pkg.osv_version and ":" in pkg.osv_version else None
        return _purl("rpm", [ns, name], pkg.version, {"epoch": epoch, "distro": distro})
    if base in ("Debian", "DEB"):
        return _purl("deb", [ns, name], pkg.version, {"distro": distro, "upstream": upstream})
    if base in ("Alpine", "APK"):
        return _purl("apk", [ns, name], pkg.version, {"distro": distro, "upstream": upstream})
    return None


def to_cyclonedx(report: ScanReport) -> dict[str, Any]:
    components: list[dict[str, Any]] = []
    refs: dict[tuple[str, str, str], str] = {}
    used_refs: set[str] = set()
    for p in report.packages:
        key = (p.ecosystem, p.name, p.version)
        if key in refs:
            continue
        purl = package_purl(p, report.os_info)
        ref = purl or f"{p.ecosystem}:{p.name}@{p.version}"
        if ref in used_refs:
            ref = f"{ref}#{len(refs)}"
        refs[key] = ref
        used_refs.add(ref)
        comp: dict[str, Any] = {"type": "library", "bom-ref": ref, "name": p.name, "version": p.version,
                                "properties": [{"name": "openbom:ecosystem", "value": p.ecosystem}]}
        if purl:
            comp["purl"] = purl
        if p.diff_label:
            comp["properties"].append({"name": "openbom:diff", "value": p.diff_label})
        components.append(comp)

    vulns: dict[str, dict[str, Any]] = {}
    for r in report.vulnerable:
        key = (r.package.ecosystem, r.package.name, r.package.version)
        ref = refs.get(key) or f"{r.package.ecosystem}:{r.package.name}@{r.package.version}"
        for v in r.vulns:
            vid = f"{v.vuln_id}::{r.package.name}" if v.is_heuristic else v.vuln_id
            entry = vulns.get(vid)
            if entry is None:
                rating: dict[str, Any] = {"severity": v.severity.lower() if v.severity != "UNKNOWN" else "unknown"}
                if v.cvss_score is not None:
                    rating.update({"score": v.cvss_score, "method": "CVSSv31"})
                props = []
                if v.epss_score is not None:
                    props.append({"name": "openbom:epss", "value": f"{v.epss_score:.5f}"})
                if v.is_kev:
                    props.append({"name": "openbom:cisa_kev", "value": "true"})
                entry = {
                    "bom-ref": f"vuln-{len(vulns)}",
                    "id": v.vuln_id,
                    "source": {"name": "OpenBOM heuristics" if v.is_heuristic else "OSV",
                               **({} if v.is_heuristic else {"url": f"https://osv.dev/vulnerability/{v.vuln_id}"})},
                    "ratings": [rating],
                    "description": v.summary,
                    "recommendation": v.recommendation,
                    "affects": [],
                    "properties": props,
                }
                if v.poc_links:
                    entry["advisories"] = [{"url": u} for u in v.poc_links[:10]]
                vulns[vid] = entry
            entry["affects"].append({"ref": ref})

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": report.scan_ts or datetime.now(timezone.utc).isoformat(),
            "tools": {"components": [{"type": "application", "name": "OpenBOM Agent", "version": AGENT_VERSION}]},
            "component": {"type": "device", "name": report.hostname, "bom-ref": f"host:{report.hostname}"},
        },
        "components": components,
        "vulnerabilities": list(vulns.values()),
    }


def write_cyclonedx(report: ScanReport, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(to_cyclonedx(report), indent=2) + "\n")
    log.info("CycloneDX SBOM written to %s", dest)


# ---------------------------------------------------------------------------
# Rich terminal output
# ---------------------------------------------------------------------------


def render_summary_table(report: ScanReport, max_rows: int = 200) -> None:
    console.print()

    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold cyan")
    info.add_column()
    info.add_row("Asset", escape(report.hostname))
    if report.scan_target and report.scan_target.get("type") != "host":
        info.add_row("Target", escape(f"{report.scan_target.get('type')}: {report.scan_target.get('ref')}"))
    if report.os_info and report.os_info.get("pretty_name"):
        info.add_row("OS", escape(report.os_info["pretty_name"]))
    info.add_row("Scan Time", report.scan_ts)
    info.add_row("Total Packages", str(len(report.packages)))
    eco_counts: dict[str, int] = {}
    for p in report.packages:
        eco_counts[p.ecosystem] = eco_counts.get(p.ecosystem, 0) + 1
    for eco, cnt in sorted(eco_counts.items()):
        info.add_row(f"{eco} Packages", str(cnt))
    if report.osv_results is not None:
        info.add_row("OSV-checked", str(report.queried))
    console.print(Panel(info, title="[bold]OpenBOM Scan Summary[/bold]", border_style="blue", expand=False))

    if report.diff_summary:
        ds = report.diff_summary
        diff_parts: list[str] = []
        for key, style, prefix in [("new", "green", "+"), ("removed", "red", "-"), ("upgraded", "cyan", ""),
                                   ("downgraded", "yellow", ""), ("unchanged", "dim", "")]:
            if ds.get(key):
                diff_parts.append(f"[{style}]{prefix}{ds[key]} {key}[/{style}]")
        if diff_parts:
            body = "  ".join(diff_parts)
            if report.removed_packages:
                shown = ", ".join(escape(k.split("::", 1)[-1]) for k in report.removed_packages[:10])
                more = f" (+{len(report.removed_packages) - 10} more)" if len(report.removed_packages) > 10 else ""
                body += f"\n[dim]Removed: {shown}{more}[/dim]"
            downgraded = [p for p in report.packages if p.diff_label == "[DOWNGRADED]"]
            if downgraded:
                body += "\n[yellow]Downgraded: " + ", ".join(
                    escape(f"{p.name}=={p.version}") for p in downgraded[:10]) + "[/yellow]"
            console.print(Panel(body, title="[bold]Delta from Last Scan[/bold]", border_style="yellow", expand=False))

    eol_rows = report.eol or []
    if eol_rows:
        lines = []
        for e in eol_rows:
            if e.get("is_eol"):
                lines.append(f"  [bold bright_red]EOL[/bold bright_red] {escape(e['label'])} — ended {e['eol']}")
            elif e.get("days_left") is not None and e["days_left"] <= 180:
                lines.append(f"  [yellow]SOON[/yellow] {escape(e['label'])} — EOL {e['eol']} ({e['days_left']} days)")
            else:
                lines.append(f"  [green]OK[/green]   {escape(e['label'])} — supported until {e['eol']}")
        console.print(Panel("\n".join(lines), title="[bold]End-of-life status[/bold]",
                            border_style="red" if any(e.get("is_eol") for e in eol_rows) else "green", expand=False))

    if report.license_violations:
        lv = report.license_violations
        console.print(Panel(
            "\n".join(f"  [bold red]{escape(v['package'])}[/bold red]=={escape(v['version'])} "
                      f"[dim]({escape(v['ecosystem'])})[/dim] — {escape(v['license'])} [dim](rule {escape(v['rule'])})[/dim]"
                      for v in lv[:25]) + (f"\n  … {len(lv) - 25} more" if len(lv) > 25 else ""),
            title=f"[bold red]License policy violations ({len(lv)})[/bold red]", border_style="red", expand=False))

    if report.suppressed:
        console.print(f"[dim]{len(report.suppressed)} finding(s) suppressed by VEX/ignore rules "
                      f"(listed under 'suppressed' in the JSON report)[/dim]")

    if report.osv_results is None:
        return

    vulnerable = report.vulnerable
    if not vulnerable:
        console.print(Panel("[bold green]No known vulnerabilities or IOC detections found.[/bold green]",
                            title="Results", border_style="green", expand=False))
        return

    summary = report.to_dict().get("osv_summary", {})

    mal_findings = [(r, v) for r in vulnerable for v in r.vulns if v.is_malicious]
    if mal_findings:
        console.print(Panel(
            "\n".join(f"  [blink bold bright_red]>>> {escape(v.vuln_id)}[/blink bold bright_red] "
                      f"[bold]{escape(r.package.name)}=={escape(r.package.version)}[/bold] ({escape(r.package.ecosystem)})"
                      f"\n      [dim]{escape(v.summary[:120])}[/dim]{_location_line(r.package)}" for r, v in mal_findings),
            title=f"[blink bold bright_red]KNOWN MALICIOUS PACKAGES — {len(mal_findings)} (OpenSSF)[/blink bold bright_red]",
            subtitle="remove immediately and treat the host as compromised",
            border_style="bright_red", expand=False,
        ))

    kev_findings = [(r, v) for r in vulnerable for v in r.vulns if v.is_kev]
    if kev_findings:
        kev_lines: list[str] = []
        for r, v in kev_findings:
            kev_lines.append(
                f"  [blink bold bright_red]>>> {escape(v.vuln_id)}[/blink bold bright_red]"
                f" on [bold]{escape(r.package.name)}=={escape(r.package.version)}[/bold]"
            )
            if v.kev_description:
                kev_lines.append(f"      [dim]{escape(v.kev_description[:120])}[/dim]")
            if r.package.location:
                kev_lines.append(_location_line(r.package).lstrip("\n"))
        console.print(Panel(
            "\n".join(kev_lines),
            title=f"[blink bold bright_red]CISA KEV — {len(kev_findings)} ACTIVELY EXPLOITED[/blink bold bright_red]",
            border_style="bright_red", expand=False,
        ))

    heuristic_findings = [(r, v) for r in vulnerable for v in r.vulns if v.is_heuristic]
    if heuristic_findings:
        h_lines: list[str] = []
        for r, v in heuristic_findings:
            tag = "TYPOSQUAT?" if v.vuln_id == "TYPOSQUAT_SUSPECT" else "MALWARE"
            h_lines.append(
                f"  [blink bold bright_red]{tag}[/blink bold bright_red]"
                f" [bold]{escape(r.package.name)}=={escape(r.package.version)}[/bold] ({v.severity})"
            )
            h_lines.append(f"      [yellow]{escape(v.summary[:160])}[/yellow]{_location_line(r.package)}")
        console.print(Panel(
            "\n".join(h_lines),
            title="[blink bold bright_red]HEURISTIC IOC — POSSIBLE SUPPLY-CHAIN ATTACK[/blink bold bright_red]",
            border_style="bright_red", expand=False,
        ))

    sev_table = Table(title="Vulnerability Metrics", show_header=True, header_style="bold")
    sev_table.add_column("Severity", justify="center")
    sev_table.add_column("Count", justify="center")
    for sev, color in [("CRITICAL", "bold red"), ("HIGH", "red"), ("MEDIUM", "yellow"), ("LOW", "green"),
                       ("UNKNOWN", "dim")]:
        cnt = summary.get(f"total_{sev.lower()}", 0)
        if cnt > 0:
            sev_table.add_row(Text(sev, style=color), Text(str(cnt), style=color))
    if summary.get("kev_hits"):
        sev_table.add_row(Text("CISA KEV", style="blink bold bright_red"),
                          Text(str(summary["kev_hits"]), style="bold bright_red"))
    if summary.get("poc_count"):
        sev_table.add_row(Text("Has PoC", style="bold yellow"), Text(str(summary["poc_count"]), style="bold yellow"))
    if summary.get("heuristic_hits"):
        sev_table.add_row(Text("Heuristic", style="bold bright_red"),
                          Text(str(summary["heuristic_hits"]), style="bold bright_red"))
    console.print(sev_table)
    console.print()

    detail_table = Table(title="Vulnerable Packages (highest risk first)", show_header=True,
                         header_style="bold magenta", show_lines=True)
    detail_table.add_column("#", justify="right", style="dim", width=4)
    detail_table.add_column("Package", style="bold", min_width=16)
    detail_table.add_column("Version", min_width=8)
    detail_table.add_column("Vuln ID", min_width=20)
    detail_table.add_column("Severity", justify="center", min_width=10)
    detail_table.add_column("EPSS", justify="center", min_width=7)
    detail_table.add_column("Intel", justify="center", min_width=8)
    detail_table.add_column("Recommendation", min_width=24)

    sev_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green", "UNKNOWN": "dim"}
    rows = sorted(((r, v) for r in vulnerable for v in r.vulns), key=lambda rv: finding_sort_key(rv[1]))
    for idx, (r, v) in enumerate(rows[:max_rows], 1):
        pkg_label = r.package.name if not r.package.diff_label else f"{r.package.diff_label} {r.package.name}"
        pkg_cell = Text(pkg_label)
        if r.package.location:
            pkg_cell.append(f"\n{r.package.location}", style="dim cyan")
        if v.epss_score is not None:
            pct = v.epss_score * 100
            epss_obj = Text(f"{pct:.1f}%", style="bold red" if pct >= 10 else ("yellow" if pct >= 1 else "dim"))
        else:
            epss_obj = Text("—", style="dim")
        intel_parts: list[str] = []
        if v.is_kev:
            intel_parts.append("[blink bold bright_red]KEV[/blink bold bright_red]")
        if v.poc_links:
            intel_parts.append(f"[bold yellow]PoC({len(v.poc_links)})[/bold yellow]")
        if v.is_malicious:
            intel_parts.append("[blink bold bright_red]MALWARE[/blink bold bright_red]")
        if v.is_heuristic:
            intel_parts.append("[blink bold bright_red]IOC[/blink bold bright_red]")
        intel_text = Text.from_markup(" ".join(intel_parts)) if intel_parts else Text("—", style="dim")
        detail_table.add_row(
            str(idx), pkg_cell, Text(r.package.version), Text(v.vuln_id),
            Text(v.severity, style=sev_colors.get(v.severity, "white")), epss_obj, intel_text, Text(v.recommendation),
        )
    console.print(detail_table)
    if len(rows) > max_rows:
        console.print(f"[dim]… {len(rows) - max_rows} more finding(s) — see the JSON/HTML report[/dim]")
    console.print()

    high_epss = [(r, v) for r in vulnerable for v in r.vulns if v.epss_score is not None and v.epss_score >= 0.1]
    if high_epss:
        console.print(Panel(
            "\n".join(
                f"  [bold red]{escape(v.vuln_id)}[/bold red] on {escape(r.package.name)}=={escape(r.package.version)}"
                f" — EPSS [bold]{(v.epss_score or 0) * 100:.1f}%[/bold]"
                for r, v in sorted(high_epss, key=lambda x: x[1].epss_score or 0, reverse=True)[:25]
            ),
            title=f"[bold red]High Exploit Probability ({len(high_epss)} findings with EPSS >= 10%)[/bold red]",
            border_style="red", expand=False,
        ))


def _location_line(pkg: Package) -> str:
    return f"\n      [cyan]found in[/cyan] [dim]{escape(pkg.location)}[/dim]" if pkg.location else ""


def finding_sort_key(v: VulnDetail) -> tuple[int, int, int, int, float]:
    return (0 if v.is_malicious else 1, 0 if v.is_heuristic else 1, 0 if v.is_kev else 1,
            SEVERITY_ORDER.get(v.severity, 9), -(v.epss_score or 0))


# ---------------------------------------------------------------------------
# Enterprise reporting — HTML + PDF
# ---------------------------------------------------------------------------


def generate_html_report(report: ScanReport) -> str:
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=select_autoescape(["html"]))
    template = env.get_template("report_template.html")

    d = report.to_dict()
    eco_counts: dict[str, int] = {}
    for p in d["packages"]:
        eco_counts[p["ecosystem"]] = eco_counts.get(p["ecosystem"], 0) + 1

    vulnerabilities = d.get("osv_vulnerabilities", [])
    for finding in vulnerabilities:
        finding["vulns"].sort(key=lambda v: finding_sort_key(VulnDetail.from_dict(v)))
    vulnerabilities.sort(key=lambda f: min((finding_sort_key(VulnDetail.from_dict(v)) for v in f["vulns"]),
                                           default=(9, 9, 9, 9, 0)))

    return template.render(
        hostname=d["hostname"],
        scan_ts=d["scan_ts"],
        os_name=(report.os_info or {}).get("pretty_name", ""),
        agent_version=AGENT_VERSION,
        total_packages=d["total_packages"],
        ecosystem_counts=eco_counts,
        os_packages=sum(v for k, v in eco_counts.items() if k not in ("PyPI", "NPM")),
        pypi_packages=eco_counts.get("PyPI", 0),
        npm_packages=eco_counts.get("NPM", 0),
        summary=d.get("osv_summary", {}),
        vulnerabilities=vulnerabilities,
        diff_summary=d.get("diff_summary"),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )


def write_enterprise_reports(report: ScanReport, output_dir: Path) -> tuple[Path, Path | None]:
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    html_path = output_dir / f"report_openbom_{ts}.html"
    html_content = generate_html_report(report)
    html_path.write_text(html_content)
    log.info("HTML report written to %s", html_path)

    pdf_path: Path | None = output_dir / f"report_openbom_{ts}.pdf"
    try:
        from weasyprint import HTML
        HTML(string=html_content, base_url=str(TEMPLATE_DIR)).write_pdf(str(pdf_path))
        log.info("PDF report written to %s", pdf_path)
    except ImportError:
        log.warning("weasyprint not installed — PDF generation skipped (pip install weasyprint)")
        pdf_path = None
    except Exception as exc:
        log.error("PDF generation failed: %s", exc)
        pdf_path = None
    return html_path, pdf_path


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------


def build_report(
    all_pkgs: list[Package],
    osv_results: list[VulnResult] | None = None,
    diff_summary: dict[str, int] | None = None,
    *,
    hostname: str | None = None,
    removed: list[str] | None = None,
    os_info: dict[str, str] | None = None,
    queried: int = 0,
) -> ScanReport:
    return ScanReport(
        hostname=hostname or socket.gethostname(),
        scan_ts=datetime.now(timezone.utc).isoformat(),
        packages=all_pkgs,
        osv_results=osv_results,
        diff_summary=diff_summary,
        removed_packages=removed,
        os_info=os_info,
        queried=queried,
    )


def write_json_report(report: ScanReport, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(report.to_dict(), indent=2, default=str) + "\n")
    log.info("JSON report written to %s", dest)


def load_report(path: Path) -> ScanReport:
    return ScanReport.from_dict(json.loads(path.read_text()))


def latest_scan_file(output_dir: Path = DEFAULT_OUTPUT_DIR) -> Path | None:
    files = sorted(output_dir.glob("sbom_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def to_sarif(report: ScanReport) -> dict[str, Any]:
    """SARIF 2.1.0 for GitHub/GitLab code scanning: one rule per advisory, one result per affected package."""
    sev_score = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 2.0, "UNKNOWN": 5.0}
    level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "UNKNOWN": "warning"}
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for r in report.vulnerable:
        for v in r.vulns:
            if v.vuln_id not in rules:
                score = v.cvss_score if v.cvss_score is not None else sev_score.get(v.severity, 5.0)
                tags = ["security", "supply-chain"] + (["malicious"] if v.is_malicious else []) + \
                       (["cisa-kev"] if v.is_kev else [])
                rule: dict[str, Any] = {
                    "id": v.vuln_id, "name": v.vuln_id.replace("-", "_"),
                    "shortDescription": {"text": (v.summary or v.vuln_id)[:200]},
                    "fullDescription": {"text": v.summary or v.vuln_id},
                    "help": {"text": v.recommendation, "markdown": v.recommendation},
                    "properties": {"security-severity": f"{score:.1f}", "tags": tags},
                }
                if not v.is_heuristic:
                    rule["helpUri"] = f"https://osv.dev/vulnerability/{v.vuln_id}"
                rules[v.vuln_id] = rule
            fingerprint = hashlib.sha256(f"{r.package.ecosystem}|{r.package.name}|{r.package.version}|{v.vuln_id}"
                                         .encode()).hexdigest()[:32]
            results.append({
                "ruleId": v.vuln_id,
                "level": level.get(v.severity, "warning"),
                "message": {"text": f"{r.package.name} {r.package.version} ({r.package.ecosystem}) is affected by "
                                    f"{v.vuln_id} [{v.severity}]. {v.recommendation}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": (r.package.location or "openbom-sbom.json").split("!/")[0]},
                    "region": {"startLine": 1}}}],
                "partialFingerprints": {"openbom/v1": fingerprint},
                "properties": {"package": r.package.name, "version": r.package.version,
                               "ecosystem": r.package.ecosystem, "epss": v.epss_score, "kev": v.is_kev},
            })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "OpenBOM", "version": AGENT_VERSION,
                                "informationUri": "https://github.com/Masriyan/OpenBOM",
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }


_SPDX_ID = re.compile(r"^[A-Za-z0-9.\-+]+$")


def _spdx_license(lic: str | None, extracted: dict[str, str]) -> str:
    if not lic:
        return "NOASSERTION"
    tokens = re.split(r"\s+(?:AND|OR|WITH)\s+", lic.replace("(", "").replace(")", ""))
    if all(_SPDX_ID.match(t) for t in tokens):
        return lic
    ref = "LicenseRef-" + re.sub(r"[^A-Za-z0-9.\-]+", "-", lic).strip("-")[:60]
    extracted[ref] = lic
    return ref


def to_spdx(report: ScanReport) -> dict[str, Any]:
    """SPDX 2.3 JSON document describing the scanned target."""
    extracted: dict[str, str] = {}
    root_id = "SPDXRef-Target"
    packages: list[dict[str, Any]] = [{
        "SPDXID": root_id, "name": report.hostname, "versionInfo": report.scan_ts[:10] or "unknown",
        "downloadLocation": "NOASSERTION", "filesAnalyzed": False, "primaryPackagePurpose": "OPERATING-SYSTEM"
        if not report.scan_target or report.scan_target.get("type") in ("host", "rootfs", "image") else "APPLICATION",
        "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION",
    }]
    relationships = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root_id}]
    for i, p in enumerate(report.packages, 1):
        sid = f"SPDXRef-Package-{i}"
        entry: dict[str, Any] = {
            "SPDXID": sid, "name": p.name, "versionInfo": p.version, "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False, "licenseConcluded": "NOASSERTION",
            "licenseDeclared": _spdx_license(p.license, extracted), "copyrightText": "NOASSERTION",
            "comment": f"ecosystem={p.ecosystem}" + (f"; location={p.location}" if p.location else ""),
        }
        purl = package_purl(p, report.os_info)
        if purl:
            entry["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                      "referenceLocator": purl}]
        packages.append(entry)
        relationships.append({"spdxElementId": root_id, "relationshipType": "CONTAINS", "relatedSpdxElement": sid})
    doc: dict[str, Any] = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"openbom-{report.hostname}",
        "documentNamespace": f"https://openbom.local/spdx/{quote(report.hostname, safe='')}/{uuid.uuid4()}",
        "creationInfo": {"created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                         "creators": [f"Tool: OpenBOM-Agent-{AGENT_VERSION}"]},
        "packages": packages,
        "relationships": relationships,
    }
    if extracted:
        doc["hasExtractedLicensingInfos"] = [{"licenseId": k, "extractedText": v, "name": v}
                                             for k, v in extracted.items()]
    return doc


def write_json_document(doc: dict[str, Any], dest: Path, label: str) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(doc, indent=2) + "\n")
    log.info("%s written to %s", label, dest)


def exit_code_for(report: ScanReport, fail_on: str) -> int:
    """2 when findings at/above the --fail-on threshold (or KEV / malware / license violations) exist, else 0."""
    if fail_on == "never":
        return 0
    if report.license_violations:
        return 2
    if report.osv_results is None:
        return 0
    threshold = 9 if fail_on == "any" else SEVERITY_ORDER[fail_on.upper()]
    for r in report.vulnerable:
        for v in r.vulns:
            if SEVERITY_ORDER.get(v.severity, 4) <= threshold or v.is_kev or v.is_malicious:
                return 2
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _ecosystem_list(value: str) -> list[str]:
    items = [x.strip().lower() for x in value.split(",") if x.strip()]
    bad = [x for x in items if x not in ALL_ECOSYSTEM_GROUPS]
    if bad or not items:
        raise argparse.ArgumentTypeError(f"choose from {', '.join(ALL_ECOSYSTEM_GROUPS)} (got {value!r})")
    return items


def _csv_list(value: str) -> list[str]:
    return [x.strip() for x in value.split(",") if x.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openbom_agent",
        description=f"OpenBOM Endpoint Agent v{AGENT_VERSION} — supply-chain threat hunting. "
                    "Run without a mode flag on a terminal to open the interactive menu.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--scan-only", action="store_true", help="Collect SBOM only (no network calls)")
    mode.add_argument("--check-osv", action="store_true", help="Collect SBOM + validate via OSV/EPSS/KEV")
    mode.add_argument("--push-file", type=Path, metavar="JSON", help="Upload an existing scan JSON to --server-url")
    mode.add_argument("--menu", action="store_true", help="Open the interactive menu")

    src = parser.add_argument_group("scan targets (default: this host; any of these replaces the host scan)")
    src.add_argument("--path", type=Path, action="append", default=[], metavar="DIR",
                     help="Scan a repository/build tree: lockfiles, manifests, venvs, node_modules, JAR/WAR (repeatable)")
    src.add_argument("--rootfs", type=Path, default=None, metavar="DIR", help="Scan an unpacked root filesystem")
    src.add_argument("--image", default=None, metavar="REF", help="Scan a container image (podman/docker)")
    src.add_argument("--sbom", type=Path, default=None, metavar="FILE",
                     help="Analyse an existing CycloneDX/SPDX JSON SBOM (e.g. from Syft, Trivy, cdxgen)")
    src.add_argument("--ecosystems", type=_ecosystem_list, default=list(ALL_ECOSYSTEM_GROUPS),
                     help="Host sources to inventory: os,pypi,npm,podman,docker (default: all)")

    out = parser.add_argument_group("outputs")
    out.add_argument("-o", "--output", type=Path, default=None, help="JSON report output path")
    out.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
                     help="Directory for JSON/HTML/PDF output (default: ./output)")
    out.add_argument("--report", action="store_true", help="Generate HTML and PDF enterprise reports")
    out.add_argument("--cyclonedx", type=Path, default=None, metavar="PATH", help="Write a CycloneDX 1.5 JSON SBOM")
    out.add_argument("--spdx", type=Path, default=None, metavar="PATH", help="Write an SPDX 2.3 JSON SBOM")
    out.add_argument("--sarif", type=Path, default=None, metavar="PATH",
                     help="Write SARIF 2.1.0 (GitHub/GitLab code scanning)")

    ana = parser.add_argument_group("analysis & policy")
    ana.add_argument("--no-cache", action="store_true", help="Bypass OSV response cache")
    ana.add_argument("--diff", action="store_true", help="Compare against previous scan state of the same target")
    ana.add_argument("--heuristics", choices=["new", "all", "off"], default="new",
                     help="Heuristic IOC + typosquat scope: changed packages (needs --diff), all, or off")
    ana.add_argument("--vex", type=Path, action="append", default=[], metavar="FILE",
                     help="OpenVEX / CycloneDX VEX document: suppress not_affected/fixed findings (repeatable)")
    ana.add_argument("--ignore", type=Path, default=None, metavar="FILE",
                     help="Ignore file: 'VULN-ID [package|purl] [until=YYYY-MM-DD] # reason' per line")
    ana.add_argument("--license-deny", type=_csv_list, default=[], metavar="LIST",
                     help="Fail on these licenses (SPDX id prefixes), e.g. GPL-3.0,AGPL,SSPL")
    ana.add_argument("--deps-dev", action="store_true",
                     help="Fill missing licenses from deps.dev (network)")
    ana.add_argument("--no-eol", action="store_true", help="Skip end-of-life checks (endoflife.date)")
    ana.add_argument("--fail-on", choices=["any", "critical", "high", "medium", "low", "never"], default="any",
                     help="Exit 2 when findings at/above this severity exist (KEV, malware and license "
                          "violations always count)")

    parser.add_argument("--hostname", default=None, help="Override the reported asset name")
    parser.add_argument("--webhook-url", default=os.environ.get("OPENBOM_WEBHOOK_URL"),
                        help="POST critical/KEV/IOC alerts to this URL (env: OPENBOM_WEBHOOK_URL)")
    parser.add_argument("--server-url", default=os.environ.get("OPENBOM_SERVER_URL"),
                        help="Push results to an OpenBOM backend (env: OPENBOM_SERVER_URL)")
    parser.add_argument("--api-key", default=os.environ.get("OPENBOM_API_KEY"),
                        help="API key for the backend (env: OPENBOM_API_KEY)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug-level console logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {AGENT_VERSION}")
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def has_custom_target(args: argparse.Namespace) -> bool:
    return bool(getattr(args, "path", None) or getattr(args, "rootfs", None) or getattr(args, "image", None)
                or getattr(args, "sbom", None))


def asset_name(raw: str) -> str:
    """Asset names travel in URL paths on the backend — keep them free of '/'."""
    return raw.replace("/", "_").strip() or "unknown"


def collect_target_packages(args: argparse.Namespace) -> tuple[list[Package], dict[str, str], dict[str, str], str]:
    """Packages from --path/--rootfs/--image/--sbom. Returns (packages, os_release, scan_target, default name)."""
    pkgs: list[Package] = []
    os_release: dict[str, str] = {}
    target: dict[str, str] = {}
    name = socket.gethostname()
    if args.sbom:
        data = json.loads(Path(args.sbom).read_text())
        sbom_pkgs, meta = parse_sbom_document(data)
        pkgs += sbom_pkgs
        target = {"type": "sbom", "ref": str(args.sbom), "format": meta.get("format", "")}
        name = meta.get("name") or Path(args.sbom).stem
        log.info("SBOM %s (%s): %d packages", args.sbom, meta.get("format"), len(sbom_pkgs))
    if args.image:
        tmp = Path(tempfile.mkdtemp(prefix="openbom-image-"))
        try:
            engine = export_image(args.image, tmp)
            img_pkgs, os_release = scan_rootfs(tmp)
            for p in img_pkgs:  # don't leak temp paths into reports
                if p.location:
                    p.location = p.location.replace(str(tmp), "")
            pkgs += img_pkgs
            target = {"type": "image", "ref": args.image, "engine": engine}
            name = f"image:{args.image}"
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    if args.rootfs:
        fs_pkgs, os_release = scan_rootfs(Path(args.rootfs))
        pkgs += fs_pkgs
        target = {"type": "rootfs", "ref": str(Path(args.rootfs).resolve())}
        name = f"rootfs:{Path(args.rootfs).resolve().name or 'root'}"
    for path in args.path:
        found = scan_path(Path(path))
        log.info("Path %s: %d packages from manifests/lockfiles/archives", path, len(found))
        pkgs += found
        if not target:
            target = {"type": "path", "ref": str(Path(path).resolve())}
            name = f"path:{Path(path).resolve().name}"
    return pkgs, os_release, target, asset_name(name)


async def run_scan(args: argparse.Namespace) -> tuple[int, ScanReport | None]:
    custom = has_custom_target(args)
    console.print(Panel(
        f"[bold cyan]OpenBOM[/bold cyan] Agent v{AGENT_VERSION} — Supply-Chain Threat Hunting",
        subtitle=f"mode={'check-osv' if args.check_osv else 'scan-only'}  heuristics={args.heuristics}",
        border_style="bright_blue", expand=False,
    ))
    os_release: dict[str, str] = {}
    scan_target: dict[str, str] = {"type": "host", "ref": socket.gethostname()}
    default_name = socket.gethostname()

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(), console=console, transient=False,
    ) as progress:

        all_pkgs: list[Package] = []
        if custom:
            t = progress.add_task("[cyan]Collecting packages from targets …", total=1)
            try:
                all_pkgs, os_release, scan_target, default_name = collect_target_packages(args)
            except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
                log.error("Target collection failed: %s", exc)
                return 1, None
            progress.update(t, completed=1)
        else:
            os_release = read_os_release()
            groups = set(args.ecosystems)
            for group, label, fn in [("os", "[cyan]Extracting OS packages …", None),
                                     ("pypi", "[green]Extracting Python packages …", extract_python_packages),
                                     ("npm", "[blue]Extracting NPM packages …", extract_npm_packages),
                                     ("podman", "[yellow]Scanning Podman containers …", extract_podman_containers),
                                     ("docker", "[yellow]Scanning Docker containers …", extract_docker_containers)]:
                if group not in groups:
                    continue
                t = progress.add_task(label, total=None)
                all_pkgs += extract_os_packages(progress, t, os_release) if fn is None else fn(progress, t)
        os_info = _os_summary(os_release) if os_release else None
        hostname = args.hostname or default_name

        if not all_pkgs:
            log.warning("No packages found — nothing to report")
            return 1, None

        diff_summary: dict[str, int] | None = None
        removed: list[str] | None = None
        if args.diff:
            state_key = None if scan_target["type"] == "host" else f"{scan_target['type']}:{scan_target['ref']}"
            diff_summary, removed = compute_diff(all_pkgs, diff_state_path(state_key))
            log.info("Diff: +%d new, -%d removed, %d upgraded, %d downgraded",
                     diff_summary["new"], diff_summary["removed"],
                     diff_summary["upgraded"], diff_summary["downgraded"])

        # --- Heuristic IOC (installed host packages only) + typosquat (any PyPI/npm) ---
        heuristic_results: list[VulnResult] = []
        heuristics_ran = False
        if args.heuristics != "off":
            lang_pkgs = [p for p in all_pkgs if p.ecosystem in ("PyPI", "NPM")]
            if args.heuristics == "new":
                targets = [p for p in lang_pkgs if p.diff_label in ("[NEW]", "[UPGRADED]", "[DOWNGRADED]")]
                if not args.diff:
                    log.info("Heuristic scan targets changed packages and needs --diff (or use --heuristics all)")
            else:
                targets = lang_pkgs
            if targets:
                heuristics_ran = True
                h_task = progress.add_task("[bright_red]Heuristic IOC + typosquat scan …", total=len(targets))
                for pkg in targets:
                    ioc = scan_heuristics(pkg, progress, h_task) if not custom else None
                    if custom:
                        progress.advance(h_task)
                    found = [d for d in (ioc, check_typosquat(pkg)) if d]
                    if found:
                        heuristic_results.append(VulnResult(package=pkg, vulns=found))
            elif args.diff:
                log.info("No new or changed PyPI/NPM packages — heuristic scan skipped")

        # --- Licenses ---
        if args.deps_dev and args.check_osv:
            t = progress.add_task("[cyan]deps.dev license enrichment …", total=None)
            await enrich_licenses_deps_dev(all_pkgs, progress, t)
        license_violations = check_licenses(all_pkgs, args.license_deny) if args.license_deny else None

        # --- OSV + EPSS + KEV + EOL ---
        osv_results: list[VulnResult] | None = None
        queried = 0
        eol: list[dict[str, Any]] | None = None
        if args.check_osv:
            cache = None if args.no_cache else OsvCache()
            osv_task = progress.add_task("[yellow]Querying OSV.dev …", total=None)
            osv_results, enriched_vulns = await query_osv_batch(all_pkgs, progress, osv_task, cache)
            queried = len(osv_results)

            kev = KevCatalog()
            kev_task = progress.add_task("[bright_red]Loading CISA KEV catalog …", total=None)
            epss_task = progress.add_task("[red]Querying EPSS scores …", total=None)
            eol_coro = check_eol(eol_targets(os_release, include_runtimes=not custom)) \
                if not args.no_eol else asyncio.sleep(0, result=None)
            _, _, eol = await asyncio.gather(
                kev.load(progress, kev_task),
                query_epss(osv_results, enriched_vulns, progress, epss_task),
                eol_coro,
            )
            if kev.size > 0:
                kev_hits = apply_kev(osv_results, enriched_vulns, kev)
                log.info("KEV cross-reference: %d match(es) against %d catalog entries", kev_hits, kev.size)

        if heuristic_results:
            osv_results = merge_results(osv_results or [], heuristic_results)
        elif osv_results is None and heuristics_ran:
            osv_results = []

        # --- VEX / ignore ---
        suppressed: list[dict[str, str]] | None = None
        sups: list[Suppression] = []
        for vex_path in args.vex:
            try:
                sups += load_vex(json.loads(Path(vex_path).read_text()), source=str(vex_path))
            except (OSError, ValueError) as exc:
                log.error("Cannot load VEX %s: %s", vex_path, exc)
                return 1, None
        if args.ignore:
            try:
                sups += load_ignore_file(Path(args.ignore).read_text(), source=str(args.ignore))
            except OSError as exc:
                log.error("Cannot read ignore file %s: %s", args.ignore, exc)
                return 1, None
        if sups and osv_results:
            suppressed = apply_suppressions(osv_results, sups, os_info)

    report = build_report(all_pkgs, osv_results, diff_summary, hostname=hostname,
                          removed=removed, os_info=os_info, queried=queried)
    report.scan_target = scan_target
    report.eol = eol
    report.license_violations = license_violations
    report.suppressed = suppressed
    render_summary_table(report)

    output_dir: Path = args.output_dir
    dest = args.output or output_dir / f"sbom_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    write_json_report(report, dest)

    if args.cyclonedx:
        write_cyclonedx(report, args.cyclonedx)
    if args.spdx:
        write_json_document(to_spdx(report), args.spdx, "SPDX 2.3 SBOM")
    if args.sarif:
        write_json_document(to_sarif(report), args.sarif, "SARIF report")

    if args.report:
        html_path, pdf_path = write_enterprise_reports(report, output_dir)
        lines = f"[bold green]Reports generated:[/bold green]\n  HTML: {html_path}"
        if pdf_path:
            lines += f"\n  PDF:  {pdf_path}"
        console.print(Panel(lines, border_style="green", expand=False))

    if args.webhook_url:
        await send_webhook_alert(args.webhook_url, report)
    if args.server_url:
        await push_to_server(args.server_url, report.to_dict(), args.api_key)

    return exit_code_for(report, args.fail_on), report


def merge_results(base: list[VulnResult], extra: list[VulnResult]) -> list[VulnResult]:
    """Attach heuristic findings to the matching package result instead of duplicating the package."""
    index = {(r.package.ecosystem, r.package.name, r.package.version): r for r in base}
    for r in extra:
        key = (r.package.ecosystem, r.package.name, r.package.version)
        if key in index:
            index[key].vulns.extend(r.vulns)
        else:
            base.append(r)
            index[key] = r
    return base


async def _async_main(args: argparse.Namespace) -> int:
    if args.push_file:
        if not args.server_url:
            log.error("--push-file requires --server-url (or OPENBOM_SERVER_URL)")
            return 1
        try:
            payload = json.loads(args.push_file.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            log.error("Cannot read %s: %s", args.push_file, exc)
            return 1
        return 0 if await push_to_server(args.server_url, payload, args.api_key) else 1
    rc, _ = await run_scan(args)
    return rc


# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------

MENU_ITEMS: list[tuple[str, str]] = [
    ("1", "Quick SBOM inventory (offline)"),
    ("2", "Full threat hunt — OSV + EPSS + KEV + diff + heuristics"),
    ("3", "Full threat hunt + HTML/PDF report + CycloneDX"),
    ("4", "Deep heuristic IOC + typosquat scan of ALL Python/NPM packages"),
    ("p", "Scan a project / repository directory (lockfiles, JARs, venvs)"),
    ("i", "Scan a container image"),
    ("s", "Analyse an existing SBOM file (CycloneDX / SPDX)"),
    ("5", "View latest scan result"),
    ("6", "Push latest scan to OpenBOM server"),
    ("7", "Export latest scan as CycloneDX SBOM"),
    ("8", "Show cache / baseline status"),
    ("9", "Clear caches & diff baseline"),
    ("0", "Exit"),
]


def _render_menu() -> None:
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan", justify="right")
    table.add_column()
    for key, label in MENU_ITEMS:
        table.add_row(key, label)
    console.print(Panel(table, title=f"[bold]OpenBOM Agent v{AGENT_VERSION}[/bold]",
                        subtitle=f"state: {state_dir()}", border_style="bright_blue", expand=False))


def _cache_status(output_dir: Path = DEFAULT_OUTPUT_DIR) -> None:
    table = Table(title="OpenBOM state", show_header=True, header_style="bold")
    table.add_column("Item")
    table.add_column("Path")
    table.add_column("Status")
    for label, path, ttl in [("OSV cache", osv_cache_path(), CACHE_TTL_SECONDS),
                             ("KEV cache", kev_cache_path(), KEV_CACHE_TTL),
                             ("Diff baseline", diff_state_path(), None)]:
        if path.exists():
            age = time.time() - path.stat().st_mtime
            stale = ttl is not None and age > ttl
            status = f"{path.stat().st_size // 1024} KiB, {age / 3600:.1f}h old" + (" (stale)" if stale else "")
        else:
            status = "missing"
        table.add_row(label, str(path), status)
    latest = latest_scan_file(output_dir)
    table.add_row("Latest scan", str(latest) if latest else "-", "present" if latest else f"none in {output_dir}")
    console.print(table)


def clear_state() -> list[Path]:
    removed: list[Path] = []
    for path in (osv_cache_path(), kev_cache_path(), diff_state_path()):
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
            removed.append(path)
    return removed


def _menu_scan_args(flags: list[str], base: argparse.Namespace) -> argparse.Namespace:
    args = parse_args(flags)
    args.server_url, args.api_key, args.webhook_url = base.server_url, base.api_key, base.webhook_url
    args.output_dir = base.output_dir
    return args


def interactive_menu(base: argparse.Namespace) -> int:
    from rich.prompt import Confirm, Prompt

    last_rc = 0
    choices = [k for k, _ in MENU_ITEMS]
    while True:
        _render_menu()
        choice = Prompt.ask("Select an option", choices=choices, default="2", console=console)
        try:
            if choice == "0":
                return last_rc
            if choice in ("p", "i", "s"):
                prompt_label = {"p": "Directory to scan", "i": "Image reference (e.g. alpine:3.19)",
                                "s": "SBOM file (CycloneDX/SPDX JSON)"}[choice]
                default = {"p": ".", "i": "", "s": str(latest_scan_file(base.output_dir) or "")}[choice]
                value = Prompt.ask(prompt_label, default=default or None, console=console)
                if not value:
                    continue
                flag = {"p": "--path", "i": "--image", "s": "--sbom"}[choice]
                args = _menu_scan_args(["--check-osv", "--diff", flag, value], base)
                last_rc, _ = asyncio.run(run_scan(args))
            elif choice in ("1", "2", "3", "4"):
                flags = {
                    "1": ["--scan-only", "--heuristics", "off"],
                    "2": ["--check-osv", "--diff"],
                    "3": ["--check-osv", "--diff", "--report",
                          "--cyclonedx", str(base.output_dir / f"cyclonedx_{datetime.now():%Y%m%d_%H%M%S}.json")],
                    "4": ["--scan-only", "--heuristics", "all", "--ecosystems", "pypi,npm"],
                }[choice]
                args = _menu_scan_args(flags, base)
                if choice in ("2", "3") and args.server_url is None and Confirm.ask(
                        "Push results to an OpenBOM server as well?", default=False, console=console):
                    args.server_url = Prompt.ask("Server URL", default="http://127.0.0.1:8000", console=console)
                    base.server_url = args.server_url
                last_rc, _ = asyncio.run(run_scan(args))
            elif choice in ("5", "6", "7"):
                latest = latest_scan_file(base.output_dir)
                if latest is None:
                    console.print(f"[yellow]No scan found in {base.output_dir} — run option 1-4 first.[/yellow]")
                    continue
                console.print(f"[dim]Using {latest}[/dim]")
                if choice == "5":
                    render_summary_table(load_report(latest))
                elif choice == "6":
                    url = base.server_url or Prompt.ask("Server URL", default="http://127.0.0.1:8000", console=console)
                    key = base.api_key or Prompt.ask("API key (blank for none)", default="", password=True,
                                                     console=console) or None
                    base.server_url, base.api_key = url, key
                    ok = asyncio.run(push_to_server(url, json.loads(latest.read_text()), key))
                    console.print("[green]Pushed.[/green]" if ok else "[red]Push failed — see log above.[/red]")
                else:
                    dest = latest.with_name(latest.stem.replace("sbom_", "cyclonedx_") + ".json")
                    write_cyclonedx(load_report(latest), dest)
                    console.print(f"[green]CycloneDX written to {dest}[/green]")
            elif choice == "8":
                _cache_status(base.output_dir)
            elif choice == "9":
                if Confirm.ask("Delete OSV/KEV caches and the diff baseline?", default=False, console=console):
                    removed = clear_state()
                    console.print(f"[green]Removed {len(removed)} file(s).[/green]")
        except KeyboardInterrupt:
            console.print("\n[yellow]Cancelled — back to menu.[/yellow]")
        except SystemExit:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(args.verbose)
    try:
        if has_custom_target(args) and not (args.scan_only or args.check_osv or args.push_file):
            args.check_osv = True
        if args.menu or not (args.scan_only or args.check_osv or args.push_file):
            if not args.menu and not sys.stdin.isatty():
                parser.error("one of --scan-only, --check-osv, --push-file or --menu is required")
            return interactive_menu(args)
        return asyncio.run(_async_main(args))
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Interrupted by user[/bold yellow]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
