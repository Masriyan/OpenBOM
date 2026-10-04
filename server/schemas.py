"""Pydantic schemas for request validation and response serialization.

Inbound models mirror the JSON written by the OpenBOM Agent (v4 and v5);
unknown fields are ignored so newer agents can talk to older servers.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from server.models import as_utc

HEURISTIC_IDS = {"MALICIOUS_HEURISTIC", "TYPOSQUAT_SUSPECT"}
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


# ---------------------------------------------------------------------------
# Inbound — agent payload (POST /api/v1/ingest)
# ---------------------------------------------------------------------------


class PackageIn(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    version: str = Field(min_length=1, max_length=255)
    ecosystem: str = Field(min_length=1, max_length=32)
    diff_label: str | None = Field(default=None, max_length=20)
    purl: str | None = Field(default=None, max_length=512)
    license: str | None = None
    osv_ecosystem: str | None = Field(default=None, max_length=64)
    osv_name: str | None = Field(default=None, max_length=255)
    osv_version: str | None = Field(default=None, max_length=255)
    location: str | None = Field(default=None, max_length=4096)

    @field_validator("license")
    @classmethod
    def _clip_license(cls, v: str | None) -> str | None:
        return v[:255] if v else v


class VulnDetailIn(BaseModel):
    vuln_id: str = Field(min_length=1, max_length=200)
    severity: str = "UNKNOWN"
    summary: str | None = None
    fixed_version: str | None = Field(default=None, max_length=255)
    recommendation: str | None = None
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    epss_score: float | None = Field(default=None, ge=0, le=1)
    epss_percentile: float | None = Field(default=None, ge=0, le=1)
    is_kev: bool = False
    kev_description: str | None = None
    is_heuristic: bool = False
    is_malicious: bool = False
    poc_links: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)

    @field_validator("severity", mode="before")
    @classmethod
    def _norm_severity(cls, v: Any) -> str:
        s = str(v or "UNKNOWN").upper()
        return {"MODERATE": "MEDIUM", "IMPORTANT": "HIGH"}.get(s, s if s in SEVERITIES else "UNKNOWN")

    @property
    def heuristic(self) -> bool:
        return self.is_heuristic or self.vuln_id in HEURISTIC_IDS

    @property
    def malicious(self) -> bool:
        return self.is_malicious or self.vuln_id.startswith("MAL-")


class VulnFindingIn(BaseModel):
    package: PackageIn
    max_severity: str = "UNKNOWN"
    vulns: list[VulnDetailIn] = Field(default_factory=list)


class DiffSummaryIn(BaseModel):
    new: int = 0
    removed: int = 0
    upgraded: int = 0
    downgraded: int = 0
    unchanged: int = 0


class OsvSummaryIn(BaseModel):
    queried: int = 0
    vulnerable: int = 0
    kev_hits: int = 0
    poc_count: int = 0
    heuristic_hits: int = 0
    malicious_hits: int = 0
    total_critical: int = 0
    total_high: int = 0
    total_medium: int = 0
    total_low: int = 0
    total_unknown: int = 0


class OsInfoIn(BaseModel):
    id: str = ""
    version_id: str = ""
    pretty_name: str = ""
    osv_ecosystem: str = ""


class AgentPayload(BaseModel):
    """Root payload from the OpenBOM Agent."""

    hostname: str = Field(min_length=1, max_length=255)
    scan_ts: str
    agent_version: str | None = Field(default=None, max_length=32)
    os: OsInfoIn | None = None
    total_packages: int = 0
    packages: list[PackageIn] = Field(default_factory=list)
    osv_summary: OsvSummaryIn | None = None
    osv_vulnerabilities: list[VulnFindingIn] | None = None
    diff_summary: DiffSummaryIn | None = None
    removed_packages: list[str] | None = None
    scan_target: dict[str, str] | None = None
    eol: list[dict[str, Any]] | None = None
    license_violations: list[dict[str, str]] | None = None
    suppressed: list[dict[str, str]] | None = None

    @field_validator("hostname")
    @classmethod
    def _strip_hostname(cls, v: str) -> str:
        v = v.strip()
        if not v or "/" in v:
            raise ValueError("hostname must be non-empty and must not contain '/'")
        return v


# ---------------------------------------------------------------------------
# Outbound — API responses
# ---------------------------------------------------------------------------


class PackageOut(BaseModel):
    id: int
    name: str
    version: str
    ecosystem: str
    license: str | None = None
    purl: str | None = None
    # Where it was found on the asset (path/venv/lockfile); only set in per-asset views
    location: str | None = None

    model_config = ConfigDict(from_attributes=True)


class AffectedPackageOut(PackageOut):
    fixed_version: str | None = None
    recommendation: str | None = None


class HostLocationOut(BaseModel):
    hostname: str
    location: str | None = None


class OccurrenceOut(BaseModel):
    """One (asset, package) exposure of a vulnerability — what the vulnerability list shows inline."""
    hostname: str
    name: str
    version: str
    ecosystem: str
    fixed_version: str | None = None
    location: str | None = None


class VulnerabilityOut(BaseModel):
    id: int
    vuln_id: str
    severity: str
    summary: str | None = None
    fixed_version: str | None = None
    recommendation: str | None = None
    cvss_score: float | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    is_kev: bool = False
    kev_description: str | None = None
    is_heuristic: bool = False
    is_malicious: bool = False
    poc_links: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    triage_state: str | None = None

    model_config = ConfigDict(from_attributes=True)

    _utc = field_validator("first_seen")(classmethod(lambda cls, v: as_utc(v)))
    _bool = field_validator("is_malicious", mode="before")(classmethod(lambda cls, v: bool(v)))

    @field_validator("poc_links", "cves", mode="before")
    @classmethod
    def _json_list(cls, v: Any) -> list[str]:
        if v is None or v == "":
            return []
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
            except json.JSONDecodeError:
                return [v]
            return [str(x) for x in parsed] if isinstance(parsed, list) else [str(parsed)]
        return list(v)


class AssetOut(BaseModel):
    id: int
    hostname: str
    last_seen: datetime
    first_seen: datetime | None = None
    ip_address: str | None = None
    os_name: str | None = None
    agent_version: str | None = None
    target_type: str | None = None
    target_ref: str | None = None
    eol: list[dict[str, Any]] = Field(default_factory=list, validation_alias="eol_json")

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    @field_validator("eol", mode="before")
    @classmethod
    def _eol(cls, v: Any) -> list[dict[str, Any]]:
        if not v:
            return []
        if isinstance(v, str):
            try:
                v = json.loads(v)
            except json.JSONDecodeError:
                return []
        return v if isinstance(v, list) else []

    _utc = field_validator("last_seen", "first_seen")(classmethod(lambda cls, v: as_utc(v)))


class AssetStatsOut(AssetOut):
    package_count: int = 0
    vulnerability_count: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)
    kev_count: int = 0
    heuristic_count: int = 0
    malicious_count: int = 0
    license_violation_count: int = 0
    max_epss: float | None = None
    risk_score: int = 0
    stale: bool = False


class AssetDetailOut(AssetStatsOut):
    last_scan_summary: dict[str, Any] | None = None
    ecosystem_counts: dict[str, int] = Field(default_factory=dict)
    license_violations: list[dict[str, str]] = Field(default_factory=list)


class AssetVulnerabilityOut(VulnerabilityOut):
    affected_packages: list[AffectedPackageOut] = Field(default_factory=list)


class ScanOut(BaseModel):
    id: int
    received_at: datetime
    scan_ts: datetime | None = None
    agent_version: str | None = None
    total_packages: int
    vulnerable_packages: int
    critical: int
    high: int
    medium: int
    low: int
    unknown: int
    kev_hits: int
    heuristic_hits: int
    malicious_hits: int | None = 0
    license_violations: int | None = 0
    source: str | None = None
    diff_new: int | None = None
    diff_removed: int | None = None
    osv_checked: bool

    model_config = ConfigDict(from_attributes=True)

    _utc = field_validator("received_at", "scan_ts")(classmethod(lambda cls, v: as_utc(v)))


class IngestResponse(BaseModel):
    status: str
    hostname: str
    scan_id: int
    packages_processed: int
    packages_unlinked: int
    vulnerabilities_linked: int


class ThreatFindingOut(BaseModel):
    vulnerability: VulnerabilityOut
    affected_packages: list[AffectedPackageOut]


class ThreatAssetOut(BaseModel):
    """An asset with its threatening vulns + affected packages."""

    asset: AssetOut
    findings: list[ThreatFindingOut]


class PackageHostsOut(BaseModel):
    package: PackageOut
    hosts: list[str]
    locations: list[HostLocationOut] = Field(default_factory=list)
    vulnerability_count: int = 0
    max_severity: str | None = None


class VulnerabilityListOut(VulnerabilityOut):
    affected_assets: int = 0
    affected_packages: int = 0
    occurrences: list[OccurrenceOut] = Field(default_factory=list, description="First few exposures (host/package/path)")


class AffectedAssetOut(BaseModel):
    hostname: str
    package: AffectedPackageOut


class VulnerabilityDetailOut(BaseModel):
    vulnerability: VulnerabilityOut
    affected: list[AffectedAssetOut]


class PruneResponse(BaseModel):
    packages_deleted: int
    vulnerabilities_deleted: int


class TriageIn(BaseModel):
    vuln_id: str = Field(min_length=1, max_length=255)
    hostname: str | None = Field(default=None, description="Limit the decision to one asset; omit for fleet-wide")
    state: str
    justification: str | None = Field(default=None, max_length=64)
    detail: str | None = Field(default=None, max_length=4000)
    author: str | None = Field(default=None, max_length=128)

    @field_validator("state")
    @classmethod
    def _state(cls, v: str) -> str:
        from server.models import TRIAGE_STATES
        if v not in TRIAGE_STATES:
            raise ValueError(f"state must be one of {', '.join(TRIAGE_STATES)}")
        return v


class TriageOut(BaseModel):
    id: int
    vuln_id: str
    hostname: str | None = None
    state: str
    justification: str | None = None
    detail: str | None = None
    author: str | None = None
    updated_at: datetime

    _utc = field_validator("updated_at")(classmethod(lambda cls, v: as_utc(v)))


class LicenseSummaryOut(BaseModel):
    license: str
    packages: int
    assets: int


class LicensePackageOut(BaseModel):
    package: PackageOut
    hosts: list[str]


class EolAssetOut(BaseModel):
    hostname: str
    target_type: str | None = None
    eol: list[dict[str, Any]]


class ReanalyzeResponse(BaseModel):
    assets: int
    packages_checked: int
    vulnerabilities_linked: int
