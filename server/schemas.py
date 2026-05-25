"""Pydantic schemas for request validation and response serialization.

These mirror the JSON output of the OpenBOM Agent v4.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Inbound — agent payload (POST /api/v1/ingest)
# ---------------------------------------------------------------------------


class PackageIn(BaseModel):
    name: str
    version: str
    ecosystem: str
    diff_label: str | None = None


class VulnDetailIn(BaseModel):
    vuln_id: str
    severity: str = "UNKNOWN"
    summary: str | None = None
    fixed_version: str | None = None
    recommendation: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    is_kev: bool = False
    kev_description: str | None = None
    poc_links: list[str] = Field(default_factory=list)


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
    total_critical: int = 0
    total_high: int = 0
    total_medium: int = 0
    total_low: int = 0
    total_unknown: int = 0


class AgentPayload(BaseModel):
    """Root payload from the OpenBOM Agent."""

    hostname: str
    scan_ts: str
    total_packages: int = 0
    packages: list[PackageIn] = Field(default_factory=list)
    osv_summary: OsvSummaryIn | None = None
    osv_vulnerabilities: list[VulnFindingIn] | None = None
    diff_summary: DiffSummaryIn | None = None


# ---------------------------------------------------------------------------
# Outbound — API responses
# ---------------------------------------------------------------------------


class PackageOut(BaseModel):
    id: int
    name: str
    version: str
    ecosystem: str

    model_config = {"from_attributes": True}


class VulnerabilityOut(BaseModel):
    id: int
    vuln_id: str
    severity: str
    summary: str | None = None
    fixed_version: str | None = None
    recommendation: str | None = None
    epss_score: float | None = None
    is_kev: bool = False
    kev_description: str | None = None
    is_heuristic: bool = False
    poc_links: str | None = None
    first_seen: datetime | None = None

    model_config = {"from_attributes": True}


class AssetOut(BaseModel):
    id: int
    hostname: str
    last_seen: datetime

    model_config = {"from_attributes": True}


class IngestResponse(BaseModel):
    status: str
    hostname: str
    packages_processed: int
    vulnerabilities_linked: int


class ThreatAssetOut(BaseModel):
    """An asset with its threatening vulns + affected packages."""

    asset: AssetOut
    findings: list[ThreatFindingOut]


class ThreatFindingOut(BaseModel):
    vulnerability: VulnerabilityOut
    affected_packages: list[PackageOut]

    model_config = {"from_attributes": True}


# Rebuild forward refs after ThreatFindingOut is defined
ThreatAssetOut.model_rebuild()
