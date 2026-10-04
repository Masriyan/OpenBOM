"""SQLAlchemy ORM models for the OpenBOM backend.

Relationships:
    Asset  <-M:N->  Package  <-M:N->  Vulnerability
    Asset  <-1:N->  ScanRecord

asset_package is a snapshot: each ingest replaces the asset's links, so
uninstalled/upgraded packages stop counting against the host.
package_vulnerability carries the per-package fix (the same CVE can have
different fixed versions in different ecosystems).

Relationships use lazy="raise": all reads go through explicit queries
(see server/queries.py) instead of implicit cascading loads.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(dt: datetime | None) -> datetime | None:
    """SQLite drops tzinfo on DateTime(timezone=True) — re-attach UTC so APIs emit "+00:00"."""
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Association tables
# ---------------------------------------------------------------------------

asset_package = Table(
    "asset_package",
    Base.metadata,
    Column("asset_id", Integer, ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),
    Column("package_id", Integer, ForeignKey("packages.id", ondelete="CASCADE"), primary_key=True),
    Column("diff_label", String(20), nullable=True),
    Column("scan_ts", DateTime(timezone=True), nullable=False, default=utcnow),
    Index("ix_asset_package_package", "package_id"),
)

package_vulnerability = Table(
    "package_vulnerability",
    Base.metadata,
    Column("package_id", Integer, ForeignKey("packages.id", ondelete="CASCADE"), primary_key=True),
    Column("vulnerability_id", Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), primary_key=True),
    Column("fixed_version", String(255), nullable=True),
    Column("recommendation", Text, nullable=True),
    Index("ix_package_vulnerability_vuln", "vulnerability_id"),
)


# ---------------------------------------------------------------------------
# Core models
# ---------------------------------------------------------------------------


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    hostname: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    os_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    agent_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_scan_ts: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_scan_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    target_type: Mapped[str | None] = mapped_column(String(16), nullable=True)  # host | image | rootfs | path | sbom
    target_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    eol_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    license_violations_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    packages: Mapped[list[Package]] = relationship(
        "Package", secondary=asset_package, back_populates="assets", lazy="raise", passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"<Asset {self.hostname}>"


class Package(Base):
    __tablename__ = "packages"
    __table_args__ = (
        UniqueConstraint("name", "version", "ecosystem", name="uq_package_identity"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(255), nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    purl: Mapped[str | None] = mapped_column(String(512), nullable=True)
    license: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    osv_ecosystem: Mapped[str | None] = mapped_column(String(64), nullable=True)
    osv_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    osv_version: Mapped[str | None] = mapped_column(String(255), nullable=True)

    assets: Mapped[list[Asset]] = relationship(
        "Asset", secondary=asset_package, back_populates="packages", lazy="raise", passive_deletes=True,
    )
    vulnerabilities: Mapped[list[Vulnerability]] = relationship(
        "Vulnerability", secondary=package_vulnerability, back_populates="packages", lazy="raise",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"<Package {self.ecosystem}:{self.name}=={self.version}>"


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        Index("ix_vuln_kev", "is_kev"),
        Index("ix_vuln_heuristic", "is_heuristic"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vuln_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="UNKNOWN")
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Last-seen fix/recommendation; the authoritative per-package values live on package_vulnerability
    fixed_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    kev_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_heuristic: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_malicious: Mapped[bool | None] = mapped_column(Boolean, nullable=True, default=False)
    poc_links: Mapped[str | None] = mapped_column(Text, nullable=True)
    cves: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_updated: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=utcnow)

    packages: Mapped[list[Package]] = relationship(
        "Package", secondary=package_vulnerability, back_populates="vulnerabilities", lazy="raise",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"<Vulnerability {self.vuln_id}>"


class ScanRecord(Base):
    """One row per ingest — powers per-asset history and trend views."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[int] = mapped_column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    scan_ts: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    agent_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    total_packages: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    vulnerable_packages: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    critical: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    medium: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    low: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unknown: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    kev_hits: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    heuristic_hits: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    malicious_hits: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    license_violations: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    source: Mapped[str | None] = mapped_column(String(32), nullable=True)  # agent | sbom-upload | reanalysis
    diff_new: Mapped[int | None] = mapped_column(Integer, nullable=True)
    diff_removed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    osv_checked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


TRIAGE_STATES = ("in_triage", "exploitable", "not_affected", "false_positive", "resolved")
SUPPRESSED_STATES = ("not_affected", "false_positive")


class Triage(Base):
    """Analyst decision for a vulnerability — fleet-wide (asset_id NULL) or for one asset.

    not_affected / false_positive suppress the finding everywhere it applies (VEX semantics).
    """

    __tablename__ = "triage"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True, nullable=False)
    asset_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("assets.id", ondelete="CASCADE"), index=True, nullable=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    justification: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    author: Mapped[str | None] = mapped_column(String(128), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
