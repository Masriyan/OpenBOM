"""SQLAlchemy ORM models for the OpenBOM backend.

Relationships:
    Asset  <-M:N->  Package  <-M:N->  Vulnerability

Association tables carry per-scan context (scan timestamp, diff label)
so the same Package row can be linked to many Assets across scans.
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
    Column("scan_ts", DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)),
)

package_vulnerability = Table(
    "package_vulnerability",
    Base.metadata,
    Column("package_id", Integer, ForeignKey("packages.id", ondelete="CASCADE"), primary_key=True),
    Column("vulnerability_id", Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), primary_key=True),
)


# ---------------------------------------------------------------------------
# Core models
# ---------------------------------------------------------------------------


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    hostname: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc),
    )
    last_scan_summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    packages: Mapped[list[Package]] = relationship(
        "Package", secondary=asset_package, back_populates="assets", lazy="selectin",
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
    version: Mapped[str] = mapped_column(String(128), nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    assets: Mapped[list[Asset]] = relationship(
        "Asset", secondary=asset_package, back_populates="packages", lazy="selectin",
    )
    vulnerabilities: Mapped[list[Vulnerability]] = relationship(
        "Vulnerability", secondary=package_vulnerability, back_populates="packages", lazy="selectin",
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
    vuln_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="UNKNOWN")
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    fixed_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    kev_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_heuristic: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    poc_links: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc),
    )

    packages: Mapped[list[Package]] = relationship(
        "Package", secondary=package_vulnerability, back_populates="vulnerabilities", lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<Vulnerability {self.vuln_id}>"
