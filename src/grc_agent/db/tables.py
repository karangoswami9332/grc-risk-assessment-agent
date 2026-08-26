"""SQLAlchemy 2.0 table definitions. Separate from Pydantic domain models."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import JSON


class Base(DeclarativeBase):
    pass


class AssessmentRow(Base):
    __tablename__ = "assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    scenario: Mapped[str] = mapped_column(Text, nullable=False)
    environment_notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    assets: Mapped[list[AssetRow]] = relationship(back_populates="assessment", cascade="all, delete-orphan")
    threats: Mapped[list[ThreatRow]] = relationship(back_populates="assessment", cascade="all, delete-orphan")
    vulnerabilities: Mapped[list[VulnerabilityRow]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    controls: Mapped[list[ControlRow]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    risks: Mapped[list[RiskRow]] = relationship(back_populates="assessment", cascade="all, delete-orphan")


class AssetRow(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    criticality: Mapped[str] = mapped_column(String(32), nullable=False)

    assessment: Mapped[AssessmentRow] = relationship(back_populates="assets")


class ThreatRow(Base):
    __tablename__ = "threats"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    asset_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    assessment: Mapped[AssessmentRow] = relationship(back_populates="threats")


class VulnerabilityRow(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    asset_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    assessment: Mapped[AssessmentRow] = relationship(back_populates="vulnerabilities")


class ControlRow(Base):
    __tablename__ = "controls"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    effectiveness: Mapped[str] = mapped_column(String(64), nullable=False)

    assessment: Mapped[AssessmentRow] = relationship(back_populates="controls")


class RiskRow(Base):
    """Likelihood and impact are inputs. Score/rating are stored engine outputs."""

    __tablename__ = "risks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    likelihood: Mapped[int] = mapped_column(Integer, nullable=False)
    impact: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_rating: Mapped[str] = mapped_column(String(32), nullable=False)
    asset_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    threat_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    vulnerability_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    control_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    treatment: Mapped[str | None] = mapped_column(String(32), nullable=True)

    assessment: Mapped[AssessmentRow] = relationship(back_populates="risks")
