"""SQLAlchemy ORM models for APEIRON."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> datetime:
    return datetime.now(timezone.utc)


class SampleStatus:
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Sample(Base):
    __tablename__ = "samples"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    filename: Mapped[str] = mapped_column(String(512))
    stored_path: Mapped[str] = mapped_column(String(1024))
    size: Mapped[int] = mapped_column(Integer, default=0)

    md5: Mapped[str] = mapped_column(String(32), index=True, default="")
    sha1: Mapped[str] = mapped_column(String(40), index=True, default="")
    sha256: Mapped[str] = mapped_column(String(64), index=True, default="")
    ssdeep: Mapped[str] = mapped_column(String(256), default="")

    file_format: Mapped[str] = mapped_column(String(32), default="unknown")  # PE / ELF
    arch: Mapped[str] = mapped_column(String(32), default="unknown")
    bits: Mapped[int] = mapped_column(Integer, default=0)
    platform: Mapped[str] = mapped_column(String(32), default="unknown")

    status: Mapped[str] = mapped_column(String(16), default=SampleStatus.QUEUED, index=True)
    threat_score: Mapped[int] = mapped_column(Integer, default=0)
    verdict: Mapped[str] = mapped_column(String(32), default="unknown")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str] = mapped_column(Text, default="")

    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    trace_events: Mapped[list[TraceEvent]] = relationship(
        back_populates="sample", cascade="all, delete-orphan"
    )
    iocs: Mapped[list[IOC]] = relationship(
        back_populates="sample", cascade="all, delete-orphan"
    )
    rules: Mapped[list[GeneratedRule]] = relationship(
        back_populates="sample", cascade="all, delete-orphan"
    )
    dumps: Mapped[list[MemoryDump]] = relationship(
        back_populates="sample", cascade="all, delete-orphan"
    )
    report: Mapped[Report | None] = relationship(
        back_populates="sample", cascade="all, delete-orphan", uselist=False
    )


class TraceEvent(Base):
    __tablename__ = "trace_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sample_id: Mapped[str] = mapped_column(ForeignKey("samples.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer, default=0)
    rel_ts: Mapped[float] = mapped_column(Float, default=0.0)
    category: Mapped[str] = mapped_column(String(24), index=True)  # api/file/registry/network/...
    name: Mapped[str] = mapped_column(String(256))
    args: Mapped[dict] = mapped_column(JSON, default=dict)
    ret: Mapped[str] = mapped_column(String(256), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="info")  # info/low/medium/high
    suspicious: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    sample: Mapped[Sample] = relationship(back_populates="trace_events")


class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sample_id: Mapped[str] = mapped_column(ForeignKey("samples.id"), index=True)
    ioc_type: Mapped[str] = mapped_column(String(32), index=True)  # ip/domain/url/mutex/...
    value: Mapped[str] = mapped_column(String(2048), index=True)
    context: Mapped[str] = mapped_column(Text, default="")
    count: Mapped[int] = mapped_column(Integer, default=1)

    sample: Mapped[Sample] = relationship(back_populates="iocs")


class GeneratedRule(Base):
    __tablename__ = "generated_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sample_id: Mapped[str] = mapped_column(ForeignKey("samples.id"), index=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)  # yara / sigma
    name: Mapped[str] = mapped_column(String(256))
    path: Mapped[str] = mapped_column(String(1024), default="")
    content: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    sample: Mapped[Sample] = relationship(back_populates="rules")


class MemoryDump(Base):
    __tablename__ = "memory_dumps"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sample_id: Mapped[str] = mapped_column(ForeignKey("samples.id"), index=True)
    reason: Mapped[str] = mapped_column(String(256))
    address: Mapped[str] = mapped_column(String(32), default="0x0")
    size: Mapped[int] = mapped_column(Integer, default=0)
    path: Mapped[str] = mapped_column(String(1024), default="")
    sha256: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    sample: Mapped[Sample] = relationship(back_populates="dumps")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sample_id: Mapped[str] = mapped_column(ForeignKey("samples.id"), index=True, unique=True)
    json_path: Mapped[str] = mapped_column(String(1024), default="")
    pdf_path: Mapped[str] = mapped_column(String(1024), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    sample: Mapped[Sample] = relationship(back_populates="report")
