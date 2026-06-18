"""Pydantic schemas for API request/response bodies."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class TraceEventOut(ORMModel):
    id: int
    seq: int
    rel_ts: float
    category: str
    name: str
    args: dict
    ret: str
    detail: str
    severity: str
    suspicious: bool


class IOCOut(ORMModel):
    id: int
    ioc_type: str
    value: str
    context: str
    count: int


class RuleOut(ORMModel):
    id: int
    kind: str
    name: str
    path: str
    content: str
    created_at: datetime


class MemoryDumpOut(ORMModel):
    id: int
    reason: str
    address: str
    size: int
    path: str
    sha256: str
    created_at: datetime


class ReportOut(ORMModel):
    id: int
    json_path: str
    pdf_path: str
    created_at: datetime


class SampleSummary(ORMModel):
    id: str
    filename: str
    size: int
    md5: str
    sha1: str
    sha256: str
    file_format: str
    arch: str
    bits: int
    platform: str
    status: str
    threat_score: int
    verdict: str
    tags: list
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


class SampleDetail(SampleSummary):
    ssdeep: str
    error: str
    iocs: list[IOCOut] = []
    rules: list[RuleOut] = []
    dumps: list[MemoryDumpOut] = []
    report: ReportOut | None = None


class SampleListResponse(BaseModel):
    total: int
    items: list[SampleSummary]


class TraceListResponse(BaseModel):
    total: int
    items: list[TraceEventOut]


class SubmitResponse(BaseModel):
    id: str
    status: str
    sha256: str
    message: str = "Sample queued for analysis."


class HealthResponse(BaseModel):
    status: str
    version: str
    emulation_enabled: bool
    components: dict[str, str]
