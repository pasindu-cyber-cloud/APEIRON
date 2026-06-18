"""Health and dashboard statistics."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import __version__
from ..config import settings
from ..database import get_db
from ..models import IOC, GeneratedRule, MemoryDump, Sample
from ..schemas import HealthResponse

router = APIRouter(tags=["meta"])


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    components = {"api": "ok"}
    try:
        import redis

        client = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=1)
        client.ping()
        components["redis"] = "ok"
    except Exception as exc:
        components["redis"] = f"error: {exc}"
    try:
        import qiling  # type: ignore  # noqa: F401

        components["qiling"] = "available"
    except Exception:
        components["qiling"] = "unavailable"
    return HealthResponse(
        status="ok",
        version=__version__,
        emulation_enabled=settings.enable_emulation,
        components=components,
    )


@router.get("/stats")
def stats(db: Session = Depends(get_db)) -> dict:
    by_status = dict(
        db.execute(select(Sample.status, func.count(Sample.id)).group_by(Sample.status)).all()
    )
    by_verdict = dict(
        db.execute(select(Sample.verdict, func.count(Sample.id)).group_by(Sample.verdict)).all()
    )
    return {
        "samples_total": db.scalar(select(func.count(Sample.id))) or 0,
        "samples_by_status": by_status,
        "samples_by_verdict": by_verdict,
        "iocs_total": db.scalar(select(func.count(IOC.id))) or 0,
        "rules_total": db.scalar(select(func.count(GeneratedRule.id))) or 0,
        "dumps_total": db.scalar(select(func.count(MemoryDump.id))) or 0,
    }
