"""Cross-sample IOC search."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import IOC
from ..schemas import IOCOut
from ..security import require_api_key

router = APIRouter(prefix="/iocs", tags=["iocs"])


@router.get("", response_model=list[IOCOut], dependencies=[Depends(require_api_key)])
def search_iocs(
    db: Session = Depends(get_db),
    ioc_type: str | None = Query(None, alias="type"),
    q: str | None = Query(None),
    sample_id: str | None = Query(None),
    limit: int = Query(200, ge=1, le=2000),
) -> list[IOCOut]:
    stmt = select(IOC)
    if ioc_type:
        stmt = stmt.where(IOC.ioc_type == ioc_type)
    if sample_id:
        stmt = stmt.where(IOC.sample_id == sample_id)
    if q:
        stmt = stmt.where(IOC.value.ilike(f"%{q}%"))
    rows = db.scalars(stmt.order_by(IOC.count.desc()).limit(limit)).all()
    return [IOCOut.model_validate(r) for r in rows]


@router.get("/stats", dependencies=[Depends(require_api_key)])
def ioc_stats(db: Session = Depends(get_db)) -> dict:
    rows = db.execute(
        select(IOC.ioc_type, func.count(IOC.id)).group_by(IOC.ioc_type)
    ).all()
    return {ioc_type: count for ioc_type, count in rows}
