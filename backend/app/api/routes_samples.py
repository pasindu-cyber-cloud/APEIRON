"""Sample submission, listing, detail, traces, dumps and reports."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, selectinload

from ..analyzer.static_analysis import detect_format
from ..config import settings
from ..database import get_db
from ..logging_config import get_logger
from ..models import MemoryDump, Sample, SampleStatus, TraceEvent
from ..queue import enqueue_analysis
from ..schemas import (
    SampleDetail,
    SampleListResponse,
    SampleSummary,
    SubmitResponse,
    TraceEventOut,
    TraceListResponse,
)
from ..security import require_api_key
from ..storage import compute_hashes, store_sample

logger = get_logger("apeiron.api.samples")
router = APIRouter(prefix="/samples", tags=["samples"])


@router.post(
    "",
    response_model=SubmitResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_api_key)],
)
async def submit_sample(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> SubmitResponse:
    data = await file.read()
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Empty file.")
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"File exceeds limit of {settings.max_upload_bytes} bytes.",
        )

    fmt = detect_format(data)
    if fmt not in ("PE", "ELF"):
        raise HTTPException(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            "Unsupported file: only PE (MZ) and ELF binaries are accepted.",
        )

    hashes = compute_hashes(data)
    sample = Sample(
        filename=file.filename or "sample.bin",
        stored_path="",
        size=len(data),
        md5=hashes["md5"],
        sha1=hashes["sha1"],
        sha256=hashes["sha256"],
        ssdeep=hashes.get("ssdeep", ""),
        file_format=fmt,
        status=SampleStatus.QUEUED,
    )
    db.add(sample)
    db.flush()  # assign id

    dest = store_sample(sample.id, sample.filename, data)
    sample.stored_path = str(dest)
    db.commit()

    try:
        task_id = enqueue_analysis(sample.id)
        logger.info("queued sample=%s task=%s sha256=%s", sample.id, task_id, sample.sha256)
    except Exception as exc:
        logger.error("failed to enqueue sample=%s: %s", sample.id, exc)
        sample.status = SampleStatus.FAILED
        sample.error = f"enqueue failed: {exc}"
        db.commit()
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "Analysis queue unavailable."
        ) from exc

    return SubmitResponse(id=sample.id, status=sample.status, sha256=sample.sha256)


@router.get("", response_model=SampleListResponse, dependencies=[Depends(require_api_key)])
def list_samples(
    db: Session = Depends(get_db),
    q: str | None = Query(None, description="Search filename or hash"),
    status_filter: str | None = Query(None, alias="status"),
    tag: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> SampleListResponse:
    stmt = select(Sample)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            or_(
                Sample.filename.ilike(like),
                Sample.sha256.ilike(like),
                Sample.md5.ilike(like),
                Sample.sha1.ilike(like),
            )
        )
    if status_filter:
        stmt = stmt.where(Sample.status == status_filter)

    rows = db.scalars(stmt.order_by(Sample.created_at.desc())).all()
    if tag:
        rows = [r for r in rows if tag in (r.tags or [])]
    total = len(rows)
    page = rows[offset : offset + limit]
    return SampleListResponse(
        total=total,
        items=[SampleSummary.model_validate(r) for r in page],
    )


def _get_sample_or_404(db: Session, sample_id: str) -> Sample:
    stmt = (
        select(Sample)
        .where(Sample.id == sample_id)
        .options(
            selectinload(Sample.iocs),
            selectinload(Sample.rules),
            selectinload(Sample.dumps),
            selectinload(Sample.report),
        )
    )
    sample = db.scalars(stmt).first()
    if sample is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Sample not found.")
    return sample


@router.get("/{sample_id}", response_model=SampleDetail, dependencies=[Depends(require_api_key)])
def get_sample(sample_id: str, db: Session = Depends(get_db)) -> SampleDetail:
    return SampleDetail.model_validate(_get_sample_or_404(db, sample_id))


@router.delete("/{sample_id}", dependencies=[Depends(require_api_key)])
def delete_sample(sample_id: str, db: Session = Depends(get_db)) -> dict:
    sample = db.get(Sample, sample_id)
    if sample is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Sample not found.")
    db.delete(sample)
    db.commit()
    return {"deleted": sample_id}


@router.get(
    "/{sample_id}/trace",
    response_model=TraceListResponse,
    dependencies=[Depends(require_api_key)],
)
def get_traces(
    sample_id: str,
    db: Session = Depends(get_db),
    category: str | None = Query(None),
    suspicious: bool | None = Query(None),
    q: str | None = Query(None),
    limit: int = Query(500, ge=1, le=5000),
    offset: int = Query(0, ge=0),
) -> TraceListResponse:
    stmt = select(TraceEvent).where(TraceEvent.sample_id == sample_id)
    if category:
        stmt = stmt.where(TraceEvent.category == category)
    if suspicious is not None:
        stmt = stmt.where(TraceEvent.suspicious == suspicious)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(TraceEvent.name.ilike(like), TraceEvent.detail.ilike(like)))
    all_rows = db.scalars(stmt.order_by(TraceEvent.seq.asc())).all()
    total = len(all_rows)
    page = all_rows[offset : offset + limit]
    return TraceListResponse(
        total=total, items=[TraceEventOut.model_validate(r) for r in page]
    )


@router.get("/{sample_id}/report.json", dependencies=[Depends(require_api_key)])
def get_report_json(sample_id: str, db: Session = Depends(get_db)) -> FileResponse:
    sample = _get_sample_or_404(db, sample_id)
    if not sample.report or not sample.report.json_path:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not available yet.")
    path = Path(sample.report.json_path)
    if not path.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report file missing.")
    return FileResponse(path, media_type="application/json", filename=f"{sample_id}.json")


@router.get("/{sample_id}/report.pdf", dependencies=[Depends(require_api_key)])
def get_report_pdf(sample_id: str, db: Session = Depends(get_db)) -> FileResponse:
    sample = _get_sample_or_404(db, sample_id)
    if not sample.report or not sample.report.pdf_path:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "PDF report not available.")
    path = Path(sample.report.pdf_path)
    if not path.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "PDF file missing.")
    return FileResponse(path, media_type="application/pdf", filename=f"{sample_id}.pdf")


@router.get("/{sample_id}/dumps/{dump_id}", dependencies=[Depends(require_api_key)])
def download_dump(sample_id: str, dump_id: int, db: Session = Depends(get_db)) -> FileResponse:
    dump = db.get(MemoryDump, dump_id)
    if dump is None or dump.sample_id != sample_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Dump not found.")
    path = Path(dump.path)
    if not path.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Dump file missing.")
    return FileResponse(
        path, media_type="application/octet-stream", filename=path.name
    )
