"""Generated + built-in detection rule endpoints."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import GeneratedRule
from ..schemas import RuleOut
from ..security import require_api_key

router = APIRouter(prefix="/rules", tags=["rules"])


@router.get("", response_model=list[RuleOut], dependencies=[Depends(require_api_key)])
def list_rules(
    db: Session = Depends(get_db),
    kind: str | None = Query(None, description="yara | sigma"),
    sample_id: str | None = Query(None),
) -> list[RuleOut]:
    stmt = select(GeneratedRule)
    if kind:
        stmt = stmt.where(GeneratedRule.kind == kind)
    if sample_id:
        stmt = stmt.where(GeneratedRule.sample_id == sample_id)
    rows = db.scalars(stmt.order_by(GeneratedRule.created_at.desc())).all()
    return [RuleOut.model_validate(r) for r in rows]


@router.get("/builtin", dependencies=[Depends(require_api_key)])
def list_builtin_rules() -> dict:
    base = Path(settings.builtin_rules_dir)
    files = []
    if base.exists():
        for path in sorted(base.glob("*.yar")) + sorted(base.glob("*.yara")):
            files.append({"name": path.name, "size": path.stat().st_size})
    return {"rules_dir": str(base), "files": files}


@router.get("/builtin/{name}", response_class=PlainTextResponse,
            dependencies=[Depends(require_api_key)])
def get_builtin_rule(name: str) -> str:
    base = Path(settings.builtin_rules_dir)
    target = (base / name).resolve()
    # Prevent path traversal.
    if base.resolve() not in target.parents or not target.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found.")
    return target.read_text()


@router.get("/{rule_id}", response_model=RuleOut, dependencies=[Depends(require_api_key)])
def get_rule(rule_id: int, db: Session = Depends(get_db)) -> RuleOut:
    rule = db.get(GeneratedRule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found.")
    return RuleOut.model_validate(rule)


@router.get("/{rule_id}/download", response_class=PlainTextResponse,
            dependencies=[Depends(require_api_key)])
def download_rule(rule_id: int, db: Session = Depends(get_db)) -> PlainTextResponse:
    rule = db.get(GeneratedRule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found.")
    ext = "yar" if rule.kind == "yara" else "yml"
    return PlainTextResponse(
        rule.content,
        headers={"Content-Disposition": f'attachment; filename="{rule.name}.{ext}"'},
    )
