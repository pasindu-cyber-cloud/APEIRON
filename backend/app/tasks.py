"""Celery tasks."""
from __future__ import annotations

from .analyzer import engine
from .logging_config import get_logger
from .worker import celery_app

logger = get_logger("apeiron.tasks")


@celery_app.task(
    name="app.tasks.analyze_sample",
    bind=True,
    max_retries=0,
    acks_late=True,
)
def analyze_sample(self, sample_id: str) -> dict:
    """Run the full analysis pipeline for a queued sample."""
    logger.info("starting analysis task for sample=%s", sample_id)
    return engine.run_analysis(sample_id)
