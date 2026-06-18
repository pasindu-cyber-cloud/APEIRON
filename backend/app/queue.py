"""Lightweight Celery producer used by the API to enqueue analysis jobs.

Kept separate from ``app.worker`` so the API process does not import the heavy
analysis stack (Qiling/Unicorn). Tasks are dispatched by name.
"""

from __future__ import annotations

from celery import Celery

from .config import settings

_producer = Celery("apeiron-producer", broker=settings.celery_broker_url)
_producer.conf.task_default_queue = "analysis"

ANALYZE_TASK = "app.tasks.analyze_sample"


def enqueue_analysis(sample_id: str) -> str:
    """Dispatch an analysis job and return the Celery task id."""
    result = _producer.send_task(ANALYZE_TASK, args=[sample_id], queue="analysis")
    return result.id
