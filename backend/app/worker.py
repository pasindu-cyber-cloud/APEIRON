"""Celery application for asynchronous, concurrent sample analysis."""

from __future__ import annotations

from celery import Celery
from celery.signals import worker_process_init

from .config import settings
from .database import init_db
from .logging_config import configure_logging
from .security import enforce_startup_security

configure_logging(settings.log_level)

celery_app = Celery(
    "apeiron",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    task_default_queue="analysis",
    task_routes={"app.tasks.analyze_sample": {"queue": "analysis"}},
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_track_started=True,
    result_expires=86_400,
    task_time_limit=settings.emulation_timeout + 120,
    task_soft_time_limit=settings.emulation_timeout + 60,
)


@worker_process_init.connect
def _init_worker(**_kwargs) -> None:
    # Each worker process validates security config and gets its own DB engine.
    enforce_startup_security()
    init_db()


# Ensure tasks are registered when the worker imports this module.
from . import tasks  # noqa: E402,F401
