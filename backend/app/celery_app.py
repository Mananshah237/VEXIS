"""Celery application instance for VEXIS background scan tasks."""
from __future__ import annotations
from celery import Celery
from celery.signals import worker_init
from app.config import settings
import structlog


@worker_init.connect
def validate_worker_settings(**kwargs):
    structlog.get_logger().info("worker.startup", env=settings.env)
    try:
        settings.validate_secrets()
    except RuntimeError as exc:
        # Celery signals swallow ordinary exceptions; SystemExit must stop startup.
        raise SystemExit(str(exc)) from exc

# Use the same Redis URL as the rest of the app
_REDIS_URL = settings.redis_url

celery_app = Celery(
    "vexis",
    broker=_REDIS_URL,
    backend=_REDIS_URL,
    include=["app.tasks.scan_task"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    worker_prefetch_multiplier=1,  # one scan at a time per worker
)
