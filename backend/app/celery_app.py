"""Celery application instance for VEXIS background scan tasks."""
from __future__ import annotations
import os
from celery import Celery

# Use the same Redis URL as the rest of the app
_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

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
