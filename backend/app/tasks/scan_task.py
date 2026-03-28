"""Celery task for running VEXIS scans in a worker process."""
from __future__ import annotations
import asyncio
import structlog

from app.celery_app import celery_app

log = structlog.get_logger()


@celery_app.task(name="vexis.run_scan", bind=True, max_retries=0)
def run_scan_task(self, scan_id: str) -> dict:
    """Run a full scan pipeline in a Celery worker process."""
    log.info("celery.scan.start", scan_id=scan_id, task_id=self.request.id)
    try:
        from app.core.orchestrator import _run_scan_impl
        asyncio.run(_run_scan_impl(scan_id))
        log.info("celery.scan.complete", scan_id=scan_id)
        return {"status": "complete", "scan_id": scan_id}
    except Exception as exc:
        log.error("celery.scan.error", scan_id=scan_id, error=str(exc))
        raise
