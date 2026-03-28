"""MinIO object storage service for code snapshots, artifacts, and reports.

All operations are wrapped in try/except — MinIO unavailability never breaks a scan.
"""
from __future__ import annotations
import io
import json
import os
from typing import Optional

import structlog
from minio import Minio
from minio.error import S3Error

log = structlog.get_logger()

BUCKET_CODE = "code-snapshots"
BUCKET_ARTIFACTS = "scan-artifacts"
BUCKET_REPORTS = "reports"

_client: Optional[Minio] = None


def get_client() -> Optional[Minio]:
    """Get or create the MinIO client singleton."""
    global _client
    if _client is not None:
        return _client
    try:
        endpoint = os.environ.get("MINIO_ENDPOINT", "localhost:9000")
        access_key = os.environ.get("MINIO_ACCESS_KEY", "vexis")
        secret_key = os.environ.get("MINIO_SECRET_KEY", "vexis_dev_password")
        _client = Minio(endpoint, access_key=access_key, secret_key=secret_key, secure=False)
        return _client
    except Exception as e:
        log.warning("minio.client_init_failed", error=str(e))
        return None


async def ensure_buckets() -> None:
    """Create required buckets if they don't exist. Called at startup."""
    client = get_client()
    if not client:
        return
    for bucket in [BUCKET_CODE, BUCKET_ARTIFACTS, BUCKET_REPORTS]:
        try:
            if not client.bucket_exists(bucket):
                client.make_bucket(bucket)
                log.info("minio.bucket_created", bucket=bucket)
        except Exception as e:
            log.warning("minio.bucket_create_failed", bucket=bucket, error=str(e))


async def upload_code_snapshot(scan_id: str, source_code: str, filename: str = "source.py") -> bool:
    """Upload scanned source code to code-snapshots/{scan_id}/source.py"""
    client = get_client()
    if not client:
        return False
    try:
        data = source_code.encode("utf-8")
        client.put_object(
            BUCKET_CODE,
            f"{scan_id}/{filename}",
            io.BytesIO(data),
            length=len(data),
            content_type="text/plain",
        )
        log.debug("minio.code_snapshot_uploaded", scan_id=scan_id, filename=filename)
        return True
    except Exception as e:
        log.warning("minio.upload_failed", scan_id=scan_id, error=str(e))
        return False


async def upload_artifact(scan_id: str, artifact_name: str, data: dict | list) -> bool:
    """Upload a JSON artifact to scan-artifacts/{scan_id}/{artifact_name}.json"""
    client = get_client()
    if not client:
        return False
    try:
        payload = json.dumps(data, default=str).encode("utf-8")
        client.put_object(
            BUCKET_ARTIFACTS,
            f"{scan_id}/{artifact_name}.json",
            io.BytesIO(payload),
            length=len(payload),
            content_type="application/json",
        )
        log.debug("minio.artifact_uploaded", scan_id=scan_id, artifact=artifact_name)
        return True
    except Exception as e:
        log.warning("minio.artifact_upload_failed", scan_id=scan_id, error=str(e))
        return False


def get_signed_url(bucket: str, object_name: str, expires_seconds: int = 3600) -> Optional[str]:
    """Generate a presigned GET URL valid for expires_seconds.

    If MINIO_PUBLIC_ENDPOINT is set, rewrites the internal endpoint in the URL
    so it is accessible from outside Docker (e.g. http://localhost:9000 instead
    of http://minio:9000).
    """
    client = get_client()
    if not client:
        return None
    try:
        from datetime import timedelta
        url = client.presigned_get_object(bucket, object_name, expires=timedelta(seconds=expires_seconds))
        # Rewrite internal hostname to public-facing endpoint when configured
        public_endpoint = os.environ.get("MINIO_PUBLIC_ENDPOINT", "")
        if public_endpoint and url:
            internal = os.environ.get("MINIO_ENDPOINT", "")
            if internal and internal in url:
                scheme = "https" if os.environ.get("MINIO_SECURE", "").lower() == "true" else "http"
                url = url.replace(f"http://{internal}", public_endpoint, 1)
                url = url.replace(f"https://{internal}", public_endpoint, 1)
        return url
    except Exception as e:
        log.warning("minio.presigned_url_failed", bucket=bucket, object=object_name, error=str(e))
        return None


def list_objects(bucket: str, prefix: str) -> list[str]:
    """List object names in a bucket with the given prefix."""
    client = get_client()
    if not client:
        return []
    try:
        return [obj.object_name for obj in client.list_objects(bucket, prefix=prefix)]
    except Exception as e:
        log.warning("minio.list_failed", bucket=bucket, prefix=prefix, error=str(e))
        return []
