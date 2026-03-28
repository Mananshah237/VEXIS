"""
Incremental scan support.

Computes a SHA-256 manifest for a directory of source files, stores it in MinIO
(scan-artifacts/{scan_id}/manifest.json), and loads the previous scan's manifest
for the same source_ref so the orchestrator can skip unchanged files.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Optional

import structlog

log = structlog.get_logger()

_MANIFEST_ARTIFACT = "manifest"
_MINIO_BUCKET = "scan-artifacts"


# ── Manifest helpers ──────────────────────────────────────────────────────────

def compute_manifest(directory: str, extensions: tuple[str, ...] = (".py", ".js", ".jsx", ".ts", ".tsx")) -> dict[str, str]:
    """Return {relative_path: sha256_hex} for all matching files in directory."""
    root = Path(directory)
    manifest: dict[str, str] = {}
    for fpath in sorted(root.rglob("*")):
        if fpath.suffix not in extensions:
            continue
        if any(part in fpath.parts for part in {"node_modules", ".venv", "venv", "__pycache__", ".git"}):
            continue
        try:
            content = fpath.read_bytes()
            rel = str(fpath.relative_to(root))
            manifest[rel] = hashlib.sha256(content).hexdigest()
        except Exception:
            pass
    return manifest


def changed_files(old_manifest: dict[str, str], new_manifest: dict[str, str]) -> set[str]:
    """Return relative paths that are new or whose content changed."""
    changed: set[str] = set()
    for path, sha in new_manifest.items():
        if path not in old_manifest or old_manifest[path] != sha:
            changed.add(path)
    return changed


# ── MinIO persistence ─────────────────────────────────────────────────────────

async def save_manifest(scan_id: str, manifest: dict[str, str]) -> None:
    """Persist the manifest for scan_id to MinIO (best-effort)."""
    try:
        from app.core.storage import upload_artifact
        await upload_artifact(scan_id, _MANIFEST_ARTIFACT, manifest)
        log.debug("incremental.manifest_saved", scan_id=scan_id, files=len(manifest))
    except Exception as exc:
        log.warning("incremental.manifest_save_failed", scan_id=scan_id, error=str(exc))


def _load_manifest_from_minio(scan_id: str) -> Optional[dict[str, str]]:
    """Load a previously saved manifest from MinIO. Returns None on any failure."""
    try:
        from app.core.storage import get_client
        import io
        client = get_client()
        if not client:
            return None
        obj = client.get_object(_MINIO_BUCKET, f"{scan_id}/{_MANIFEST_ARTIFACT}.json")
        data = json.loads(obj.read())
        return data
    except Exception:
        return None


# ── Database lookup ───────────────────────────────────────────────────────────

async def find_previous_scan_id(source_ref: str, current_scan_id: str, db) -> Optional[str]:
    """Find the most recent *completed* scan for the same source_ref (excluding current)."""
    try:
        from sqlalchemy import select, desc
        from app.models.scan import Scan
        import uuid
        result = await db.execute(
            select(Scan.id)
            .where(Scan.source_ref == source_ref)
            .where(Scan.status == "complete")
            .where(Scan.id != uuid.UUID(current_scan_id))
            .order_by(desc(Scan.completed_at))
            .limit(1)
        )
        row = result.scalar_one_or_none()
        return str(row) if row else None
    except Exception as exc:
        log.warning("incremental.previous_scan_lookup_failed", error=str(exc))
        return None


async def get_changed_files_for_scan(
    current_dir: str,
    source_ref: str,
    current_scan_id: str,
    db,
) -> Optional[set[str]]:
    """
    Compute the current manifest, find the previous scan, and return the set of
    changed/new file paths (relative to current_dir).

    Returns None if incremental comparison is not possible (no previous scan,
    no stored manifest, etc.) — caller should fall back to full scan.
    """
    new_manifest = compute_manifest(current_dir)
    if not new_manifest:
        return None

    prev_id = await find_previous_scan_id(source_ref, current_scan_id, db)
    if not prev_id:
        log.info("incremental.no_previous_scan", source_ref=source_ref[:80])
        return None

    old_manifest = _load_manifest_from_minio(prev_id)
    if old_manifest is None:
        log.info("incremental.no_previous_manifest", prev_scan_id=prev_id)
        return None

    diff = changed_files(old_manifest, new_manifest)
    log.info(
        "incremental.diff",
        prev_scan_id=prev_id,
        total_files=len(new_manifest),
        changed=len(diff),
    )
    return diff
