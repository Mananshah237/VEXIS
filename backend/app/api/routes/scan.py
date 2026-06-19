from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import uuid

from app.database import get_db
from app.models.scan import Scan, ScanStatus
from app.models.schemas import ScanCreateRequest, ScanResponse
from app.core.orchestrator import run_scan
from app.api.deps import require_user

router = APIRouter()


def _assert_owner(scan: Scan, current_user: dict) -> None:
    """Raise 404 (not 403, to avoid enumeration) unless the caller owns the scan.

    Every scan now has an owner (creation requires auth), so there is no
    anonymous/world-readable path: a NULL or mismatched owner is denied.
    """
    if scan.user_id is None or str(scan.user_id) != str(current_user["id"]):
        raise HTTPException(status_code=404, detail="Scan not found")


@router.post("/scan", response_model=ScanResponse, status_code=201)
async def create_scan(
    body: ScanCreateRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_user),
) -> ScanResponse:
    # Block server-side path scanning — only github_url and raw_code are safe
    if body.source_type not in ("github_url", "raw_code"):
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid source_type. Only 'github_url' and 'raw_code' are accepted via the API. "
                "Local path scanning ('directory', 'file_upload') is disabled to prevent server-side file read."
            ),
        )

    # Validate GitHub URL format before creating DB record (avoids orphaned scan rows)
    if body.source_type == "github_url":
        from app.core.git_ops import _validate_repo_url
        try:
            _validate_repo_url(body.source)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    # Raw code size guard — reject oversized payloads before creating DB record
    if body.source_type == "raw_code" and len(body.source) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Raw code payload exceeds 10 MB limit.")

    # Rate limiting — every caller is authenticated and limited (fails closed).
    from app.core.rate_limiter import check_rate_limit, FREE_TIER_DAILY_LIMIT
    allowed, remaining = await check_rate_limit(str(current_user["id"]))
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Daily scan limit reached ({FREE_TIER_DAILY_LIMIT} scans/day for free tier). Upgrade for unlimited scans.",
            headers={"X-RateLimit-Remaining": "0"},
        )

    scan = Scan(
        id=uuid.uuid4(),
        source_type=body.source_type,
        source_ref=body.source,
        language=body.language,
        status=ScanStatus.QUEUED,
        config=body.config.model_dump() if body.config else {},
        user_id=current_user["id"],
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    from app.config import settings
    if settings.use_celery:
        from app.tasks.scan_task import run_scan_task
        run_scan_task.delay(str(scan.id))
    else:
        background_tasks.add_task(run_scan, str(scan.id))
    return ScanResponse.model_validate(scan)


@router.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_user),
) -> ScanResponse:
    result = await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    _assert_owner(scan, current_user)
    return ScanResponse.model_validate(scan)


@router.get("/scan/{scan_id}/download-code")
async def download_code_snapshot(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_user),
) -> dict:
    """Return a presigned URL to download the code snapshot for this scan."""
    result = await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    _assert_owner(scan, current_user)
    from app.core.storage import get_signed_url, BUCKET_CODE
    url = get_signed_url(BUCKET_CODE, f"{scan_id}/source.py")
    if not url:
        raise HTTPException(status_code=404, detail="No code snapshot available")
    return {"url": url, "expires_in": 3600}


@router.get("/scan/{scan_id}/compare/{other_scan_id}")
async def compare_scans(
    scan_id: str,
    other_scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_user),
) -> dict:
    """Compare findings between two scans of the same source.

    Returns three lists:
    - new: findings in scan_id not in other_scan_id (keyed by CWE + sink file + sink line)
    - resolved: findings in other_scan_id not in scan_id
    - unchanged: findings present in both
    """
    async def _load(sid: str):
        r = await db.execute(select(Scan).where(Scan.id == uuid.UUID(sid)))
        s = r.scalar_one_or_none()
        if not s:
            raise HTTPException(status_code=404, detail=f"Scan {sid} not found")
        if s.user_id is None or str(s.user_id) != str(current_user["id"]):
            raise HTTPException(status_code=404, detail=f"Scan {sid} not found")
        return s

    from app.models.finding import Finding as FindingModel
    from sqlalchemy import select as _select

    scan_a = await _load(scan_id)
    scan_b = await _load(other_scan_id)

    async def _findings(s):
        res = await db.execute(_select(FindingModel).where(FindingModel.scan_id == s.id))
        return list(res.scalars().all())

    findings_a = await _findings(scan_a)
    findings_b = await _findings(scan_b)

    def _key(f) -> str:
        return f"{f.cwe_id}|{f.sink_file}|{f.sink_line}|{f.vuln_class}"

    keys_a = {_key(f): f for f in findings_a}
    keys_b = {_key(f): f for f in findings_b}

    def _serialize(f) -> dict:
        return {
            "id": str(f.id),
            "title": f.title,
            "severity": f.severity,
            "cwe_id": f.cwe_id,
            "source_file": f.source_file,
            "source_line": f.source_line,
            "sink_file": f.sink_file,
            "sink_line": f.sink_line,
            "confidence": f.confidence,
        }

    new_findings = [_serialize(f) for k, f in keys_a.items() if k not in keys_b]
    resolved_findings = [_serialize(f) for k, f in keys_b.items() if k not in keys_a]
    unchanged_findings = [_serialize(f) for k, f in keys_a.items() if k in keys_b]

    return {
        "scan_id": scan_id,
        "base_scan_id": other_scan_id,
        "new": new_findings,
        "resolved": resolved_findings,
        "unchanged": unchanged_findings,
        "summary": {
            "new": len(new_findings),
            "resolved": len(resolved_findings),
            "unchanged": len(unchanged_findings),
        },
    }


@router.get("/scan/{scan_id}/artifacts")
async def list_scan_artifacts(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_user),
) -> dict:
    """Return presigned URLs for all artifacts of this scan."""
    result = await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    _assert_owner(scan, current_user)
    from app.core.storage import list_objects, get_signed_url, BUCKET_ARTIFACTS
    objects = list_objects(BUCKET_ARTIFACTS, prefix=f"{scan_id}/")
    urls = {
        obj.split("/")[-1]: get_signed_url(BUCKET_ARTIFACTS, obj)
        for obj in objects
        if get_signed_url(BUCKET_ARTIFACTS, obj)
    }
    return {"artifacts": urls}


@router.delete("/scan/{scan_id}", status_code=200)
async def delete_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_user),
) -> dict:
    """Delete a single scan, its findings, and stored artifacts (owner only)."""
    sid = uuid.UUID(scan_id)
    result = await db.execute(select(Scan).where(Scan.id == sid))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    _assert_owner(scan, current_user)

    from app.models.finding import Finding
    from sqlalchemy import delete as _delete

    await db.execute(_delete(Finding).where(Finding.scan_id == sid))
    await db.execute(_delete(Scan).where(Scan.id == sid))
    await db.commit()

    # Best-effort purge of object storage for this scan.
    try:
        from app.core.storage import delete_prefix, BUCKET_CODE, BUCKET_ARTIFACTS, BUCKET_REPORTS
        for bucket in (BUCKET_CODE, BUCKET_ARTIFACTS, BUCKET_REPORTS):
            delete_prefix(bucket, f"{scan_id}/")
        delete_prefix(BUCKET_ARTIFACTS, f"reports/{scan_id}/")
    except Exception:
        pass

    return {"status": "deleted", "scan_id": scan_id}
