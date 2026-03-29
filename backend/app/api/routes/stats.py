from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.database import get_db
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.schemas import ScanResponse
from app.api.deps import get_current_user

router = APIRouter()


@router.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    current_user: dict | None = Depends(get_current_user),
) -> dict:
    # Scope to the caller's scans (or anonymous-only scans if unauthenticated)
    if current_user:
        scan_filter = Scan.user_id == current_user["id"]
        finding_filter = Finding.scan_id.in_(
            select(Scan.id).where(Scan.user_id == current_user["id"])
        )
    else:
        scan_filter = Scan.user_id.is_(None)
        finding_filter = Finding.scan_id.in_(
            select(Scan.id).where(Scan.user_id.is_(None))
        )

    total_scans = await db.scalar(select(func.count(Scan.id)).where(scan_filter))
    total_findings = await db.scalar(select(func.count(Finding.id)).where(finding_filter))
    critical = await db.scalar(select(func.count(Finding.id)).where(finding_filter, Finding.severity == "critical"))
    high = await db.scalar(select(func.count(Finding.id)).where(finding_filter, Finding.severity == "high"))
    medium = await db.scalar(select(func.count(Finding.id)).where(finding_filter, Finding.severity == "medium"))
    low = await db.scalar(select(func.count(Finding.id)).where(finding_filter, Finding.severity == "low"))
    return {
        "total_scans": total_scans or 0,
        "total_findings": total_findings or 0,
        "by_severity": {
            "critical": critical or 0,
            "high": high or 0,
            "medium": medium or 0,
            "low": low or 0,
        },
    }


@router.get("/scans/recent")
async def get_recent_scans(
    limit: int = Query(10, ge=1, le=100),
    page: int = Query(1, ge=1),
    status: str | None = Query(None),
    min_severity: str | None = Query(None, description="Return only scans with at least one finding at this severity"),
    db: AsyncSession = Depends(get_db),
    current_user: dict | None = Depends(get_current_user),
) -> dict:
    """Return paginated scan history scoped to the caller.

    Authenticated users see only their own scans.
    Unauthenticated users see only anonymous scans (user_id IS NULL).
    """
    _SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    if current_user:
        user_filter = Scan.user_id == current_user["id"]
    else:
        user_filter = Scan.user_id.is_(None)

    q = select(Scan).where(user_filter)
    if status:
        q = q.where(Scan.status == status)

    count_q = select(func.count(Scan.id)).where(user_filter)
    if status:
        count_q = count_q.where(Scan.status == status)
    total = await db.scalar(count_q) or 0

    q = q.order_by(desc(Scan.created_at)).limit(limit).offset((page - 1) * limit)
    scan_result = await db.execute(q)
    scans = list(scan_result.scalars().all())

    scan_ids = [s.id for s in scans]
    counts: dict = {}
    max_severities: dict = {}
    if scan_ids:
        count_result = await db.execute(
            select(Finding.scan_id, func.count(Finding.id))
            .where(Finding.scan_id.in_(scan_ids))
            .group_by(Finding.scan_id)
        )
        counts = {row[0]: row[1] for row in count_result.all()}

        sev_result = await db.execute(
            select(Finding.scan_id, Finding.severity)
            .where(Finding.scan_id.in_(scan_ids))
        )
        for sid, sev in sev_result.all():
            if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(max_severities.get(sid, "info"), 0):
                max_severities[sid] = sev

    result_scans = [
        {
            **ScanResponse.model_validate(s).model_dump(mode="json"),
            "finding_count": counts.get(s.id, 0),
            "max_severity": max_severities.get(s.id),
        }
        for s in scans
    ]

    if min_severity and min_severity in _SEV_RANK:
        threshold = _SEV_RANK[min_severity]
        result_scans = [
            sc for sc in result_scans
            if _SEV_RANK.get(sc["max_severity"] or "info", 0) >= threshold
        ]

    return {
        "scans": result_scans,
        "total": total,
        "page": page,
        "limit": limit,
        "pages": max(1, (total + limit - 1) // limit),
    }
