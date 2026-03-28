from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.database import get_db
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.schemas import ScanResponse

router = APIRouter()


@router.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db)) -> dict:
    total_scans = await db.scalar(select(func.count(Scan.id)))
    total_findings = await db.scalar(select(func.count(Finding.id)))
    critical = await db.scalar(select(func.count(Finding.id)).where(Finding.severity == "critical"))
    high = await db.scalar(select(func.count(Finding.id)).where(Finding.severity == "high"))
    medium = await db.scalar(select(func.count(Finding.id)).where(Finding.severity == "medium"))
    low = await db.scalar(select(func.count(Finding.id)).where(Finding.severity == "low"))
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
) -> dict:
    """Return paginated scan history with per-scan finding counts.

    Query params:
    - limit / page: pagination
    - status: filter by scan status (e.g. 'complete', 'failed')
    - min_severity: 'critical' | 'high' | 'medium' | 'low' — filters to scans
      that have at least one finding at that severity or above
    """
    _SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    # Base query
    q = select(Scan)
    if status:
        q = q.where(Scan.status == status)

    # Count total matching scans (for pagination metadata)
    count_q = select(func.count(Scan.id))
    if status:
        count_q = count_q.where(Scan.status == status)
    total = await db.scalar(count_q) or 0

    q = q.order_by(desc(Scan.created_at)).limit(limit).offset((page - 1) * limit)
    scan_result = await db.execute(q)
    scans = list(scan_result.scalars().all())

    # Batch-fetch finding counts and max severity per scan
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

    # Apply min_severity filter post-fetch (simpler than a subquery join)
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
