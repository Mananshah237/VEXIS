from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
import uuid

from app.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.schemas import FindingSummaryResponse, FindingDetailResponse
from app.api.deps import get_current_user

router = APIRouter()


@router.get("/scan/{scan_id}/findings")
async def list_findings(
    scan_id: str,
    severity: str | None = Query(None),
    vuln_class: str | None = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: dict | None = Depends(get_current_user),
) -> dict:
    # Verify the scan exists and the user has access to it
    scan_result = await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.user_id is not None:
        if not current_user or str(scan.user_id) != str(current_user["id"]):
            raise HTTPException(status_code=404, detail="Scan not found")

    q = select(Finding).where(Finding.scan_id == uuid.UUID(scan_id))
    if severity:
        q = q.where(Finding.severity == severity)
    if vuln_class:
        q = q.where(Finding.vuln_class == vuln_class)
    q = q.order_by(desc(Finding.taint_confidence), desc(Finding.confidence))
    q = q.offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(q)
    findings = result.scalars().all()
    return {
        "findings": [FindingSummaryResponse.model_validate(f) for f in findings],
        "page": page,
        "per_page": per_page,
    }


@router.get("/finding/{finding_id}", response_model=FindingDetailResponse)
async def get_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict | None = Depends(get_current_user),
) -> FindingDetailResponse:
    result = await db.execute(select(Finding).where(Finding.id == uuid.UUID(finding_id)))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    # Verify ownership through the parent scan
    scan_result = await db.execute(select(Scan).where(Scan.id == finding.scan_id))
    scan = scan_result.scalar_one_or_none()
    if scan and scan.user_id is not None:
        if not current_user or str(scan.user_id) != str(current_user["id"]):
            raise HTTPException(status_code=404, detail="Finding not found")
    return FindingDetailResponse.model_validate(finding)
