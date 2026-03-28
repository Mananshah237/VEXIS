from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import uuid

from app.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.schemas import TriageRequest
from app.api.deps import get_current_user

router = APIRouter()


@router.post("/finding/{finding_id}/triage")
async def triage_finding(
    finding_id: str,
    body: TriageRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict | None = Depends(get_current_user),
) -> dict:
    result = await db.execute(select(Finding).where(Finding.id == uuid.UUID(finding_id)))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Verify caller owns the scan this finding belongs to
    scan_result = await db.execute(select(Scan).where(Scan.id == finding.scan_id))
    scan = scan_result.scalar_one_or_none()
    if current_user and scan and scan.user_id and scan.user_id != current_user["id"]:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.triage_status = body.status
    finding.triage_notes = body.notes
    await db.commit()
    return {"status": "ok", "triage_status": body.status}
