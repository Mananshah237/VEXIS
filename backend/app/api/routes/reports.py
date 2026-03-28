"""
Report routes.

GET /api/v1/report/{scan_id}         — generate (or serve cached) PDF report
GET /api/v1/report/{scan_id}/html    — return raw HTML (debug / preview)
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.storage import get_signed_url
from app.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan

router = APIRouter()

_PDF_CONTENT_TYPE = "application/pdf"
_PDF_CACHE_BUCKET = "scan-artifacts"


async def _load_scan_and_findings(
    scan_id: str,
    db: AsyncSession,
    current_user: dict | None,
) -> tuple[Scan, list[Finding]]:
    """Fetch scan + findings, enforcing ownership when auth is present."""
    try:
        uid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID")

    result = await db.execute(select(Scan).where(Scan.id == uid))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if current_user and scan.user_id and scan.user_id != current_user["id"]:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "complete":
        raise HTTPException(status_code=409, detail=f"Scan is not complete (status: {scan.status})")

    findings_result = await db.execute(
        select(Finding).where(Finding.scan_id == uid)
    )
    findings = list(findings_result.scalars().all())
    return scan, findings


@router.get("/report/{scan_id}")
async def get_pdf_report(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict | None = Depends(get_current_user),
) -> Response:
    """Generate a PDF report for a completed scan.

    On first call the PDF is built with WeasyPrint and cached in MinIO.
    Subsequent calls for the same scan return a redirect to the signed MinIO URL.
    """
    scan, findings = await _load_scan_and_findings(scan_id, db, current_user)

    object_name = f"reports/{scan_id}/report.pdf"

    # Try to serve from MinIO cache first
    try:
        url = get_signed_url(_PDF_CACHE_BUCKET, object_name, expires_seconds=3600)
        if url:
            from fastapi.responses import RedirectResponse
            return RedirectResponse(url=url, status_code=302)
    except Exception:
        pass  # cache miss — generate below

    # Build PDF
    try:
        from app.reporting.pdf_builder import build_pdf
        pdf_bytes = build_pdf(scan, findings)
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="WeasyPrint is not installed. Run: pip install weasyprint",
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}")

    # Cache in MinIO (best-effort — don't fail the request if storage is unavailable)
    try:
        import io as _io
        from app.core.storage import get_client as _get_minio
        _mc = _get_minio()
        if _mc:
            _mc.put_object(
                _PDF_CACHE_BUCKET,
                object_name,
                _io.BytesIO(pdf_bytes),
                length=len(pdf_bytes),
                content_type=_PDF_CONTENT_TYPE,
            )
    except Exception:
        pass

    filename = f"vexis-report-{scan_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type=_PDF_CONTENT_TYPE,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/report/{scan_id}/html")
async def get_html_report(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict | None = Depends(get_current_user),
) -> Response:
    """Return the rendered HTML for a scan report (preview / debugging)."""
    scan, findings = await _load_scan_and_findings(scan_id, db, current_user)

    try:
        from app.reporting.pdf_builder import build_html
        html = build_html(scan, findings)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Report rendering failed: {exc}")

    return Response(content=html, media_type="text/html")
