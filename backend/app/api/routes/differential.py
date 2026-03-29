"""
GET /api/v1/scan/{id}/differential — returns the Semgrep vs VEXIS differential report.

The differential is computed lazily and cached in scan.stats["differential"].
First call runs Semgrep; subsequent calls return cached results.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import uuid

from app.database import get_db
from app.models.scan import Scan
from app.models.finding import Finding
from app.api.deps import get_current_user

router = APIRouter()


@router.get("/scan/{scan_id}/differential")
async def get_differential(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict | None = Depends(get_current_user),
) -> dict:
    scan_result = await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.user_id is not None:
        if not current_user or str(scan.user_id) != str(current_user["id"]):
            raise HTTPException(status_code=404, detail="Scan not found")

    # Return cached differential if available
    cached = (scan.stats or {}).get("differential")
    if cached:
        return cached

    if scan.status not in ("complete", "COMPLETE"):
        raise HTTPException(status_code=409, detail="Scan not yet complete")

    # Load findings
    findings_result = await db.execute(
        select(Finding).where(Finding.scan_id == uuid.UUID(scan_id))
    )
    findings = list(findings_result.scalars().all())

    # Determine scan path — try to find cached clone or temp dir
    # For now, run semgrep on what we have from source_ref
    from app.analysis.semgrep_runner import run_semgrep, compute_differential, DifferentialResult
    import tempfile, os

    # We need the source path — stored in scan metadata or re-derive
    source_path = (scan.stats or {}).get("source_path")

    semgrep_findings: list = []
    semgrep_available = True
    semgrep_error = None

    if source_path and os.path.isdir(source_path):
        semgrep_findings = await run_semgrep(source_path)
    else:
        semgrep_available = False
        semgrep_error = "Source path no longer available (ephemeral scan). Re-scan to enable differential."

    diff = compute_differential(findings, semgrep_findings)

    response = {
        "semgrep_available": semgrep_available,
        "semgrep_error": semgrep_error,
        "summary": {
            "vexis_total": diff.vexis_total,
            "semgrep_total": diff.semgrep_total,
            "vexis_only": len(diff.vexis_only),
            "semgrep_only": len(diff.semgrep_only),
            "overlap": len(diff.overlap),
        },
        "vexis_only": diff.vexis_only,
        "semgrep_only": [
            {
                "rule_id": sf.rule_id,
                "file": sf.file,
                "line": sf.line,
                "message": sf.message,
                "severity": sf.severity,
                "vuln_class": sf.vuln_class,
                "cwe": sf.cwe,
            }
            for sf in diff.semgrep_only
        ],
        "overlap": diff.overlap,
    }

    # Cache in scan stats
    scan.stats = {**(scan.stats or {}), "differential": response}
    await db.commit()

    return response
