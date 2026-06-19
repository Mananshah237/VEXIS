"""
Autofix + PR generation.

POST /api/v1/finding/{id}/autofix/generate  — LLM-generate a fix (patched code + diff).
GET  /api/v1/finding/{id}/autofix           — return the stored fix.
POST /api/v1/finding/{id}/pr                 — open a GitHub PR with the fix.
"""
from __future__ import annotations
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.api.deps import require_user
from app.exploit.autofix_generator import AutoFixGenerator
from app.exploit.pr_generator import PRGenerator, parse_repo_url

router = APIRouter()

# File extension → language label (matches the analyzer's language names)
_EXT_LANG = {
    "py": "python", "js": "javascript", "jsx": "javascript", "ts": "typescript",
    "tsx": "typescript", "java": "java", "go": "go", "rb": "ruby", "c": "c",
    "h": "c", "cpp": "cpp", "cc": "cpp", "cxx": "cpp", "hpp": "cpp", "rs": "rust",
    "sh": "bash", "bash": "bash",
}


def _lang_for(path: str) -> str:
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    return _EXT_LANG.get(ext, "text")


async def _load_owned_finding(finding_id: str, db: AsyncSession, current_user: dict) -> Finding:
    result = await db.execute(select(Finding).where(Finding.id == uuid.UUID(finding_id)))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    scan_result = await db.execute(select(Scan).where(Scan.id == finding.scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan or scan.user_id is None or str(scan.user_id) != str(current_user["id"]):
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.post("/finding/{finding_id}/autofix/generate")
async def generate_autofix(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_user),
) -> dict:
    finding = await _load_owned_finding(finding_id, db, current_user)
    vulnerable_code = finding.sink_code or finding.source_code or ""
    if not vulnerable_code:
        raise HTTPException(status_code=400, detail="No code available on this finding to fix")

    taint_summary = (finding.llm_reasoning or "")[:500]
    fix = await AutoFixGenerator().generate(
        vuln_class=finding.vuln_class,
        cwe_id=finding.cwe_id,
        language=_lang_for(finding.sink_file),
        file_path=finding.sink_file,
        line=finding.sink_line,
        vulnerable_code=vulnerable_code,
        taint_summary=taint_summary,
    )
    finding.autofix = {
        "patched_code": fix.patched_code,
        "diff": fix.diff,
        "explanation": fix.explanation,
        "summary": fix.summary,
    }
    await db.commit()
    return finding.autofix


@router.get("/finding/{finding_id}/autofix")
async def get_autofix(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_user),
) -> dict:
    finding = await _load_owned_finding(finding_id, db, current_user)
    if not finding.autofix:
        raise HTTPException(status_code=404, detail="No autofix generated yet")
    return finding.autofix


class PRRequest(BaseModel):
    # Optional: defaults to the signed-in user's stored GitHub token.
    github_token: str | None = None
    repo_url: str | None = None  # owner/repo or URL; defaults to the scan's source


@router.post("/finding/{finding_id}/pr")
async def open_pull_request(
    finding_id: str,
    body: PRRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_user),
) -> dict:
    finding = await _load_owned_finding(finding_id, db, current_user)
    scan_result = await db.execute(select(Scan).where(Scan.id == finding.scan_id))
    scan = scan_result.scalar_one_or_none()

    token = body.github_token or (current_user or {}).get("github_token")
    if not token:
        raise HTTPException(status_code=401, detail="GitHub not connected — sign in with GitHub to open a PR")

    repo_source = body.repo_url or (scan.source_ref if scan else None)
    ref = parse_repo_url(repo_source or "")
    if not ref:
        raise HTTPException(status_code=400, detail="Could not determine the GitHub repository (owner/repo)")

    # Repo-relative path: strip any temp/clone prefix up to and including the repo name.
    file_path = finding.sink_file.replace("\\", "/").lstrip("/")
    marker = f"{ref.repo}/"
    if marker in file_path:
        file_path = file_path.split(marker, 1)[1]

    pr = PRGenerator()
    try:
        original, _sha, default_branch = await pr.get_file(token, ref, file_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not read {file_path} from GitHub: {e}")

    # Fix the WHOLE file so the commit is valid.
    fix = await AutoFixGenerator().generate(
        vuln_class=finding.vuln_class,
        cwe_id=finding.cwe_id,
        language=_lang_for(file_path),
        file_path=file_path,
        line=finding.sink_line,
        vulnerable_code=original,
        taint_summary=(finding.llm_reasoning or "")[:500],
    )
    if fix.patched_code.strip() == original.strip():
        raise HTTPException(status_code=422, detail="Autofix produced no change to the file")

    branch = f"vexis/fix-{finding.vuln_class}-{str(finding.id)[:8]}"
    title = fix.summary or f"Fix {finding.vuln_class} in {file_path}"
    pr_body = (
        f"## VEXIS automated security fix\n\n"
        f"**Vulnerability:** {finding.vuln_class} ({finding.cwe_id or 'CWE n/a'}) — {finding.severity}\n"
        f"**Location:** `{file_path}:{finding.sink_line}`\n\n"
        f"### What changed\n{fix.explanation}\n\n"
        f"```diff\n{fix.diff[:4000]}\n```\n\n"
        f"_Generated by VEXIS. Please review before merging._"
    )

    try:
        pr_url = await pr.open_fix_pr(
            token=token, ref=ref, file_path=file_path,
            new_content=fix.patched_code, branch_name=branch,
            title=title, body=pr_body, base_branch=default_branch,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to open PR: {e}")

    finding.autofix = {
        "patched_code": fix.patched_code, "diff": fix.diff,
        "explanation": fix.explanation, "summary": fix.summary, "pr_url": pr_url,
    }
    await db.commit()
    return {"pr_url": pr_url, "branch": branch}
