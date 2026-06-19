"""Authentication routes — GitHub OAuth token exchange and API key management."""
from __future__ import annotations
import uuid
import httpx
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.config import settings
from app.core.auth import create_access_token, generate_api_key
from app.models.user import User
from app.models.scan import Scan
from app.models.finding import Finding
from app.api.deps import require_user

router = APIRouter()


class GitHubTokenRequest(BaseModel):
    # Either an OAuth `code` (server does the exchange) OR an already-obtained
    # GitHub `access_token` (e.g. from NextAuth, which already did the exchange).
    code: str | None = None
    access_token: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


@router.post("/auth/token", response_model=TokenResponse)
async def exchange_github_token(
    body: GitHubTokenRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Exchange a GitHub OAuth code (or an existing GitHub access token) for a VEXIS JWT."""
    async with httpx.AsyncClient() as client:
        # Path 1: caller already has a GitHub access token (NextAuth flow).
        if body.access_token:
            gh_token = body.access_token
        # Path 2: classic server-side code exchange.
        elif body.code:
            if not settings.github_client_id or not settings.github_client_secret:
                raise HTTPException(status_code=501, detail="GitHub OAuth not configured")
            resp = await client.post(
                "https://github.com/login/oauth/access_token",
                json={
                    "client_id": settings.github_client_id,
                    "client_secret": settings.github_client_secret,
                    "code": body.code,
                },
                headers={"Accept": "application/json"},
            )
            if resp.status_code != 200:
                raise HTTPException(status_code=400, detail="GitHub token exchange failed")
            gh_token = resp.json().get("access_token")
            if not gh_token:
                raise HTTPException(status_code=400, detail="No access token in GitHub response")
        else:
            raise HTTPException(status_code=400, detail="Provide either 'code' or 'access_token'")

        # Fetch GitHub user info
        user_resp = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {gh_token}", "Accept": "application/vnd.github.v3+json"},
        )
        if user_resp.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to fetch GitHub user")
        gh_user = user_resp.json()

    # Upsert user in DB
    github_id = str(gh_user["id"])
    result = await db.execute(select(User).where(User.github_id == github_id))
    user = result.scalar_one_or_none()
    if not user:
        user = User(
            id=uuid.uuid4(),
            github_id=github_id,
            github_login=gh_user["login"],
            email=gh_user.get("email"),
            avatar_url=gh_user.get("avatar_url"),
        )
        user.github_token_plain = gh_token  # encrypt-on-write
        db.add(user)
    else:
        user.github_login = gh_user["login"]
        user.email = gh_user.get("email")
        user.avatar_url = gh_user.get("avatar_url")
        user.github_token_plain = gh_token  # encrypt-on-write
        user.last_seen_at = datetime.utcnow()
    await db.commit()
    await db.refresh(user)

    token = create_access_token(str(user.id), user.github_login)
    return TokenResponse(
        access_token=token,
        user={"id": str(user.id), "login": user.github_login, "avatar_url": user.avatar_url},
    )


@router.post("/auth/api-key")
async def generate_user_api_key(
    current_user: dict = Depends(require_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Generate (or regenerate) an API key for the authenticated user."""
    result = await db.execute(select(User).where(User.id == current_user["id"]))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    from app.core.crypto import hash_api_key

    raw_key = generate_api_key()
    user.api_key = hash_api_key(raw_key)  # store only the hash at rest
    await db.commit()
    # Return the raw key exactly once — it is not recoverable afterwards.
    return {"api_key": raw_key}


@router.get("/auth/me")
async def get_me(current_user: dict = Depends(require_user)) -> dict:
    """Return info about the authenticated user."""
    return current_user


@router.delete("/auth/me")
async def delete_my_account(
    current_user: dict = Depends(require_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """GDPR right-to-erasure: delete the caller's account and ALL their data.

    Removes every scan + finding owned by the user, the user record (including
    the encrypted GitHub token and API-key hash), and best-effort purges object
    storage for each scan. Irreversible.
    """
    from sqlalchemy import delete as _delete

    user_id = current_user["id"]
    scan_rows = await db.execute(select(Scan.id).where(Scan.user_id == user_id))
    scan_ids = [r[0] for r in scan_rows.all()]

    if scan_ids:
        await db.execute(_delete(Finding).where(Finding.scan_id.in_(scan_ids)))
        await db.execute(_delete(Scan).where(Scan.id.in_(scan_ids)))
    await db.execute(_delete(User).where(User.id == user_id))
    await db.commit()

    # Best-effort purge of object storage for every deleted scan.
    try:
        from app.core.storage import (
            delete_prefix, BUCKET_CODE, BUCKET_ARTIFACTS, BUCKET_REPORTS,
        )
        for sid in scan_ids:
            for bucket in (BUCKET_CODE, BUCKET_ARTIFACTS, BUCKET_REPORTS):
                delete_prefix(bucket, f"{sid}/")
            delete_prefix(BUCKET_ARTIFACTS, f"reports/{sid}/")
    except Exception:
        pass

    return {"status": "deleted", "scans_deleted": len(scan_ids)}
