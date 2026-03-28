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
from app.api.deps import get_current_user

router = APIRouter()


class GitHubTokenRequest(BaseModel):
    code: str  # GitHub OAuth code


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


@router.post("/auth/token", response_model=TokenResponse)
async def exchange_github_token(
    body: GitHubTokenRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Exchange a GitHub OAuth code for a VEXIS JWT."""
    if not settings.github_client_id or not settings.github_client_secret:
        raise HTTPException(status_code=501, detail="GitHub OAuth not configured")

    # Exchange code for GitHub access token
    async with httpx.AsyncClient() as client:
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
        gh_data = resp.json()
        gh_token = gh_data.get("access_token")
        if not gh_token:
            raise HTTPException(status_code=400, detail="No access token in GitHub response")

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
        db.add(user)
    else:
        user.github_login = gh_user["login"]
        user.email = gh_user.get("email")
        user.avatar_url = gh_user.get("avatar_url")
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
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Generate (or regenerate) an API key for the authenticated user."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    result = await db.execute(select(User).where(User.id == current_user["id"]))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.api_key = generate_api_key()
    await db.commit()
    return {"api_key": user.api_key}


@router.get("/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)) -> dict:
    """Return info about the authenticated user."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return current_user
