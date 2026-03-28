"""FastAPI dependency for optional authentication.

Authentication is OPTIONAL — requests without credentials are treated as anonymous
and continue to work. This preserves backward compatibility with the test suite.
"""
from __future__ import annotations
from typing import Optional
import uuid

from fastapi import Header, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db


async def get_current_user(
    authorization: Optional[str] = Header(default=None),
    x_vexis_api_key: Optional[str] = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> Optional[dict]:
    """
    Extract authenticated user from JWT Bearer token or X-VEXIS-API-Key header.
    Returns None for unauthenticated requests (backward-compatible).
    """
    from app.models.user import User

    # Try API key first
    if x_vexis_api_key:
        result = await db.execute(select(User).where(User.api_key == x_vexis_api_key))
        user = result.scalar_one_or_none()
        if user:
            return {"id": user.id, "login": user.github_login, "email": user.email}
        return None  # invalid key — treat as anonymous

    # Try JWT Bearer
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        try:
            from app.core.auth import decode_token
            from jose import JWTError
            payload = decode_token(token)
            return {"id": uuid.UUID(payload["sub"]), "login": payload["login"], "email": None}
        except Exception:
            return None  # invalid token — treat as anonymous

    return None  # no credentials
