"""FastAPI authentication dependencies.

Two dependencies are exposed:

* ``get_current_user`` — resolves the caller from a JWT Bearer token or an
  ``X-VEXIS-API-Key`` header. **Invalid or malformed credentials are rejected
  with 401** (they are no longer silently downgraded to anonymous). A request
  with *no* credentials at all resolves to ``None`` so that genuinely public
  endpoints (``/health``) keep working.

* ``require_user`` — wraps ``get_current_user`` and raises 401 when the caller
  is anonymous. Every data-returning / state-changing endpoint depends on this,
  so there is no anonymous data path anymore.
"""
from __future__ import annotations
from typing import Optional
import uuid

import structlog
from fastapi import Header, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db

log = structlog.get_logger()

_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid or missing authentication credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


async def get_current_user(
    authorization: Optional[str] = Header(default=None),
    x_vexis_api_key: Optional[str] = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> Optional[dict]:
    """Resolve the authenticated user.

    * Valid JWT / API key  → returns the user dict.
    * **Invalid** JWT / API key → raises 401 (no anonymous downgrade).
    * No credentials at all → returns ``None`` (anonymous).
    """
    from app.models.user import User

    # API key path -------------------------------------------------------
    if x_vexis_api_key:
        from app.core.crypto import hash_api_key

        result = await db.execute(
            select(User).where(User.api_key == hash_api_key(x_vexis_api_key))
        )
        user = result.scalar_one_or_none()
        if user:
            return _user_dict(user)
        log.warning("auth.api_key.invalid")
        raise _UNAUTHORIZED  # invalid key — reject, do not downgrade

    # JWT Bearer path ----------------------------------------------------
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        try:
            from app.core.auth import decode_token
            payload = decode_token(token)
            user_id = uuid.UUID(payload["sub"])
        except Exception:
            log.warning("auth.jwt.invalid")
            raise _UNAUTHORIZED  # invalid token — reject, do not downgrade

        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if user:
            return _user_dict(user)
        # Valid signature but the user no longer exists.
        log.warning("auth.jwt.unknown_user", user_id=str(user_id))
        raise _UNAUTHORIZED

    # An Authorization header that isn't a Bearer token is malformed.
    if authorization:
        log.warning("auth.header.malformed")
        raise _UNAUTHORIZED

    return None  # no credentials — anonymous (only allowed on public routes)


async def require_user(
    current_user: Optional[dict] = Depends(get_current_user),
) -> dict:
    """Require an authenticated user; raise 401 for anonymous callers."""
    if not current_user:
        raise _UNAUTHORIZED
    return current_user


def _user_dict(user) -> dict:
    """Project a User ORM row into the dict callers expect, decrypting secrets."""
    return {
        "id": user.id,
        "login": user.github_login,
        "email": user.email,
        "github_token": user.github_token_plain,
    }
