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
            return _user_dict(user, "api_key")
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
            return _user_dict(user, "jwt")
        # Valid signature but the user no longer exists.
        log.warning("auth.jwt.unknown_user", user_id=str(user_id))
        raise _UNAUTHORIZED

    # An Authorization header that isn't a Bearer token is malformed.
    if authorization:
        log.warning("auth.header.malformed")
        raise _UNAUTHORIZED

    return None  # no credentials — anonymous (only allowed on public routes)


# Fixed synthetic user used ONLY when settings.auth_enforced is false (local dev).
# Every anonymous request resolves to this same id, so owner-scoped queries stay
# coherent (create -> list -> view all match). scan.user_id has no FK, so no DB row
# is needed. Never reachable when AUTH_ENFORCED is true (the default).
_DEV_USER = {
    "id": uuid.UUID("00000000-0000-0000-0000-0000000000de"),
    "login": "dev-local",
    "email": None,
    "auth_method": "dev",
}


async def require_user(
    current_user: Optional[dict] = Depends(get_current_user),
) -> dict:
    """Require an authenticated user; raise 401 for anonymous callers.

    When ``AUTH_ENFORCED=false`` (local dev only), an anonymous request is
    resolved to a fixed dev user instead of being rejected, so the UI works
    without GitHub OAuth. ``validate_secrets`` forbids this outside dev.
    """
    if current_user:
        return current_user
    from app.config import settings
    if not settings.auth_enforced:
        log.warning("auth.dev_bypass", detail="AUTH_ENFORCED=false — anonymous request resolved to dev user")
        return dict(_DEV_USER)
    raise _UNAUTHORIZED


async def require_repository_write(
    current_user: dict = Depends(require_user),
) -> dict:
    """Stored repository write credentials require a signed-in web user."""
    if current_user.get("auth_method") != "jwt":
        raise HTTPException(status_code=403, detail="Sign in to open pull requests; API keys cannot write repositories")
    return current_user


def _user_dict(user, auth_method: str) -> dict:
    """Authentication carries identity only; credentials are loaded on demand."""
    return {
        "id": user.id,
        "login": user.github_login,
        "email": user.email,
        "auth_method": auth_method,
    }
