"""JWT and API key authentication utilities."""
from __future__ import annotations
from datetime import datetime, timedelta
import secrets
import uuid

from jose import JWTError, jwt
from app.config import settings


def create_access_token(user_id: str, github_login: str) -> str:
    """Create a signed JWT for a user."""
    expire = datetime.utcnow() + timedelta(minutes=settings.jwt_expire_minutes)
    payload = {
        "sub": user_id,
        "login": github_login,
        "exp": expire,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict:
    """Decode and verify a JWT. Returns payload or raises JWTError."""
    return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])


def generate_api_key() -> str:
    """Generate a 32-byte random API key."""
    return secrets.token_hex(32)
