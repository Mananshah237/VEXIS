"""Application-layer encryption for secrets at rest.

Two primitives:

* ``encrypt_secret`` / ``decrypt_secret`` — symmetric Fernet encryption used for
  the GitHub OAuth token (repo scope) stored on ``users.github_token``. The key
  comes from ``ENCRYPTION_KEY`` (a url-safe base64 32-byte Fernet key).
* ``hash_api_key`` — one-way SHA-256 of API keys so a DB leak does not expose
  usable keys. Lookups hash the presented key and compare.

In dev (``VEXIS_ENV=dev``) with no ``ENCRYPTION_KEY`` set we fall back to a
deterministic key derived from the JWT secret so local development still works
without extra setup; ``Settings.validate_secrets`` forbids this in production.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app.config import settings

# Marker prepended to ciphertext so we can tell encrypted values apart from any
# legacy plaintext values that may still be in the DB (transparent migration).
_PREFIX = "enc:v1:"


def _derive_dev_key() -> str:
    """Deterministic Fernet key from the JWT secret for dev-only use."""
    digest = hashlib.sha256(("vexis-dev-fernet:" + settings.jwt_secret).encode()).digest()
    return base64.urlsafe_b64encode(digest).decode()


def _fernet() -> Fernet:
    key = settings.encryption_key.strip() or (_derive_dev_key() if settings.is_dev else "")
    if not key:
        raise RuntimeError(
            "ENCRYPTION_KEY is not configured — cannot encrypt/decrypt secrets at rest."
        )
    try:
        return Fernet(key.encode())
    except Exception as exc:  # malformed key
        raise RuntimeError(f"ENCRYPTION_KEY is not a valid Fernet key: {exc}") from exc


def encrypt_secret(plaintext: str | None) -> str | None:
    """Encrypt a secret for storage. ``None``/empty pass through unchanged."""
    if not plaintext:
        return plaintext
    token = _fernet().encrypt(plaintext.encode())
    return _PREFIX + token.decode()


def decrypt_secret(stored: str | None) -> str | None:
    """Decrypt a stored secret. Transparently returns legacy plaintext values
    (those without the ``enc:v1:`` prefix) so pre-encryption rows keep working."""
    if not stored:
        return stored
    if not stored.startswith(_PREFIX):
        return stored  # legacy plaintext — return as-is
    raw = stored[len(_PREFIX):].encode()
    try:
        return _fernet().decrypt(raw).decode()
    except InvalidToken:
        # Wrong/rotated key — fail closed rather than leaking a corrupt value.
        raise RuntimeError("Unable to decrypt stored secret (key mismatch?)")


def hash_api_key(api_key: str) -> str:
    """One-way SHA-256 hash for API-key storage/lookup."""
    return hashlib.sha256(api_key.encode()).hexdigest()
