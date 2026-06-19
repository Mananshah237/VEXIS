"""User model for VEXIS authentication."""
from __future__ import annotations
from datetime import datetime
import uuid
from sqlalchemy import String, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    github_id: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    github_login: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    avatar_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    # API key is stored as a SHA-256 hash (64 hex chars), never plaintext.
    api_key: Mapped[str | None] = mapped_column(String(128), unique=True, nullable=True)
    # GitHub OAuth token (repo scope) — stored ENCRYPTED at rest (Fernet).
    # Never read/write this column directly; use the github_token_plain property
    # which transparently decrypts on read and encrypts on write.
    github_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    @property
    def github_token_plain(self) -> str | None:
        """Decrypt and return the stored GitHub OAuth token (or None)."""
        from app.core.crypto import decrypt_secret
        return decrypt_secret(self.github_token)

    @github_token_plain.setter
    def github_token_plain(self, value: str | None) -> None:
        """Encrypt and store a GitHub OAuth token."""
        from app.core.crypto import encrypt_secret
        self.github_token = encrypt_secret(value)
