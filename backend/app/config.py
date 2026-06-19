import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List

# Secret values that must never be used outside an explicit dev environment.
# If any of these appear in JWT_SECRET / MINIO_SECRET_KEY while VEXIS_ENV is not
# "dev"/"test", the app refuses to boot (see Settings.validate_secrets()).
_KNOWN_WEAK_SECRETS = {
    "",
    "vexis-dev-jwt-secret-change-in-prod",
    "vexis-dev-secret-change-in-prod",
    "vexis-local-dev-secret",
    "vexis_dev_password",
    "change_me_generate_with_secrets_token_hex_32",
    "change_me_strong_random_password",
}


# ---------------------------------------------------------------------------
# Default exclusion patterns for vendored / minified / generated files.
# Paths are matched as substrings against the full file path (case-insensitive).
# Filenames are matched against the basename only.
# Override via VEXIS_EXCLUDED_PATH_PATTERNS / VEXIS_EXCLUDED_FILENAME_PATTERNS
# env vars (comma-separated lists).
# ---------------------------------------------------------------------------
DEFAULT_EXCLUDED_PATH_PATTERNS: List[str] = [
    "/node_modules/",
    "/vendor/",
    "/vendors/",
    "/static/js/",
    "/static/css/",
    "/assets/js/",
    "/assets/css/",
    "/dist/",
    "/build/",
    "/.venv/",
    "/venv/",
    "/env/",
    "/__pycache__/",
    "/.git/",
    "/bower_components/",
    "/jspm_packages/",
]

DEFAULT_EXCLUDED_FILENAME_PATTERNS: List[str] = [
    ".min.js",
    ".min.css",
    ".bundle.js",
    ".chunk.js",
    "-min.js",
    ".packed.js",
]

# Files larger than this (in bytes) are skipped — minified/generated files are huge
DEFAULT_MAX_FILE_BYTES: int = 200_000  # 200 KB


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Deployment environment. Set VEXIS_ENV=production (or anything other than
    # dev/test/local) to enforce the secret-strength startup guard.
    env: str = "dev"

    # Database
    database_url: str = "postgresql+asyncpg://vexis:vexis@localhost:5432/vexis"

    # Redis
    redis_url: str = "redis://localhost:6379"

    # LLM providers
    google_api_key: str = ""
    anthropic_api_key: str = ""

    # CORS
    cors_origins: List[str] = ["http://localhost:3000", "http://localhost:3001"]

    # Scan limits
    max_repo_size_mb: int = 500
    max_llm_calls_per_scan: int = 100
    scan_timeout_seconds: int = 600

    # File exclusion — vendored / minified / generated files
    excluded_path_patterns: List[str] = DEFAULT_EXCLUDED_PATH_PATTERNS
    excluded_filename_patterns: List[str] = DEFAULT_EXCLUDED_FILENAME_PATTERNS
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES

    # Logging
    log_level: str = "INFO"

    # Optional: Ollama fallback
    ollama_base_url: str = "http://localhost:11434"

    # Optional: GitHub OAuth (Phase 2)
    github_client_id: str = ""
    github_client_secret: str = ""

    # MinIO object storage
    minio_endpoint: str = "localhost:9000"
    minio_public_endpoint: str = ""  # Public-facing URL base for presigned URLs, e.g. http://localhost:9000
    minio_access_key: str = "vexis"
    minio_secret_key: str = ""  # Required in production — set MINIO_SECRET_KEY env var
    minio_secure: bool = False

    # Celery async scanning (opt-in; set VEXIS_USE_CELERY=true to enable)
    use_celery: bool = False

    # JWT / Auth — MUST be set via JWT_SECRET env var in production
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60 * 24 * 7  # 7 days

    # Application-layer encryption key for secrets at rest (GitHub OAuth tokens,
    # API keys). 32-byte url-safe base64 Fernet key. REQUIRED in production.
    # Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    encryption_key: str = ""

    @property
    def is_dev(self) -> bool:
        return self.env.lower() in {"dev", "test", "local", "development"}

    def validate_secrets(self) -> None:
        """Fail closed: refuse to boot with empty/weak secrets outside dev.

        Called at application startup (and importable by tooling). Raises
        RuntimeError listing every misconfigured secret so the process exits
        rather than silently running with a forgeable JWT signing key.
        """
        if self.is_dev:
            return
        problems: List[str] = []
        if self.jwt_secret.strip().lower() in _KNOWN_WEAK_SECRETS or len(self.jwt_secret) < 32:
            problems.append(
                "JWT_SECRET is empty, a known dev default, or shorter than 32 chars"
            )
        if self.minio_secret_key.strip().lower() in _KNOWN_WEAK_SECRETS:
            problems.append("MINIO_SECRET_KEY is empty or a known dev default")
        if not self.encryption_key.strip():
            problems.append(
                "ENCRYPTION_KEY is not set — secrets-at-rest (GitHub tokens/API keys) "
                "cannot be encrypted. Generate one with cryptography.fernet.Fernet."
            )
        if problems:
            raise RuntimeError(
                "Refusing to start with insecure configuration (VEXIS_ENV="
                f"{self.env!r}):\n  - " + "\n  - ".join(problems)
                + "\nSet strong values via environment variables, or set VEXIS_ENV=dev "
                "for local development only."
            )


settings = Settings()

# Allow an explicit opt-in for the strict guard even in tooling contexts.
if os.environ.get("VEXIS_VALIDATE_SECRETS_ON_IMPORT", "").lower() == "true":
    settings.validate_secrets()
