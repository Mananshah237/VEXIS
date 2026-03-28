from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


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


settings = Settings()
