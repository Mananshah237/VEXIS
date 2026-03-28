from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import scan, findings, reports, triage, stats, auth, exploit, differential
from app.api.ws import scan_ws
from app.config import settings
from app.database import engine, Base
import structlog

# Ensure all ORM models are imported so Base.metadata.create_all registers every table
import app.models.scan  # noqa: F401
import app.models.finding  # noqa: F401
import app.models.user  # noqa: F401

log = structlog.get_logger()


# Columns added after initial table creation that create_all() won't add to
# existing tables (it only creates missing tables, never alters columns).
# Add new entries here whenever a nullable column is added to a model.
_SCHEMA_MIGRATIONS = [
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS chain_data JSONB",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS exploit_script TEXT",
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("VEXIS starting up", version="0.1.0")
    # Create tables if they don't exist (dev mode; use alembic in prod)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Apply any column additions that create_all won't handle on existing tables
        for stmt in _SCHEMA_MIGRATIONS:
            try:
                await conn.execute(__import__("sqlalchemy").text(stmt))
            except Exception as mig_err:
                log.warning("schema_migration.failed", stmt=stmt, error=str(mig_err))
    from app.core.storage import ensure_buckets
    await ensure_buckets()
    yield
    log.info("VEXIS shutting down")


app = FastAPI(
    title="VEXIS API",
    description="Vulnerability EXploration & Inference System",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "X-Requested-With"],
)

app.include_router(scan.router, prefix="/api/v1", tags=["scans"])
app.include_router(findings.router, prefix="/api/v1", tags=["findings"])
app.include_router(reports.router, prefix="/api/v1", tags=["reports"])
app.include_router(triage.router, prefix="/api/v1", tags=["triage"])
app.include_router(stats.router, prefix="/api/v1", tags=["stats"])
app.include_router(scan_ws.router, tags=["websocket"])
app.include_router(auth.router, prefix="/api/v1", tags=["auth"])
app.include_router(exploit.router, prefix="/api/v1", tags=["exploit"])
app.include_router(differential.router, prefix="/api/v1", tags=["differential"])


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "version": "0.1.0"}
