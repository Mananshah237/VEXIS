"""initial schema (users, scans, findings)

Generated from the SQLAlchemy models as the baseline migration. Prior to this,
schema was created at runtime via Base.metadata.create_all + ad-hoc ALTER TABLE
statements in main.py, which left no rollback path. This migration captures the
full current schema so deployments have real, reversible migration history.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-06-18

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("github_id", sa.String(length=50), nullable=False),
        sa.Column("github_login", sa.String(length=100), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=True),
        sa.Column("avatar_url", sa.Text(), nullable=True),
        # API keys are stored as SHA-256 hashes (64 hex chars); width allows headroom.
        sa.Column("api_key", sa.String(length=128), nullable=True),
        # GitHub OAuth token is stored ENCRYPTED at rest (Fernet ciphertext).
        sa.Column("github_token", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("github_id", name="uq_users_github_id"),
        sa.UniqueConstraint("api_key", name="uq_users_api_key"),
    )

    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("source_type", sa.String(length=50), nullable=False),
        sa.Column("source_ref", sa.Text(), nullable=False),
        sa.Column("language", sa.String(length=50), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=True),
        sa.Column("progress", sa.Float(), nullable=True),
        sa.Column("config", sa.JSON(), nullable=True),
        sa.Column("stats", sa.JSON(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_index("ix_scans_user_id", "scans", ["user_id"])

    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("vuln_class", sa.String(length=50), nullable=False),
        sa.Column("cwe_id", sa.String(length=20), nullable=True),
        sa.Column("owasp_category", sa.Text(), nullable=True),
        sa.Column("mitre_technique", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("source_file", sa.Text(), nullable=False),
        sa.Column("source_line", sa.Integer(), nullable=False),
        sa.Column("source_code", sa.Text(), nullable=True),
        sa.Column("sink_file", sa.Text(), nullable=False),
        sa.Column("sink_line", sa.Integer(), nullable=False),
        sa.Column("sink_code", sa.Text(), nullable=True),
        sa.Column("taint_path", sa.JSON(), nullable=False),
        sa.Column("attack_flow", sa.JSON(), nullable=False),
        sa.Column("poc", sa.JSON(), nullable=True),
        sa.Column("llm_reasoning", sa.Text(), nullable=True),
        sa.Column("llm_confidence", sa.Float(), nullable=True),
        sa.Column("taint_confidence", sa.Float(), nullable=True),
        sa.Column("remediation", sa.JSON(), nullable=True),
        sa.Column("chain_data", sa.JSON(), nullable=True),
        sa.Column("exploit_script", sa.Text(), nullable=True),
        sa.Column("autofix", sa.JSON(), nullable=True),
        sa.Column("triage_status", sa.String(length=30), nullable=True),
        sa.Column("triage_notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_scans_user_id", table_name="scans")
    op.drop_table("scans")
    op.drop_table("users")
