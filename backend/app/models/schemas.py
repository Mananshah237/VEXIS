from __future__ import annotations
from datetime import datetime
from typing import Any
import uuid
from pydantic import BaseModel, ConfigDict, field_validator


class ScanConfig(BaseModel):
    vuln_classes: list[str] = ["sqli", "cmdi", "path_traversal"]
    max_llm_calls: int = 50
    confidence_threshold: float = 0.5
    incremental: bool = False  # if True, skip files unchanged since last scan of same source_ref


class ScanCreateRequest(BaseModel):
    source_type: str  # github_url, file_upload, raw_code
    source: str
    language: str | None = None
    config: ScanConfig | None = None


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    source_type: str
    source_ref: str
    status: str
    progress: float
    stats: dict[str, Any]
    error_message: str | None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    user_id: uuid.UUID | None = None


class FindingSummaryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    scan_id: uuid.UUID
    title: str
    severity: str
    confidence: float
    vuln_class: str
    cwe_id: str | None
    owasp_category: str | None
    source_file: str
    source_line: int
    source_code: str | None
    sink_file: str
    sink_line: int
    sink_code: str | None
    taint_path: dict[str, Any]
    attack_flow: dict[str, Any]
    poc: dict[str, Any] | None
    llm_reasoning: str | None
    taint_confidence: float | None
    llm_confidence: float | None
    triage_status: str
    created_at: datetime


class FindingDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    scan_id: uuid.UUID
    title: str
    severity: str
    confidence: float
    vuln_class: str
    cwe_id: str | None
    owasp_category: str | None
    mitre_technique: str | None
    description: str
    source_file: str
    source_line: int
    source_code: str | None
    sink_file: str
    sink_line: int
    sink_code: str | None
    taint_path: dict[str, Any]
    attack_flow: dict[str, Any]
    poc: dict[str, Any] | None
    llm_reasoning: str | None
    llm_confidence: float | None
    taint_confidence: float | None
    remediation: dict[str, Any] | None
    triage_status: str
    created_at: datetime


_ALLOWED_TRIAGE_STATUSES = {"true_positive", "false_positive", "accepted_risk"}


class TriageRequest(BaseModel):
    status: str  # true_positive, false_positive, accepted_risk
    notes: str | None = None

    @field_validator("status")
    @classmethod
    def status_must_be_valid(cls, v: str) -> str:
        if v not in _ALLOWED_TRIAGE_STATUSES:
            raise ValueError(f"status must be one of: {', '.join(sorted(_ALLOWED_TRIAGE_STATUSES))}")
        return v

    @field_validator("notes")
    @classmethod
    def notes_length(cls, v: str | None) -> str | None:
        if v is not None and len(v) > 2000:
            raise ValueError("notes must be 2000 characters or fewer")
        return v
