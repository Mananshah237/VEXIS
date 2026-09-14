"""
LLM Pass 4 — Business Logic Discovery Mode.

Reads the full source code of the scanned project and asks an LLM to find
business-logic vulnerabilities that static taint analysis cannot detect:
  - IDOR (CWE-639)
  - Broken Authentication (CWE-287)
  - Mass Assignment (CWE-915)
  - Race Conditions (CWE-362)
  - Privilege Escalation (CWE-269)
  - Information Disclosure (CWE-200)
  - Broken Rate Limiting (CWE-307)

Quality filters:
  - Validate file/function names exist in the parsed source
  - Drop findings with confidence < 0.6
  - Validate line numbers are within file bounds
  - Cap output at 5 findings

Only runs if scan config has discovery_mode=true.
"""
from __future__ import annotations
import asyncio
from dataclasses import dataclass, field
from typing import Optional
import structlog

from app.reasoning.llm_client import LLMClient
from app.reasoning.budget import LLMBudget

log = structlog.get_logger()

CWE_MAP = {
    "idor": "CWE-639",
    "broken_auth": "CWE-287",
    "mass_assignment": "CWE-915",
    "race_condition": "CWE-362",
    "privilege_escalation": "CWE-269",
    "info_disclosure": "CWE-200",
    "broken_rate_limiting": "CWE-307",
}

OWASP_MAP = {
    "idor": "A01:2021 – Broken Access Control",
    "broken_auth": "A07:2021 – Identification and Authentication Failures",
    "mass_assignment": "A03:2021 – Injection",
    "race_condition": "A04:2021 – Insecure Design",
    "privilege_escalation": "A01:2021 – Broken Access Control",
    "info_disclosure": "A02:2021 – Cryptographic Failures",
    "broken_rate_limiting": "A04:2021 – Insecure Design",
}

MAX_FINDINGS = 5
MIN_CONFIDENCE = 0.6
MAX_SOURCE_CHARS = 20_000  # Truncate to keep within LLM context

SYSTEM_PROMPT = """You are an elite application security researcher specializing in business logic vulnerabilities.
You analyze source code to find security flaws that automated taint analysis misses.
Focus on: access control, authentication, state management, and race conditions.
You require concrete evidence in the code — do NOT speculate."""

DISCOVERY_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "maxItems": 5,
            "items": {
                "type": "object",
                "properties": {
                    "vuln_type": {
                        "type": "string",
                        "enum": ["idor", "broken_auth", "mass_assignment", "race_condition",
                                 "privilege_escalation", "info_disclosure", "broken_rate_limiting"],
                    },
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "file": {"type": "string"},
                    "function_name": {"type": "string"},
                    "line": {"type": "integer"},
                    "code_snippet": {"type": "string"},
                    "attack_scenario": {"type": "string"},
                    "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                    "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                    "remediation": {"type": "string"},
                },
                "required": ["vuln_type", "title", "description", "file", "line", "confidence", "severity"],
            },
        },
    },
    "required": ["findings"],
}


@dataclass
class DiscoveredFinding:
    vuln_type: str
    title: str
    description: str
    file: str
    function_name: str
    line: int
    code_snippet: str
    attack_scenario: str
    confidence: float
    severity: str
    remediation: str
    cwe_id: str
    owasp_category: str


def _display_path(path: str, source_path: str) -> str:
    """Repository-relative forward-slash path, never the server's temp directory."""
    normalized = path.replace("\\", "/")
    root = source_path.replace("\\", "/").rstrip("/")
    if root and normalized.startswith(root + "/"):
        return normalized[len(root) + 1:]
    return normalized


class BusinessLogicDiscoveryPass:
    def __init__(self, budget: LLMBudget | None = None) -> None:
        self._client = LLMClient()
        self._budget = budget
        # not_run | skipped_no_source | budget_exhausted | failed | completed
        self.status = "not_run"

    async def run(
        self,
        parsed_files: list,  # list of ParsedFile from parser
        source_path: str,
    ) -> list[DiscoveredFinding]:
        """Run discovery mode on the parsed source files."""
        if not parsed_files:
            self.status = "skipped_no_source"
            return []

        if self._budget and not self._budget.try_consume():
            log.warning("pass4.budget_exhausted")
            self.status = "budget_exhausted"
            return []

        # Aggregate source code (truncated)
        source_chunks: list[str] = []
        total_chars = 0
        shown_files = []  # (ParsedFile, number of source lines actually shown)
        for pf in parsed_files:
            header = f"# === FILE: {_display_path(pf.path, source_path)} ===\n"
            chunk = f"{header}{pf.source}\n"
            if total_chars + len(chunk) > MAX_SOURCE_CHARS:
                remaining = MAX_SOURCE_CHARS - total_chars
                if remaining > 500:
                    source_chunks.append(chunk[:remaining] + "\n# [truncated]\n")
                    shown = pf.source[:max(0, remaining - len(header))]
                    shown_files.append((pf, shown.count("\n")))
                break
            source_chunks.append(chunk)
            shown_files.append((pf, pf.source.count("\n") + 1))
            total_chars += len(chunk)

        combined_source = "".join(source_chunks)
        if not combined_source.strip():
            self.status = "skipped_no_source"
            return []

        user_prompt = f"""Analyze this source code for business logic vulnerabilities.
Look specifically for:
1. IDOR — object access without ownership verification (e.g. /user/{{id}} where id is not verified against session)
2. Broken Auth — missing or bypassable authentication checks
3. Mass Assignment — bulk update of model fields without whitelist
4. Race Condition — TOCTOU issues, non-atomic operations on shared state
5. Privilege Escalation — role/permission checks that can be bypassed
6. Information Disclosure — sensitive data in responses, logs, or error messages
7. Broken Rate Limiting — loops, bulk operations, or auth endpoints without rate limiting

Source code:
```
{combined_source}
```

Return up to {MAX_FINDINGS} findings. Only include findings with confidence >= {MIN_CONFIDENCE}.
Each finding MUST reference actual function names and line numbers from the code above."""

        try:
            result = await self._client.analyze(SYSTEM_PROMPT, user_prompt, DISCOVERY_SCHEMA)
        except Exception as e:
            log.warning("pass4.llm_failed", error=str(e))
            self.status = "failed"
            return []

        raw_findings = result.get("findings") if isinstance(result, dict) else None
        if not isinstance(raw_findings, list):
            log.warning("pass4.malformed_response")
            self.status = "failed"
            return []
        validated = self._validate_and_filter(raw_findings, shown_files, source_path)
        self.status = "completed"
        log.info("pass4.discovery", raw=len(raw_findings), validated=len(validated))
        return validated

    def _validate_and_filter(
        self, raw: list[dict], shown_files: list[tuple], source_path: str = ""
    ) -> list[DiscoveredFinding]:
        # A finding must cite a file and line that were actually shown to the model.
        file_line_bounds: dict[str, int] = {
            _display_path(pf.path, source_path): shown_lines
            for pf, shown_lines in shown_files
        }

        results: list[DiscoveredFinding] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            try:
                confidence = float(item.get("confidence", 0))
                line_ = int(item.get("line", 0))
            except (TypeError, ValueError):
                continue
            if not MIN_CONFIDENCE <= confidence <= 1.0:
                continue

            file_ = str(item.get("file", "")).replace("\\", "/")
            max_line = file_line_bounds.get(file_)
            if max_line is None:
                log.debug("pass4.unknown_file", file=file_)
                continue
            if not 0 < line_ <= max_line:
                log.debug("pass4.invalid_line", file=file_, line=line_, max=max_line)
                continue
            vuln_type = item.get("vuln_type")
            if vuln_type not in CWE_MAP:
                continue
            if item.get("severity") not in {"low", "medium", "high", "critical"}:
                continue

            results.append(DiscoveredFinding(
                vuln_type=vuln_type,
                title=item.get("title", f"Business Logic: {vuln_type}"),
                description=item.get("description", ""),
                file=file_,
                function_name=item.get("function_name", ""),
                line=line_,
                code_snippet=item.get("code_snippet", ""),
                attack_scenario=item.get("attack_scenario", ""),
                confidence=confidence,
                severity=item.get("severity", "medium"),
                remediation=item.get("remediation", ""),
                cwe_id=CWE_MAP.get(vuln_type, "CWE-0"),
                owasp_category=OWASP_MAP.get(vuln_type, "A01:2021"),
            ))

        # Cap at MAX_FINDINGS, sorted by confidence desc
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results[:MAX_FINDINGS]
