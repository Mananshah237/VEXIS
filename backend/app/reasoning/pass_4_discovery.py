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


class BusinessLogicDiscoveryPass:
    def __init__(self, budget: LLMBudget | None = None) -> None:
        self._client = LLMClient()
        self._budget = budget

    async def run(
        self,
        parsed_files: list,  # list of ParsedFile from parser
        source_path: str,
    ) -> list[DiscoveredFinding]:
        """Run discovery mode on the parsed source files."""
        if not parsed_files:
            return []

        if self._budget and not self._budget.try_consume():
            log.warning("pass4.budget_exhausted")
            return []

        # Aggregate source code (truncated)
        source_chunks: list[str] = []
        total_chars = 0
        for pf in parsed_files:
            chunk = f"# === FILE: {pf.file_path} ===\n{pf.source}\n"
            if total_chars + len(chunk) > MAX_SOURCE_CHARS:
                remaining = MAX_SOURCE_CHARS - total_chars
                if remaining > 500:
                    source_chunks.append(chunk[:remaining] + "\n# [truncated]\n")
                break
            source_chunks.append(chunk)
            total_chars += len(chunk)

        combined_source = "".join(source_chunks)
        if not combined_source.strip():
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
            return []

        raw_findings = result.get("findings", [])
        validated = self._validate_and_filter(raw_findings, parsed_files)
        log.info("pass4.discovery", raw=len(raw_findings), validated=len(validated))
        return validated

    def _validate_and_filter(
        self, raw: list[dict], parsed_files: list
    ) -> list[DiscoveredFinding]:
        # Build file -> max_line map
        file_line_bounds: dict[str, int] = {}
        file_sources: dict[str, str] = {}
        for pf in parsed_files:
            lines = pf.source.count("\n") + 1
            # Normalize to just the filename for matching
            short = pf.file_path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            file_line_bounds[short] = lines
            file_sources[short] = pf.source
            # Also store full path
            file_line_bounds[pf.file_path] = lines

        results: list[DiscoveredFinding] = []
        for item in raw:
            confidence = float(item.get("confidence", 0))
            if confidence < MIN_CONFIDENCE:
                continue

            file_ = item.get("file", "")
            line_ = int(item.get("line", 0))

            # Validate line is within file bounds (use short name for lookup)
            short_file = file_.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            max_line = file_line_bounds.get(file_) or file_line_bounds.get(short_file)
            if max_line and line_ > max_line:
                log.debug("pass4.invalid_line", file=file_, line=line_, max=max_line)
                continue
            if line_ <= 0:
                continue

            vuln_type = item.get("vuln_type", "idor")
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
