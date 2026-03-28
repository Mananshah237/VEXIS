"""
Authentication bypass detector (CWE-287).

Pattern-based: detects route handlers that access sensitive data without auth decorators,
and timing-attack-vulnerable token comparisons.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
import structlog

log = structlog.get_logger()

# Decorators that indicate authentication is enforced
_AUTH_DECORATORS = [
    "@login_required",
    "@require_login",
    "@jwt_required",
    "@token_required",
    "@auth_required",
    "@authenticated",
    "current_user",
    "get_current_user",
]

# Patterns that indicate route definition
_ROUTE_PATTERN = re.compile(r'@\w+\.route\s*\(', re.IGNORECASE)

# Patterns that indicate access to sensitive data
_SENSITIVE_PATTERNS = [
    re.compile(r'db\.execute\s*\(', re.IGNORECASE),
    re.compile(r'SELECT.*FROM\s+users', re.IGNORECASE),
    re.compile(r'SELECT.*FROM\s+admin', re.IGNORECASE),
    re.compile(r'SELECT\s+\*', re.IGNORECASE),
    re.compile(r'password', re.IGNORECASE),
    re.compile(r'secret', re.IGNORECASE),
    re.compile(r'admin', re.IGNORECASE),
]

# Patterns that indicate unsafe token comparison (timing attack)
_TIMING_VULN_PATTERN = re.compile(r'(token|key|secret|password)\s*==\s*', re.IGNORECASE)
_SAFE_COMPARE_PATTERN = re.compile(r'hmac\.compare_digest|secrets\.compare_digest', re.IGNORECASE)

# Patterns for role check from user-controlled header/cookie
_CLIENT_ROLE_PATTERN = re.compile(
    r'(request\.(headers|cookies|args|form).*(?:role|admin|is_admin|permission))',
    re.IGNORECASE,
)


@dataclass
class AuthFinding:
    file: str
    line: int
    code: str
    vuln_type: str
    description: str


def detect_auth_issues(parsed_files: list) -> list[AuthFinding]:
    """Detect authentication/authorization issues."""
    findings = []
    for pf in parsed_files:
        lines = pf.source.splitlines()
        for i, line in enumerate(lines):
            # Timing-attack vulnerable comparisons
            if _TIMING_VULN_PATTERN.search(line) and not _SAFE_COMPARE_PATTERN.search(pf.source):
                findings.append(AuthFinding(
                    file=pf.path,
                    line=i + 1,
                    code=line.strip(),
                    vuln_type="timing_attack",
                    description=f"Token compared with == (vulnerable to timing attack) — use hmac.compare_digest. CWE-287",
                ))

            # Client-controlled role/permission check
            if _CLIENT_ROLE_PATTERN.search(line):
                findings.append(AuthFinding(
                    file=pf.path,
                    line=i + 1,
                    code=line.strip(),
                    vuln_type="client_controlled_role",
                    description=f"Role/permission read from user-controlled request data — CWE-287",
                ))

            # Route without auth decorator accessing sensitive data
            if _ROUTE_PATTERN.search(line):
                # Check the function body (next 20 lines)
                has_auth = False
                has_sensitive = False
                window_end = min(len(lines), i + 20)
                for j in range(i, window_end):
                    body_line = lines[j]
                    if any(auth in body_line for auth in _AUTH_DECORATORS):
                        has_auth = True
                        break
                    if any(pat.search(body_line) for pat in _SENSITIVE_PATTERNS):
                        has_sensitive = True
                if has_sensitive and not has_auth:
                    findings.append(AuthFinding(
                        file=pf.path,
                        line=i + 1,
                        code=line.strip(),
                        vuln_type="missing_auth",
                        description=f"Route accesses sensitive data without authentication decorator — CWE-287",
                    ))

    log.debug("auth_analyzer.complete", findings=len(findings))
    return findings
