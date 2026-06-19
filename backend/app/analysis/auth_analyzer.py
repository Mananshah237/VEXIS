"""
Authentication / authorization bypass detector (CWE-287).

Heuristic, pattern-based. Detects three issue classes:
  - missing_auth          route handler touches sensitive data with no auth guard
  - timing_attack         token/secret compared with == instead of constant-time
  - client_controlled_role role/permission decision read from request data

Auth-guard recognition spans Flask and FastAPI so routes that ARE protected are not
flagged: decorators (@login_required and friends), Flask-Login/JWT identities, Flask
`before_request` gates, and FastAPI `Depends(...)`/`Security(...)` dependencies —
including router/app-level default dependencies that protect every route in a file.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
import structlog

log = structlog.get_logger()

# Substrings that indicate authentication/authorization on or around a route.
_AUTH_MARKERS = [
    # decorator / wrapper guards (framework + common custom names)
    "login_required", "require_login", "requires_login", "jwt_required",
    "token_required", "auth_required", "requires_auth", "require_auth",
    "authenticated", "admin_required", "requires_admin", "require_admin",
    "roles_required", "role_required", "require_role", "requires_role",
    "permission_required", "permissions_required", "require_permission",
    "requires_permission", "require_scope", "requires_scope",
    "require_api_key", "api_key_required", "protected",
    # identity objects / helpers (Flask-Login, Flask-JWT, FastAPI users)
    "current_user", "get_current_user", "current_identity",
    # in-handler verification / session checks
    "verify_jwt_in_request", "verify_jwt", "verify_token", "check_auth",
    "check_permission", "authorize(", "authenticate(",
    "session[", "session.get(", "g.user", "request.user", "request.state.user",
]

# FastAPI dependency-injected auth: Depends(...)/Security(...) whose target name looks
# auth-related. Generic deps like Depends(get_db) / Depends(get_session) deliberately
# do NOT count, so unauthenticated endpoints that only inject a DB handle still flag.
_AUTH_DEP = re.compile(
    r'(?:Depends|Security)\s*\(\s*[\'"]?[\w.]*?'
    r'(current[_-]?user|authenticate|authoriz|\bauth|verify|require|login|jwt|'
    r'token|api[_-]?key|permission|\brole|scope|oauth|bearer|principal|guard)',
    re.IGNORECASE,
)

# Route definitions — Flask (.route) and FastAPI/Starlette (.get/.post/...).
_ROUTE_PATTERN = re.compile(
    r'@\w+\.(?:route|get|post|put|patch|delete|head|options)\s*\(', re.IGNORECASE)

# Sensitive data access inside a handler.
_SENSITIVE_PATTERNS = [
    re.compile(r'\w+\.execute\s*\(', re.IGNORECASE),                  # db/cursor/conn/session.execute(
    re.compile(r'SELECT\b.*\bFROM\b', re.IGNORECASE | re.DOTALL),     # raw SQL
    re.compile(r'SELECT\s+\*', re.IGNORECASE),
    re.compile(r'\bFROM\s+(?:users|admin|accounts|credentials)\b', re.IGNORECASE),
    re.compile(r'(?:password|secret|api[_-]?key|private_key)\s*[=\[(.:]', re.IGNORECASE),
]

# Whole-file auth gates that protect every route in the file.
_FILE_GUARD_DEP = re.compile(
    r'(?:FastAPI|APIRouter)\s*\([^)]*dependencies\s*=\s*\[[^\]]*'
    r'(?:Depends|Security)\s*\([^)]*'
    r'(?:auth|current[_-]?user|verify|require|login|jwt|token|permission|role|scope|security|oauth)',
    re.IGNORECASE | re.DOTALL,
)
_BEFORE_REQUEST = re.compile(r'before_request', re.IGNORECASE)
_BEFORE_REQUEST_AUTH = re.compile(
    r'abort\s*\(\s*40[13]\b|unauthorized|current_user|g\.user|verify_(?:jwt|token)|'
    r'authenticate|login|session',
    re.IGNORECASE,
)

# Unsafe token comparison (timing attack)
_TIMING_VULN_PATTERN = re.compile(r'(token|key|secret|password)\s*==\s*', re.IGNORECASE)
_SAFE_COMPARE_PATTERN = re.compile(r'hmac\.compare_digest|secrets\.compare_digest', re.IGNORECASE)

# Role check from user-controlled header/cookie
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


def _line_has_auth(line: str) -> bool:
    """True if the line carries an auth marker (decorator, identity, session check,
    or an auth-flavored FastAPI Depends/Security dependency)."""
    low = line.lower()
    if any(m in low for m in _AUTH_MARKERS):
        return True
    return bool(_AUTH_DEP.search(line))


def _file_has_global_guard(source: str) -> bool:
    """True if the file installs an auth gate that covers every route: a FastAPI
    app/router with auth `dependencies=[...]`, or a Flask `before_request` auth hook."""
    if _FILE_GUARD_DEP.search(source):
        return True
    if _BEFORE_REQUEST.search(source) and _BEFORE_REQUEST_AUTH.search(source):
        return True
    return False


def detect_auth_issues(parsed_files: list) -> list[AuthFinding]:
    """Detect authentication/authorization issues."""
    findings = []
    for pf in parsed_files:
        lines = pf.source.splitlines()
        file_guarded = _file_has_global_guard(pf.source)
        for i, line in enumerate(lines):
            # Timing-attack vulnerable comparisons
            if _TIMING_VULN_PATTERN.search(line) and not _SAFE_COMPARE_PATTERN.search(pf.source):
                findings.append(AuthFinding(
                    file=pf.path,
                    line=i + 1,
                    code=line.strip(),
                    vuln_type="timing_attack",
                    description="Token compared with == (vulnerable to timing attack) — use hmac.compare_digest. CWE-287",
                ))

            # Client-controlled role/permission check
            if _CLIENT_ROLE_PATTERN.search(line):
                findings.append(AuthFinding(
                    file=pf.path,
                    line=i + 1,
                    code=line.strip(),
                    vuln_type="client_controlled_role",
                    description="Role/permission read from user-controlled request data — CWE-287",
                ))

            # Route without an auth guard accessing sensitive data
            if _ROUTE_PATTERN.search(line):
                if file_guarded:
                    continue  # an app/router/before_request guard already protects this route
                has_auth = False
                has_sensitive = False
                window_end = min(len(lines), i + 25)
                for j in range(i, window_end):
                    body_line = lines[j]
                    if j > i and _ROUTE_PATTERN.search(body_line):
                        break  # next handler begins — don't bleed into it
                    if _line_has_auth(body_line):
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
                        description="Route accesses sensitive data without an authentication guard — CWE-287",
                    ))

    log.debug("auth_analyzer.complete", findings=len(findings))
    return findings
