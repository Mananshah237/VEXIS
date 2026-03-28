import re
import tempfile
import asyncio
import structlog

log = structlog.get_logger()

# Allowlist of trusted Git hosting prefixes (HTTPS only, no localhost/internal)
_ALLOWED_PREFIXES = (
    "https://github.com/",
    "https://gitlab.com/",
    "https://bitbucket.org/",
)

# Reject URLs that contain suspicious sequences even after the allowed prefix
_SUSPICIOUS_RE = re.compile(r"[;&|`$<>]|\.\.")


def _validate_repo_url(url: str) -> None:
    """Raise ValueError if the URL is not a safe, allowlisted repository URL.

    Guards against:
    - SSRF to internal networks / metadata endpoints
    - Non-HTTPS transports (file://, ssh://, git://)
    - Path traversal and shell-injection characters in the URL
    """
    if not any(url.startswith(prefix) for prefix in _ALLOWED_PREFIXES):
        raise ValueError(
            f"Repository URL must start with one of: {', '.join(_ALLOWED_PREFIXES)}"
        )
    if _SUSPICIOUS_RE.search(url):
        raise ValueError("Repository URL contains disallowed characters")


async def clone_repo(url: str) -> str:
    """Clone a git repo to a temp directory. Returns path to cloned repo."""
    _validate_repo_url(url)
    tmp_dir = tempfile.mkdtemp(prefix="vexis_scan_")
    log.info("git.clone", url=url, dest=tmp_dir)
    proc = await asyncio.create_subprocess_exec(
        "git", "clone", "--depth=1", "--single-branch", url, tmp_dir,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"Git clone failed: {stderr.decode()}")
    log.info("git.clone.done", dest=tmp_dir)
    return tmp_dir
