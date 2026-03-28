"""
Git clone with local disk cache.

Algorithm:
  1. Validate URL against allowlist (SSRF prevention).
  2. Derive a stable cache key: SHA-256 of the normalized URL.
  3. Check CLONE_CACHE_DIR/<key>/ — if it exists and was modified within
     CACHE_TTL_SECONDS, do a `git fetch --depth=1` to pull latest HEAD,
     then copy the cached tree into a fresh temp dir for the scan.
  4. If cache miss (or fetch fails), do a full `git clone --depth=1` and
     store the result in the cache dir for future hits.

Why copy instead of scanning the cache dir directly?
  Each scan gets its own isolated temp dir so concurrent scans of the
  same repo don't interfere with each other, and scan cleanup (rmtree)
  doesn't corrupt the cache.

Cache TTL is 10 minutes by default. GitHub rate-limits rapid sequential
clones of the same repo, so caching eliminates the 60-80s penalty on
runs 2 and 3 of benchmark sweeps.
"""
import hashlib
import os
import re
import shutil
import tempfile
import asyncio
import time
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

# Where cloned repos are cached between scans
CLONE_CACHE_DIR = os.environ.get("VEXIS_CLONE_CACHE_DIR", "/tmp/vexis_clone_cache")

# How long a cached clone stays valid before we refresh it from remote
CACHE_TTL_SECONDS = int(os.environ.get("VEXIS_CLONE_CACHE_TTL", "600"))  # 10 minutes

# Lock per URL so two concurrent scans of the same repo don't double-clone
_clone_locks: dict[str, asyncio.Lock] = {}
_clone_locks_meta_lock = asyncio.Lock()


def _validate_repo_url(url: str) -> None:
    """Raise ValueError if the URL is not a safe, allowlisted repository URL."""
    if not any(url.startswith(prefix) for prefix in _ALLOWED_PREFIXES):
        raise ValueError(
            f"Repository URL must start with one of: {', '.join(_ALLOWED_PREFIXES)}"
        )
    if _SUSPICIOUS_RE.search(url):
        raise ValueError("Repository URL contains disallowed characters")


def _cache_key(url: str) -> str:
    return hashlib.sha256(url.strip().lower().encode()).hexdigest()


async def _get_url_lock(url: str) -> asyncio.Lock:
    """Return (and create if needed) a per-URL asyncio Lock."""
    key = _cache_key(url)
    async with _clone_locks_meta_lock:
        if key not in _clone_locks:
            _clone_locks[key] = asyncio.Lock()
        return _clone_locks[key]


async def _run_git(*args: str) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        "git", *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    return proc.returncode, stdout.decode(), stderr.decode()


async def clone_repo(url: str) -> str:
    """
    Return path to a fresh temp directory containing the repo.
    Uses a local disk cache to avoid repeated full clones.
    """
    _validate_repo_url(url)

    key = _cache_key(url)
    cache_dir = os.path.join(CLONE_CACHE_DIR, key)
    lock = await _get_url_lock(url)

    async with lock:
        cache_fresh = False

        if os.path.isdir(cache_dir):
            mtime = os.path.getmtime(cache_dir)
            age = time.time() - mtime
            if age < CACHE_TTL_SECONDS:
                # Cache is fresh — try a quick fetch to get latest HEAD
                try:
                    rc, _, err = await asyncio.wait_for(
                        _run_git("-C", cache_dir, "fetch", "--depth=1", "origin"),
                        timeout=20.0,
                    )
                    if rc == 0:
                        # Reset to fetched HEAD
                        await _run_git("-C", cache_dir, "reset", "--hard", "FETCH_HEAD")
                        log.info("git.cache_hit_refreshed", url=url, age_s=int(age))
                        cache_fresh = True
                    else:
                        log.warning("git.cache_fetch_failed", stderr=err[:200])
                except (asyncio.TimeoutError, Exception) as e:
                    log.warning("git.cache_fetch_error", error=str(e))
            else:
                log.info("git.cache_expired", url=url, age_s=int(age))
                shutil.rmtree(cache_dir, ignore_errors=True)

        if not cache_fresh:
            # Full clone into cache dir
            os.makedirs(CLONE_CACHE_DIR, exist_ok=True)
            log.info("git.clone", url=url, cache_dir=cache_dir)
            rc, _, err = await asyncio.wait_for(
                _run_git("clone", "--depth=1", "--single-branch", url, cache_dir),
                timeout=120.0,
            )
            if rc != 0:
                shutil.rmtree(cache_dir, ignore_errors=True)
                raise RuntimeError(f"Git clone failed: {err}")
            log.info("git.clone.done", url=url)

    # Copy cached repo to a fresh temp dir for this scan's exclusive use
    tmp_dir = tempfile.mkdtemp(prefix="vexis_scan_")
    shutil.copytree(cache_dir, tmp_dir, dirs_exist_ok=True)
    log.info("git.cache_copy_done", dest=tmp_dir)
    return tmp_dir
