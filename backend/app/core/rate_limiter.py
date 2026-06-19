"""Redis-based rate limiting for scan creation.

Scan creation now always requires authentication, so every caller is rate
limited by user id. The limiter **fails closed**: if the identifier is missing
or Redis is unavailable we deny the request rather than allow unbounded
(expensive) LLM scans. Set ``VEXIS_RATE_LIMIT_FAIL_OPEN=true`` only for local
development where Redis may be absent.
"""
from __future__ import annotations
from datetime import date
import os

import structlog

log = structlog.get_logger()

FREE_TIER_DAILY_LIMIT = 3


def _fail_open() -> bool:
    return os.environ.get("VEXIS_RATE_LIMIT_FAIL_OPEN", "").lower() == "true"


async def check_rate_limit(identifier: str) -> tuple[bool, int]:
    """Check if the caller has exceeded the daily scan limit.

    ``identifier`` is the authenticated user id (or, for IP-scoped limiting,
    ``ip:<addr>``). Returns ``(allowed, remaining)``.

    Fails CLOSED: a missing identifier or a Redis error denies the request
    unless ``VEXIS_RATE_LIMIT_FAIL_OPEN=true`` (dev escape hatch).
    """
    if not identifier:
        log.warning("rate_limit.no_identifier")
        return _fail_open(), 0

    try:
        import redis.asyncio as aioredis
        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        r = aioredis.from_url(redis_url)
        today = date.today().isoformat()
        key = f"rate:{identifier}:{today}"
        count = await r.incr(key)
        if count == 1:
            await r.expire(key, 86400)  # 24h TTL
        await r.aclose()
        remaining = max(0, FREE_TIER_DAILY_LIMIT - count)
        allowed = count <= FREE_TIER_DAILY_LIMIT
        return allowed, remaining
    except Exception as e:
        log.warning("rate_limit.redis_error", error=str(e), fail_open=_fail_open())
        # Fail CLOSED unless explicitly opted out (dev only).
        return _fail_open(), 0
