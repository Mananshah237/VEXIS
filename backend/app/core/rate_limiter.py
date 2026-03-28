"""Redis-based rate limiting for scan creation."""
from __future__ import annotations
from datetime import date

import structlog

log = structlog.get_logger()

FREE_TIER_DAILY_LIMIT = 3


async def check_rate_limit(user_id: str) -> tuple[bool, int]:
    """
    Check if user has exceeded daily scan limit.
    Returns (allowed: bool, remaining: int).
    Anonymous users (user_id=None) are always allowed (for backwards compat).
    """
    if not user_id:
        return True, FREE_TIER_DAILY_LIMIT

    try:
        import redis.asyncio as aioredis
        import os
        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        r = aioredis.from_url(redis_url)
        today = date.today().isoformat()
        key = f"rate:{user_id}:{today}"
        count = await r.incr(key)
        if count == 1:
            await r.expire(key, 86400)  # 24h TTL
        await r.aclose()
        remaining = max(0, FREE_TIER_DAILY_LIMIT - count)
        allowed = count <= FREE_TIER_DAILY_LIMIT
        return allowed, remaining
    except Exception as e:
        log.warning("rate_limit.redis_error", error=str(e))
        return True, FREE_TIER_DAILY_LIMIT  # allow on Redis error
