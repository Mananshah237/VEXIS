"""
WebSocket endpoint for real-time scan progress.
Dual-mode: in-memory manager (BackgroundTask) + Redis pubsub (Celery workers).
"""
from __future__ import annotations
from typing import Dict, List
import asyncio
import json
import os

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import structlog

log = structlog.get_logger()

router = APIRouter()

_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


class ScanConnectionManager:
    def __init__(self) -> None:
        self._connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, scan_id: str, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.setdefault(scan_id, []).append(ws)
        log.debug("ws.connected", scan_id=scan_id, total=len(self._connections[scan_id]))

    def disconnect(self, scan_id: str, ws: WebSocket) -> None:
        conns = self._connections.get(scan_id, [])
        if ws in conns:
            conns.remove(ws)
        if not conns:
            self._connections.pop(scan_id, None)
        log.debug("ws.disconnected", scan_id=scan_id)

    async def broadcast(self, scan_id: str, message: dict) -> None:
        """Send a JSON message to all clients watching this scan."""
        conns = list(self._connections.get(scan_id, []))
        if not conns:
            return
        dead: list[WebSocket] = []
        for ws in conns:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(scan_id, ws)


# Singleton — imported by orchestrator to broadcast progress
manager = ScanConnectionManager()


async def _redis_subscriber(scan_id: str, ws: WebSocket) -> None:
    """Subscribe to Redis pubsub for this scan and forward messages to WebSocket."""
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(_REDIS_URL)
        pubsub = r.pubsub()
        await pubsub.subscribe(f"scan:{scan_id}:progress")
        async for msg in pubsub.listen():
            if msg["type"] == "message":
                try:
                    data = json.loads(msg["data"])
                    await ws.send_json(data)
                    # Stop listening after scan completes
                    if data.get("phase") in ("complete", "failed"):
                        break
                except Exception:
                    break
        await pubsub.unsubscribe()
        await r.aclose()
    except Exception as e:
        log.debug("redis.subscriber_failed", scan_id=scan_id, error=str(e))


@router.websocket("/ws/scan/{scan_id}")
async def scan_websocket(ws: WebSocket, scan_id: str) -> None:
    await manager.connect(scan_id, ws)
    redis_task = asyncio.create_task(_redis_subscriber(scan_id, ws))
    try:
        # Run Redis subscriber and keep-alive in parallel
        while True:
            try:
                await asyncio.wait_for(ws.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                pass  # keep alive
    except WebSocketDisconnect:
        pass
    finally:
        try:
            redis_task.cancel()
        except Exception:
            pass
        manager.disconnect(scan_id, ws)
