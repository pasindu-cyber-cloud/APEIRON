"""Redis-backed event bus used to stream live trace events to the GUI.

The analysis worker publishes JSON events to per-sample channels and a global
``apeiron:events`` channel. The API's WebSocket endpoint subscribes and relays
to connected browsers.
"""

from __future__ import annotations

import json
from typing import Any

import redis
import redis.asyncio as aioredis

from .config import settings
from .logging_config import get_logger

logger = get_logger("apeiron.events")

# Synchronous client for the worker (publish only).
_sync_client: redis.Redis | None = None


def _get_sync_client() -> redis.Redis:
    global _sync_client
    if _sync_client is None:
        _sync_client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
    return _sync_client


def publish_event(sample_id: str, event: dict[str, Any]) -> None:
    """Publish an event to both the per-sample channel and global channel.

    Failures never propagate: live streaming is best-effort and must not break
    the analysis pipeline.
    """
    payload = json.dumps({"sample_id": sample_id, **event}, default=str)
    try:
        client = _get_sync_client()
        client.publish(settings.trace_channel(sample_id), payload)
        client.publish(settings.events_channel, payload)
    except Exception as exc:  # pragma: no cover - best effort
        logger.warning("publish_event failed: %s", exc)


def get_async_client() -> aioredis.Redis:
    """Async client for the API WebSocket subscriber."""
    return aioredis.Redis.from_url(settings.redis_url, decode_responses=True)
