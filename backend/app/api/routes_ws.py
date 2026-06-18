"""WebSocket endpoints streaming live trace/analysis events from Redis pub/sub."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..config import settings
from ..events import get_async_client
from ..logging_config import get_logger

logger = get_logger("apeiron.api.ws")
router = APIRouter(tags=["websocket"])


async def _relay(websocket: WebSocket, channel: str) -> None:
    await websocket.accept()
    client = get_async_client()
    pubsub = client.pubsub()
    await pubsub.subscribe(channel)
    try:
        await websocket.send_json({"type": "connected", "channel": channel})
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message is not None and message.get("type") == "message":
                await websocket.send_text(message["data"])
            else:
                # Keep the connection responsive / detect disconnects.
                await asyncio.sleep(0.05)
    except WebSocketDisconnect:
        pass
    except Exception as exc:  # pragma: no cover
        logger.warning("ws relay error on %s: %s", channel, exc)
    finally:
        try:
            await pubsub.unsubscribe(channel)
            await pubsub.aclose()
            await client.aclose()
        except Exception:
            pass


@router.websocket("/ws/trace/{sample_id}")
async def ws_trace(websocket: WebSocket, sample_id: str) -> None:
    await _relay(websocket, settings.trace_channel(sample_id))


@router.websocket("/ws/events")
async def ws_events(websocket: WebSocket) -> None:
    await _relay(websocket, settings.events_channel)
