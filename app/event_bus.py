from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger("event_bus")

_subscribers: list[WebSocket] = []


async def subscribe(ws: WebSocket) -> None:
    _subscribers.append(ws)


async def unsubscribe(ws: WebSocket) -> None:
    if ws in _subscribers:
        _subscribers.remove(ws)


async def broadcast(event_type: str, data: Any) -> None:
    if not _subscribers:
        return
    message = json.dumps({"type": event_type, "data": data}, default=str, ensure_ascii=False)
    disconnected = []
    for ws in _subscribers:
        try:
            await ws.send_text(message)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        await unsubscribe(ws)
