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

    # Snapshot before awaiting: the subscriber list may mutate (connect /
    # disconnect) while the concurrent sends are in flight.
    targets = list(_subscribers)

    # Send to all subscribers concurrently so one slow client does not delay
    # delivery to the others.
    results = await asyncio.gather(
        *(ws.send_text(message) for ws in targets),
        return_exceptions=True,
    )
    for ws, result in zip(targets, results):
        if isinstance(result, Exception):
            await unsubscribe(ws)
