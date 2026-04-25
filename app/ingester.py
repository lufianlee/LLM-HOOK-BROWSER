from __future__ import annotations

import asyncio
import logging

from app.analyzer.engine import analyze_single_request
from app.config import settings
from app.database import async_session
from app.event_bus import broadcast
from app.models import CapturedRequest
from app.schemas import CapturedRequestOut

logger = logging.getLogger("ingester")


async def run_ingester(queue: asyncio.Queue) -> None:
    logger.info("Ingester started, auto_analyze=%s", settings.auto_analyze)
    while True:
        payload = await queue.get()
        try:
            await _ingest(payload)
        except Exception:
            logger.exception("Failed to ingest request")
        finally:
            queue.task_done()


async def _ingest(payload: dict) -> None:
    async with async_session() as session:
        req = CapturedRequest(
            method=payload["method"],
            url=payload["url"],
            host=payload["host"],
            path=payload["path"],
            query_params=payload.get("query_params", ""),
            request_headers=payload.get("request_headers", "{}"),
            request_body=payload.get("request_body", ""),
            content_type=payload.get("content_type", ""),
            status_code=payload.get("status_code"),
            response_headers=payload.get("response_headers", "{}"),
            response_body=payload.get("response_body", ""),
        )
        session.add(req)
        await session.commit()
        await session.refresh(req)

        out = CapturedRequestOut.model_validate(req)
        await broadcast("new_request", out.model_dump())
        logger.info("Ingested request #%d: %s %s", req.id, req.method, req.url)

        if settings.auto_analyze:
            findings = await analyze_single_request(session, req.id)
            if findings:
                from app.schemas import FindingOut
                finding_dicts = [FindingOut.model_validate(f).model_dump() for f in findings]
                await broadcast("new_findings", finding_dicts)
