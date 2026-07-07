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
    """Persist captured requests as fast as they arrive and hand analysis off
    to a pool of concurrent workers.

    Previously each request was analysed inline: the single ingest loop blocked
    on a multi-second LLM call before pulling the next item, so a burst of
    traffic (a page load fires dozens of requests) backed the capture queue up
    and eventually dropped requests. Splitting persistence from analysis keeps
    capture latency low, and the worker pool lets several LLM calls run
    concurrently instead of strictly one at a time.
    """
    logger.info(
        "Ingester started, auto_analyze=%s, analysis_workers=%d",
        settings.auto_analyze,
        settings.analysis_workers,
    )

    analysis_queue: asyncio.Queue[int] = asyncio.Queue(maxsize=10_000)
    workers: list[asyncio.Task] = []
    if settings.auto_analyze:
        workers = [
            asyncio.create_task(_analysis_worker(analysis_queue, i))
            for i in range(max(1, settings.analysis_workers))
        ]

    try:
        while True:
            payload = await queue.get()
            try:
                await _persist_and_dispatch(payload, analysis_queue)
            except Exception:
                logger.exception("Failed to ingest request")
            finally:
                queue.task_done()
    finally:
        for w in workers:
            w.cancel()


async def _persist_and_dispatch(
    payload: dict,
    analysis_queue: asyncio.Queue[int],
) -> None:
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
        req_id = req.id

    # Broadcast and analysis dispatch happen after the session is released so
    # the DB connection is not held during the (slow) downstream work.
    await broadcast("new_request", out.model_dump())
    logger.info("Ingested request #%d: %s %s", req_id, out.method, out.url)

    if settings.auto_analyze:
        try:
            analysis_queue.put_nowait(req_id)
        except asyncio.QueueFull:
            logger.warning(
                "Analysis queue full, skipping analysis for request #%d", req_id
            )


async def _analysis_worker(analysis_queue: asyncio.Queue[int], worker_id: int) -> None:
    logger.info("Analysis worker %d started", worker_id)
    while True:
        req_id = await analysis_queue.get()
        try:
            from app.schemas import FindingOut

            async with async_session() as session:
                findings = await analyze_single_request(session, req_id)
                finding_dicts = [
                    FindingOut.model_validate(f).model_dump() for f in findings
                ]
            if finding_dicts:
                await broadcast("new_findings", finding_dicts)
        except Exception:
            logger.exception("Analysis failed for request #%d", req_id)
        finally:
            analysis_queue.task_done()
