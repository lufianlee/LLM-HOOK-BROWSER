from __future__ import annotations

import asyncio
import json
import logging
from urllib.parse import urlparse

from mitmproxy import http

logger = logging.getLogger("proxy.interceptor")

_api_base: str = ""
_target_domains: set[str] = set()
_event_queue: asyncio.Queue | None = None


def configure_interceptor(
    api_base: str,
    target_domains: list[str],
    event_queue: asyncio.Queue,
) -> None:
    global _api_base, _target_domains, _event_queue
    _api_base = api_base.rstrip("/")
    _target_domains = {d.lower().strip() for d in target_domains}
    _event_queue = event_queue


def _matches_target(host: str) -> bool:
    host = host.lower().split(":")[0]
    if not _target_domains:
        return True
    return any(host == d or host.endswith(f".{d}") for d in _target_domains)


def _has_meaningful_data(flow: http.HTTPFlow) -> bool:
    req = flow.request
    if req.method in ("POST", "PUT", "DELETE", "PATCH"):
        return True
    if req.query:
        return True
    return False


def _safe_decode(content: bytes | None, limit: int = 50_000) -> str:
    if not content:
        return ""
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        return "<binary>"
    if len(text) > limit:
        return text[:limit] + f"... [truncated, total {len(text)} chars]"
    return text


def _headers_to_dict(headers) -> dict:
    result = {}
    for k, v in headers.items():
        result[k] = v
    return result


class SecurityInterceptor:
    def response(self, flow: http.HTTPFlow) -> None:
        if not _matches_target(flow.request.host):
            return
        if not _has_meaningful_data(flow):
            return

        parsed = urlparse(flow.request.url)
        payload = {
            "method": flow.request.method,
            "url": flow.request.url,
            "host": flow.request.host,
            "path": parsed.path,
            "query_params": parsed.query or "",
            "request_headers": json.dumps(_headers_to_dict(flow.request.headers)),
            "request_body": _safe_decode(flow.request.content),
            "content_type": flow.request.headers.get("content-type", ""),
            "status_code": flow.response.status_code if flow.response else None,
            "response_headers": json.dumps(
                _headers_to_dict(flow.response.headers) if flow.response else {}
            ),
            "response_body": _safe_decode(
                flow.response.content if flow.response else None
            ),
        }

        if _event_queue:
            try:
                _event_queue.put_nowait(payload)
            except asyncio.QueueFull:
                logger.warning("Event queue full, dropping request %s %s", payload["method"], payload["url"])

        logger.info("Captured: %s %s -> %s", payload["method"], payload["url"], payload.get("status_code"))


addons = [SecurityInterceptor()]
