from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from collections import OrderedDict
from urllib.parse import quote

import httpx

import anthropic

from app.config import settings

logger = logging.getLogger("analyzer.llm_client")


def _has_bearer_token() -> bool:
    return bool(os.environ.get("AWS_BEARER_TOKEN_BEDROCK"))


def _build_client() -> anthropic.AsyncAnthropic | anthropic.AsyncAnthropicBedrock | None:
    if _has_bearer_token():
        return None

    if settings.llm_provider == "bedrock":
        kwargs = {"aws_region": settings.aws_region}
        if settings.aws_access_key_id:
            kwargs["aws_access_key"] = settings.aws_access_key_id
            kwargs["aws_secret_key"] = settings.aws_secret_access_key
        if settings.aws_session_token:
            kwargs["aws_session_token"] = settings.aws_session_token
        return anthropic.AsyncAnthropicBedrock(**kwargs)

    return anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)


def _model_id() -> str:
    if settings.llm_provider == "bedrock":
        return settings.bedrock_model_id
    return settings.anthropic_model


_client: anthropic.AsyncAnthropic | anthropic.AsyncAnthropicBedrock | None = None
_client_initialized = False


def get_client():
    global _client, _client_initialized
    if not _client_initialized:
        _client = _build_client()
        _client_initialized = True
    return _client


async def _bearer_invoke(system: str, user_message: str, max_tokens: int = 4096) -> str:
    token = os.environ["AWS_BEARER_TOKEN_BEDROCK"]
    region = os.environ.get("AWS_REGION", "us-east-1")
    model_id = settings.bedrock_model_id

    url = (
        f"https://bedrock-runtime.{region}.amazonaws.com"
        f"/model/{quote(model_id, safe='')}/invoke"
    )

    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": user_message}],
    }

    async with httpx.AsyncClient(timeout=120.0) as http:
        resp = await http.post(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            json=body,
        )
        resp.raise_for_status()

    data = resp.json()
    return data["content"][0]["text"]


async def ask_llm(system: str, user_message: str, max_tokens: int = 4096) -> str:
    if _has_bearer_token():
        return await _bearer_invoke(system, user_message, max_tokens)

    client = get_client()
    response = await client.messages.create(
        model=_model_id(),
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user_message}],
    )
    return response.content[0].text


def _parse_llm_json(raw: str) -> dict | list:
    start = raw.find("[") if raw.find("[") < raw.find("{") or raw.find("{") == -1 else raw.find("{")
    end = max(raw.rfind("]"), raw.rfind("}"))
    if start == -1 or end == -1:
        logger.error("Failed to parse LLM JSON response: %s", raw[:200])
        return {}
    return json.loads(raw[start : end + 1])


# --- Single-flight LRU cache -------------------------------------------------
# Browsing fires many identical requests (polling, static endpoints, retries).
# Analysing byte-identical (system, user_message) inputs always yields the same
# result, so we memoise the raw LLM response. The in-flight map additionally
# collapses concurrent duplicates: the second caller awaits the first's call
# instead of issuing its own, preventing a thundering herd of identical calls.

_cache: "OrderedDict[str, str]" = OrderedDict()
_inflight: dict[str, asyncio.Future] = {}


def _cache_key(system: str, user_message: str, max_tokens: int) -> str:
    h = hashlib.sha256()
    h.update(_model_id().encode())
    h.update(b"\x00")
    h.update(str(max_tokens).encode())
    h.update(b"\x00")
    h.update(system.encode())
    h.update(b"\x00")
    h.update(user_message.encode())
    return h.hexdigest()


async def ask_llm_json(system: str, user_message: str, max_tokens: int = 4096) -> dict | list:
    if not settings.llm_cache_enabled:
        return _parse_llm_json(await ask_llm(system, user_message, max_tokens))

    key = _cache_key(system, user_message, max_tokens)

    cached = _cache.get(key)
    if cached is not None:
        _cache.move_to_end(key)
        logger.info("LLM cache hit (%s)", key[:12])
        return _parse_llm_json(cached)

    inflight = _inflight.get(key)
    if inflight is not None:
        raw = await inflight
        return _parse_llm_json(raw)

    loop = asyncio.get_event_loop()
    fut: asyncio.Future = loop.create_future()
    _inflight[key] = fut
    try:
        raw = await ask_llm(system, user_message, max_tokens)
    except Exception as exc:
        _inflight.pop(key, None)
        if not fut.done():
            fut.set_exception(exc)
        raise
    else:
        _inflight.pop(key, None)
        if not fut.done():
            fut.set_result(raw)
        _cache[key] = raw
        _cache.move_to_end(key)
        while len(_cache) > settings.llm_cache_size:
            _cache.popitem(last=False)
        return _parse_llm_json(raw)
