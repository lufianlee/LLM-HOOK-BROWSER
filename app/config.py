from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel

load_dotenv()


class Settings(BaseModel):
    # LLM provider: "bedrock" (default) or "anthropic"
    llm_provider: str = os.getenv("LLM_PROVIDER", "bedrock")

    # Bedrock settings
    aws_region: str = os.getenv("AWS_REGION", "us-east-1")
    aws_access_key_id: str = os.getenv("AWS_ACCESS_KEY_ID", "")
    aws_secret_access_key: str = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    aws_session_token: str = os.getenv("AWS_SESSION_TOKEN", "")
    bedrock_model_id: str = os.getenv("BEDROCK_MODEL_ID", "us.anthropic.claude-sonnet-4-6-20250514-v1:0")

    # Anthropic direct API (fallback)
    anthropic_api_key: str = os.getenv("ANTHROPIC_API_KEY", "")
    anthropic_model: str = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6-20250514")

    # Proxy
    proxy_port: int = int(os.getenv("PROXY_PORT", "8080"))
    target_domains: list[str] = [
        d.strip() for d in os.getenv("TARGET_DOMAINS", "").split(",") if d.strip()
    ]

    # API
    api_host: str = os.getenv("API_HOST", "127.0.0.1")
    api_port: int = int(os.getenv("API_PORT", "8000"))

    # DB
    db_url: str = os.getenv("DB_URL", f"sqlite+aiosqlite:///{Path(__file__).parent.parent / 'data.db'}")

    # Analysis
    max_history_for_chain: int = int(os.getenv("MAX_HISTORY_FOR_CHAIN", "50"))
    auto_analyze: bool = os.getenv("AUTO_ANALYZE", "true").lower() == "true"

    # Number of concurrent analysis workers draining the analysis queue.
    # Each worker can have one in-flight LLM call, so this bounds LLM concurrency.
    analysis_workers: int = int(os.getenv("ANALYSIS_WORKERS", "4"))

    # In-memory LLM response cache (keyed on the exact prompt) — collapses
    # duplicate/repeated requests captured while browsing into a single LLM call.
    llm_cache_enabled: bool = os.getenv("LLM_CACHE_ENABLED", "true").lower() == "true"
    llm_cache_size: int = int(os.getenv("LLM_CACHE_SIZE", "512"))


settings = Settings()
