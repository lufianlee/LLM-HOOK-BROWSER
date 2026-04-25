from __future__ import annotations

import asyncio
import logging
import sys

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.api.routes import router
from app.config import settings
from app.database import init_db
from app.ingester import run_ingester
from app.proxy.runner import ProxyRunner

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("main")

app = FastAPI(title="LLM Security Proxy", version="1.0.0")
app.include_router(router)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

event_queue: asyncio.Queue = asyncio.Queue(maxsize=10_000)


@app.get("/")
async def root():
    return FileResponse("app/static/index.html")


@app.on_event("startup")
async def startup():
    await init_db()
    logger.info("Database initialized")

    asyncio.create_task(run_ingester(event_queue))
    logger.info("Ingester task started")

    proxy = ProxyRunner(event_queue)
    proxy.start()
    logger.info(
        "Proxy listening on port %d, target domains: %s",
        settings.proxy_port,
        settings.target_domains or ["ALL"],
    )
    logger.info(
        "LLM provider: %s, model: %s",
        settings.llm_provider,
        settings.bedrock_model_id if settings.llm_provider == "bedrock" else settings.anthropic_model,
    )
    logger.info("Dashboard: http://%s:%d", settings.api_host, settings.api_port)


def main():
    uvicorn.run(
        "main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
