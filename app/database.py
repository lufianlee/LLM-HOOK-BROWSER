from __future__ import annotations

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings
from app.models import Base

engine = create_async_engine(settings.db_url, echo=False)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


@event.listens_for(engine.sync_engine, "connect")
def _configure_sqlite(dbapi_conn, _record) -> None:
    """Enable WAL + a busy timeout so concurrent analysis workers can commit
    without hitting 'database is locked'. WAL lets readers (dashboard queries)
    proceed while a writer commits."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


# Indexes for tables that may predate this schema (create_all does not add
# indexes to already-existing tables).
_EXTRA_INDEXES = (
    "CREATE INDEX IF NOT EXISTS ix_captured_requests_timestamp ON captured_requests (timestamp)",
    "CREATE INDEX IF NOT EXISTS ix_captured_requests_host ON captured_requests (host)",
    "CREATE INDEX IF NOT EXISTS ix_captured_requests_method ON captured_requests (method)",
    "CREATE INDEX IF NOT EXISTS ix_findings_timestamp ON findings (timestamp)",
    "CREATE INDEX IF NOT EXISTS ix_findings_request_id ON findings (request_id)",
    "CREATE INDEX IF NOT EXISTS ix_findings_severity ON findings (severity)",
    "CREATE INDEX IF NOT EXISTS ix_findings_is_chain ON findings (is_chain)",
)


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        for stmt in _EXTRA_INDEXES:
            await conn.execute(text(stmt))


async def get_session() -> AsyncSession:
    async with async_session() as session:
        yield session
