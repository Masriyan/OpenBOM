"""Async SQLAlchemy engine and session factory.

Uses SQLite for local development (DATABASE_URL not set) or PostgreSQL
in production via the DATABASE_URL environment variable.

    export DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/openbom
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator

from sqlalchemy import event, inspect
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

log = logging.getLogger("openbom.server")

_raw_url = os.getenv("DATABASE_URL", "")
if _raw_url:
    if _raw_url.startswith("postgresql://"):
        _raw_url = _raw_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif _raw_url.startswith("postgres://"):
        _raw_url = _raw_url.replace("postgres://", "postgresql+asyncpg://", 1)
    DATABASE_URL = _raw_url
else:
    DATABASE_URL = "sqlite+aiosqlite:///openbom.db"

IS_SQLITE = DATABASE_URL.startswith("sqlite")

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    **({"connect_args": {"check_same_thread": False, "timeout": 30}} if IS_SQLITE else {}),
)

if IS_SQLITE:
    @event.listens_for(engine.sync_engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _record) -> None:  # type: ignore[no-untyped-def]
        # SQLite ignores ON DELETE CASCADE unless foreign_keys is enabled per connection
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.close()

async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db() -> AsyncIterator[AsyncSession]:
    async with async_session() as session:
        yield session


def _add_missing_columns(sync_conn: Connection) -> None:
    """Minimal forward migration: add nullable columns introduced after the table was created."""
    from server.models import Base

    insp = inspect(sync_conn)
    for table in Base.metadata.sorted_tables:
        if not insp.has_table(table.name):
            continue
        existing = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name in existing:
                continue
            col_type = col.type.compile(dialect=sync_conn.dialect)
            sync_conn.exec_driver_sql(f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {col_type}')
            log.warning("Schema upgrade: added column %s.%s", table.name, col.name)


async def init_db() -> None:
    from server.models import Base

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_add_missing_columns)
