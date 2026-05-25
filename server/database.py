"""Async SQLAlchemy engine and session factory.

Uses SQLite for local development (DATABASE_URL not set) or PostgreSQL
in production via the DATABASE_URL environment variable.

    export DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/openbom
"""

from __future__ import annotations

import os

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

_raw_url = os.getenv("DATABASE_URL", "")
if _raw_url:
    if _raw_url.startswith("postgresql://"):
        _raw_url = _raw_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    DATABASE_URL = _raw_url
else:
    DATABASE_URL = "sqlite+aiosqlite:///openbom.db"

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    **({"connect_args": {"check_same_thread": False}} if DATABASE_URL.startswith("sqlite") else {}),
)

async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db() -> AsyncSession:  # type: ignore[misc]
    async with async_session() as session:
        yield session
