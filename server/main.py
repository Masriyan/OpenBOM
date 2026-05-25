"""OpenBOM Centralized Backend Server.

Run:
    uvicorn server.main:app --reload --host 0.0.0.0 --port 8000

Environment:
    DATABASE_URL  — PostgreSQL connection string (omit for SQLite fallback)
                    e.g. postgresql+asyncpg://user:pass@localhost:5432/openbom
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from server.database import engine
from server.models import Base
from server.routers import assets, ingest, threats


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(
    title="OpenBOM Backend",
    description="Centralized supply-chain threat intelligence platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingest.router)
app.include_router(threats.router)
app.include_router(assets.router)


@app.get("/health", tags=["system"])
async def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "openbom-backend"}
