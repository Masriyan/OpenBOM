"""OpenBOM Centralized Backend Server.

Run:
    uvicorn server.main:app --reload --host 0.0.0.0 --port 8000

Then open http://localhost:8000/ for the dashboard, /docs for the API.

Environment: see server/config.py (DATABASE_URL, OPENBOM_API_KEY, OPENBOM_CORS_ORIGINS, OPENBOM_STALE_DAYS).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from server.config import get_settings
from server.database import engine, init_db
from server.routers import assets, governance, hunt, ingest, threats

VERSION = "2.1.0"
STATIC_DIR = Path(__file__).resolve().parent / "static"
log = logging.getLogger("openbom.server")


async def _reanalysis_loop(hours: float) -> None:
    """Continuous monitoring: periodically re-match every stored inventory against fresh OSV/EPSS/KEV data."""
    from sqlalchemy import select

    from server.database import async_session
    from server.models import Asset

    while True:
        await asyncio.sleep(hours * 3600)
        try:
            async with async_session() as db:
                assets = list((await db.execute(select(Asset))).scalars())
                result = await governance.reanalyze_assets(db, assets)
            log.info("Scheduled re-analysis: %d assets, %d packages, %d vuln links",
                     result.assets, result.packages_checked, result.vulnerabilities_linked)
        except Exception:  # keep the loop alive; next round retries
            log.exception("Scheduled re-analysis failed")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    await init_db()
    if not get_settings().api_keys:
        log.warning("OPENBOM_API_KEY is not set — the API is unauthenticated. Set it for any non-local deployment.")
    task = None
    try:
        hours = float(os.environ.get("OPENBOM_REANALYZE_HOURS", "0"))
    except ValueError:
        hours = 0.0
    if hours > 0:
        task = asyncio.create_task(_reanalysis_loop(hours))
        log.info("Continuous re-analysis enabled every %.1f h", hours)
    yield
    if task:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
    await engine.dispose()


app = FastAPI(
    title="OpenBOM Backend",
    description="Centralized supply-chain threat intelligence platform",
    version=VERSION,
    lifespan=lifespan,
)

_settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(_settings.cors_origins),
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", "Authorization"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.url.path.startswith("/static/vendor/"):
        response.headers["Cache-Control"] = "public, max-age=604800, immutable"
    elif request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache"
    return response


app.include_router(ingest.router)
app.include_router(threats.router)
app.include_router(assets.router)
app.include_router(hunt.router)
app.include_router(governance.router)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# No inline script: the console ships as /static/app.js. Arco sets inline style attributes, hence style 'unsafe-inline'.
DASHBOARD_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
    "font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; "
    "object-src 'none'"
)


@app.get("/", include_in_schema=False, response_class=HTMLResponse)
@app.get("/dashboard", include_in_schema=False, response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(html, headers={"Content-Security-Policy": DASHBOARD_CSP, "Cache-Control": "no-cache"})


@app.get("/health", tags=["system"])
async def health_check() -> dict[str, str | bool]:
    return {"status": "ok", "service": "openbom-backend", "version": VERSION,
            "auth_required": bool(get_settings().api_keys)}
