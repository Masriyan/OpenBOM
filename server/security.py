"""Optional API-key authentication for /api/v1 routes."""

from __future__ import annotations

import secrets

from fastapi import HTTPException, Request, status

from server.config import get_settings


async def require_api_key(request: Request) -> None:
    keys = get_settings().api_keys
    if not keys:
        return
    supplied = request.headers.get("x-api-key", "")
    if not supplied:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            supplied = auth[7:].strip()
    if supplied and any(secrets.compare_digest(supplied.encode(), k.encode()) for k in keys):
        return
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing or invalid API key",
        headers={"WWW-Authenticate": "Bearer"},
    )
