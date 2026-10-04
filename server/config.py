"""Runtime settings read from the environment.

    DATABASE_URL           PostgreSQL/SQLite URL (default: sqlite+aiosqlite:///openbom.db)
    OPENBOM_API_KEY        Comma-separated API key(s). When set, every /api/v1 route requires
                           an "X-API-Key: <key>" or "Authorization: Bearer <key>" header.
    OPENBOM_CORS_ORIGINS   Comma-separated allowed origins (default: *)
    OPENBOM_STALE_DAYS     Days without a scan before an asset is flagged stale (default: 7)
    OPENBOM_MAX_PACKAGES   Max packages accepted per ingest payload (default: 200000)
    OPENBOM_REANALYZE_HOURS  Re-match all stored inventories against OSV/EPSS/KEV every N hours (default: off)
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Settings:
    api_keys: tuple[str, ...]
    cors_origins: tuple[str, ...]
    stale_days: int
    max_packages: int


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def get_settings() -> Settings:
    keys = tuple(k.strip() for k in os.environ.get("OPENBOM_API_KEY", "").split(",") if k.strip())
    origins = tuple(o.strip() for o in os.environ.get("OPENBOM_CORS_ORIGINS", "*").split(",") if o.strip())
    return Settings(
        api_keys=keys,
        cors_origins=origins or ("*",),
        stale_days=_int_env("OPENBOM_STALE_DAYS", 7),
        max_packages=_int_env("OPENBOM_MAX_PACKAGES", 200_000),
    )
