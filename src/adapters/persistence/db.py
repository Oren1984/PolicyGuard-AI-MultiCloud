"""Engine/session setup for the PostgreSQL persistence adapters.

Reads `DATABASE_URL` from the environment via a simple, local
`os.environ.get`. This is a deliberate phase-2-local helper, not central
application configuration -- a later API-layer phase is expected to
introduce `src/config.py` (e.g. a pydantic-settings model) and consolidate
every environment-variable read, including this one, behind it. Nothing
else in this adapter package should read `DATABASE_URL` directly; go
through `get_database_url()` so that later consolidation is a one-line
change here.

PostgreSQL only -- no SQLite anywhere, including local development (spec
section 3).
"""

from __future__ import annotations

import os
from collections.abc import Generator

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

DEFAULT_DATABASE_URL = "postgresql+psycopg://policyguard:policyguard@localhost:5432/policyguard"

_engine_cache: dict[str, Engine] = {}


def get_database_url() -> str:
    return os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL)


def get_engine(database_url: str | None = None) -> Engine:
    url = database_url or get_database_url()
    if url not in _engine_cache:
        _engine_cache[url] = create_engine(url, pool_pre_ping=True, future=True)
    return _engine_cache[url]


def get_sessionmaker(database_url: str | None = None) -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(database_url), autoflush=False, autocommit=False, future=True)


def session_scope(database_url: str | None = None) -> Generator[Session, None, None]:
    """A plain generator (not `@contextmanager`-wrapped) so it can be used
    directly as a FastAPI dependency in a later phase, in addition to being
    driven manually with `next()`/`.close()` for scripts and smoke checks."""
    factory = get_sessionmaker(database_url)
    session = factory()
    try:
        yield session
    finally:
        session.close()
