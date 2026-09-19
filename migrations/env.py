"""Alembic environment for PolicyGuard AI MultiCloud.

Database URL resolution -- documented reasoning (Phase 4):

There are two independent, pre-existing sources of a database URL in this
repo:

1. `src/config.py::Settings` (pydantic-settings, env prefix `POLICYGUARD_`)
   reads `POLICYGUARD_DATABASE_URL`. This is what the *running FastAPI app*
   actually uses -- `src/api/dependencies/db.py::get_db` passes
   `settings.database_url` straight into `get_sessionmaker(...)`, bypassing
   the adapter's own env lookup below entirely.
2. `src/adapters/persistence/db.py::get_database_url()` is a Phase-2-era
   standalone helper that reads plain `DATABASE_URL` (no prefix) via
   `os.environ.get`, with its own hardcoded default. It is only reached by
   code that calls it directly without going through `src/config.py` --
   which describes exactly this file: Alembic runs as a separate process,
   outside the FastAPI app, and never imports `src/api/dependencies/db.py`.

This module is Alembic's own entrypoint, so it must decide explicitly which
of the two to honor, rather than silently picking one. The choice made
here: read `POLICYGUARD_DATABASE_URL` first. Rationale --
  * It's what the running app honors, so using the same variable in Docker
    Compose / CI / local `.env` means operators set exactly one database URL
    for the whole stack instead of two that must be kept in sync.
  * Falling back to plain `DATABASE_URL`, and finally to the adapter's own
    `get_database_url()` default, preserves compatibility with the
    Phase-2-era convention for anyone running Alembic against a
    non-Compose, non-`POLICYGUARD_`-prefixed environment (e.g. a bare
    `DATABASE_URL=... alembic upgrade head` invocation), without requiring
    a second, hardcoded copy of the same default connection string here.

`docker-compose.yml`, `.env.example`, and the Dockerfile all standardize on
`POLICYGUARD_DATABASE_URL` as the one variable operators are expected to
set -- see the top-level comment in `.env.example`.
"""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Importing src.adapters.persistence.models registers every ORM class
# (ManagedSystemORM, ..., KillSwitchStateORM) on Base.metadata, which is
# what makes `alembic revision --autogenerate` and `upgrade`/`downgrade`
# see the real schema rather than an empty one.
from src.adapters.persistence.db import get_database_url  # noqa: E402
from src.adapters.persistence.models import Base  # noqa: E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    # Precedence: POLICYGUARD_DATABASE_URL (matches the running app) ->
    # plain DATABASE_URL (Phase-2-era adapter convention) -> the adapter's
    # own hardcoded local-Postgres default. See module docstring above.
    return os.environ.get("POLICYGUARD_DATABASE_URL") or os.environ.get("DATABASE_URL") or get_database_url()


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = _database_url()
    connectable = engine_from_config(configuration, prefix="sqlalchemy.", poolclass=pool.NullPool)

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
