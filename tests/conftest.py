"""Root pytest configuration.

Sets the environment variables the running application and Alembic both
honor *before* anything under `src` (in particular `src.config` /
`src.main`) is ever imported by a test module -- `src.config.get_settings()`
is `lru_cache`d, so whatever `POLICYGUARD_DATABASE_URL` is in the
environment at first import time is what the whole test session uses.

Real PostgreSQL only (spec section 3 / this phase's brief) -- never SQLite,
never a mocked database standing in for Postgres-specific behavior. A
disposable `postgres:16` container is expected to already be running and
reachable at `POLICYGUARD_DATABASE_URL` (or the default below) before this
suite is invoked; nothing in this conftest starts or stops that container --
see the HANDOFF.md Phase 5 section for the exact `docker run` command used
to start/stop it around a test run.
"""

from __future__ import annotations

import os

os.environ.setdefault(
    "POLICYGUARD_DATABASE_URL",
    "postgresql+psycopg://policyguard:policyguard@localhost:5432/policyguard_test",
)
os.environ.setdefault("POLICYGUARD_AI_PROVIDER", "mock")
os.environ.setdefault("POLICYGUARD_KILL_SWITCH_DEFAULT_MODE", "normal")
os.environ.setdefault("POLICYGUARD_ENVIRONMENT", "test")

import pytest  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.engine import Engine  # noqa: E402

DATABASE_URL = os.environ["POLICYGUARD_DATABASE_URL"]

# Every application-owned table (everything except Alembic's own
# bookkeeping table). Order doesn't matter for TRUNCATE ... CASCADE since
# this schema uses no foreign keys (nested value objects are stored as
# JSONB, not normalized -- see src/adapters/persistence/models.py).
APP_TABLES = (
    "audit_events",
    "compliance_findings",
    "desired_state_snapshots",
    "drift_findings",
    "governance_decisions",
    "kill_switch_state",
    "managed_systems",
    "observed_state_snapshots",
    "policies",
    "policy_exceptions",
    "policy_packs",
    "remediation_plans",
)


@pytest.fixture(scope="session")
def db_engine() -> Engine:
    return create_engine(DATABASE_URL, future=True, pool_pre_ping=True)


@pytest.fixture(autouse=True)
def _clean_db(db_engine: Engine):
    """Truncates every application table before each test so tests never
    depend on execution order or leftover state from a previous test."""
    with db_engine.begin() as conn:
        conn.execute(text(f"TRUNCATE TABLE {', '.join(APP_TABLES)} RESTART IDENTITY CASCADE"))
    yield


@pytest.fixture()
def client():
    """A fresh FastAPI TestClient per test. Entering it as a context manager
    runs the app's lifespan startup hook, which seeds the kill-switch's
    single row (mode=NORMAL by default) on the just-truncated database --
    mirrors exactly what a real fresh deployment does on first boot."""
    from fastapi.testclient import TestClient

    from src.main import app

    with TestClient(app) as test_client:
        yield test_client
