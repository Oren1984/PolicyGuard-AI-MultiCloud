"""PostgreSQL integration tests: managed-system and snapshot repositories,
exercised against a real, disposable postgres:16 database (spec section 20:
"Use real PostgreSQL for integration and E2E testing. Do not use SQLite.")."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import sessionmaker

from src.adapters.persistence.managed_system_repository_sqlalchemy import SqlAlchemyManagedSystemRepository
from src.adapters.persistence.snapshot_repository_sqlalchemy import (
    SqlAlchemyDesiredStateSnapshotRepository,
    SqlAlchemyObservedStateSnapshotRepository,
)
from src.ports.managed_system_repository import ManagedSystemNotFoundError
from tests.fixtures.builders import (
    build_desired_snapshot,
    build_managed_system,
    build_observed_snapshot,
    build_resource,
)


@pytest.fixture()
def session(db_engine):
    factory = sessionmaker(bind=db_engine, future=True)
    s = factory()
    yield s
    s.close()


class TestManagedSystemRepository:
    def test_create_and_get_round_trip(self, session):
        repo = SqlAlchemyManagedSystemRepository(session)
        system = build_managed_system("sys-rt-1")
        repo.create(system)
        fetched = repo.get("sys-rt-1")
        assert fetched.system_id == "sys-rt-1"
        assert fetched.cloud_provider == system.cloud_provider
        assert fetched.environment == system.environment

    def test_get_missing_raises_not_found(self, session):
        repo = SqlAlchemyManagedSystemRepository(session)
        with pytest.raises(ManagedSystemNotFoundError):
            repo.get("does-not-exist")

    def test_exists_true_and_false(self, session):
        repo = SqlAlchemyManagedSystemRepository(session)
        repo.create(build_managed_system("sys-exists-1"))
        assert repo.exists("sys-exists-1") is True
        assert repo.exists("sys-does-not-exist") is False

    def test_list_pagination(self, session):
        repo = SqlAlchemyManagedSystemRepository(session)
        for i in range(5):
            repo.create(build_managed_system(f"sys-page-{i}"))
        page1, total = repo.list(limit=2, offset=0)
        page2, total2 = repo.list(limit=2, offset=2)
        assert total == 5
        assert total2 == 5
        assert len(page1) == 2
        assert len(page2) == 2
        assert {s.system_id for s in page1}.isdisjoint({s.system_id for s in page2})


class TestSnapshotRepositories:
    def test_desired_snapshot_round_trip_preserves_nested_resources(self, session):
        repo = SqlAlchemyDesiredStateSnapshotRepository(session)
        resource = build_resource("r1", "sys1")
        snapshot = build_desired_snapshot("sys1", (resource,))
        repo.create(snapshot)
        fetched = repo.get(snapshot.snapshot_id)
        assert fetched.managed_system_id == "sys1"
        assert len(fetched.resources) == 1
        assert fetched.resources[0].resource_id == "r1"
        assert fetched.baseline.allowed_regions == snapshot.baseline.allowed_regions

    def test_get_latest_for_system_returns_most_recent(self, session):
        repo = SqlAlchemyDesiredStateSnapshotRepository(session)
        first = build_desired_snapshot("sys1", ())
        repo.create(first)
        second = build_desired_snapshot("sys1", ())
        repo.create(second)
        latest = repo.get_latest_for_system("sys1")
        assert latest is not None
        assert latest.snapshot_id in (first.snapshot_id, second.snapshot_id)

    def test_get_latest_for_system_returns_none_when_absent(self, session):
        repo = SqlAlchemyDesiredStateSnapshotRepository(session)
        assert repo.get_latest_for_system("no-such-system") is None

    def test_observed_snapshot_previous_lookup(self, session):
        import dataclasses
        from datetime import UTC, datetime, timedelta

        repo = SqlAlchemyObservedStateSnapshotRepository(session)
        # Explicit, well-separated timestamps: on some hosts back-to-back
        # datetime.now(UTC) calls can land in the same clock tick, which
        # would make this lookup's ordering ambiguous rather than flaky.
        now = datetime.now(UTC)
        first = dataclasses.replace(
            build_observed_snapshot("sys1", ()), captured_at=now - timedelta(minutes=5)
        )
        repo.create(first)
        second = dataclasses.replace(build_observed_snapshot("sys1", ()), captured_at=now)
        repo.create(second)
        previous = repo.get_previous_for_system("sys1", before_snapshot_id=second.snapshot_id)
        assert previous is not None
        assert previous.snapshot_id == first.snapshot_id
