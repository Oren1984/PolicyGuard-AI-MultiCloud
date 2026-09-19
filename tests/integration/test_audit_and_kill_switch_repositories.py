"""PostgreSQL integration tests: the audit-event hash chain (spec section 14)
and the kill-switch repository (spec section 13), against a real database.

The audit-chain tampering regression here directly mutates a persisted row
with raw SQL -- exactly what an attacker with direct database access would
do -- and proves `verify_chain()` detects it. This is the strongest possible
version of that regression because it exercises the real adapter against a
real table, not an in-memory approximation.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from src.adapters.persistence.audit_repository_sqlalchemy import SqlAlchemyAuditEventRepository
from src.adapters.persistence.kill_switch_repository_sqlalchemy import (
    KillSwitchStateUnavailableError,
    SqlAlchemyKillSwitchRepository,
)
from src.domain.enums.system_mode import SystemMode
from src.domain.policies.kill_switch_policy import KillSwitchState


@pytest.fixture()
def session(db_engine):
    factory = sessionmaker(bind=db_engine, future=True)
    s = factory()
    yield s
    s.close()


class TestAuditEventRepositoryChain:
    def test_first_event_chains_from_genesis(self, session):
        repo = SqlAlchemyAuditEventRepository(session)
        event = repo.append(
            actor="actor.one",
            actor_role="platform_admin",
            action="TEST_ACTION",
            resource_type="test",
            resource_id="r1",
            correlation_id="c1",
            payload={"k": "v"},
        )
        assert event.sequence == 1
        assert event.previous_hash == "0" * 64

    def test_sequential_events_chain_correctly(self, session):
        repo = SqlAlchemyAuditEventRepository(session)
        first = repo.append(
            actor="a",
            actor_role="platform_admin",
            action="A",
            resource_type="t",
            resource_id="1",
            correlation_id="c",
            payload={},
        )
        second = repo.append(
            actor="a",
            actor_role="platform_admin",
            action="B",
            resource_type="t",
            resource_id="2",
            correlation_id="c",
            payload={},
        )
        assert second.previous_hash == first.current_hash
        assert second.sequence == 2

    def test_verify_chain_valid_after_several_appends(self, session):
        repo = SqlAlchemyAuditEventRepository(session)
        for i in range(5):
            repo.append(
                actor="a",
                actor_role="platform_admin",
                action=f"ACTION_{i}",
                resource_type="t",
                resource_id=str(i),
                correlation_id="c",
                payload={"i": i},
            )
        result = repo.verify_chain()
        assert result.is_valid is True
        assert result.total_records == 5

    def test_secrets_are_redacted_before_hashing_and_storage(self, session):
        repo = SqlAlchemyAuditEventRepository(session)
        event = repo.append(
            actor="a",
            actor_role="platform_admin",
            action="LOGIN",
            resource_type="t",
            resource_id="1",
            correlation_id="c",
            payload={"password": "hunter2", "note": "ok"},
        )
        assert "hunter2" not in str(event.payload)

    def test_tampering_a_persisted_payload_directly_in_postgres_is_detected(self, session, db_engine):
        """Required regression: audit-chain tampering. Simulates an
        attacker with raw database access mutating a historical record after
        the fact, without recomputing the hash (which they cannot do without
        also rewriting every subsequent record) -- verify_chain() must catch
        it."""
        repo = SqlAlchemyAuditEventRepository(session)
        repo.append(
            actor="a",
            actor_role="platform_admin",
            action="FIRST",
            resource_type="t",
            resource_id="1",
            correlation_id="c",
            payload={"amount": 100},
        )
        repo.append(
            actor="a",
            actor_role="platform_admin",
            action="SECOND",
            resource_type="t",
            resource_id="2",
            correlation_id="c",
            payload={"amount": 200},
        )
        assert repo.verify_chain().is_valid is True

        with db_engine.begin() as conn:
            conn.execute(
                text("UPDATE audit_events SET canonical_payload = :payload WHERE sequence = 1"),
                {"payload": '{"amount":999999,"tampered":true}'},
            )

        tampered_result = SqlAlchemyAuditEventRepository(session).verify_chain()
        assert tampered_result.is_valid is False
        assert tampered_result.first_invalid_sequence == 1

    def test_deleting_a_record_is_detected_as_a_sequence_gap(self, session, db_engine):
        repo = SqlAlchemyAuditEventRepository(session)
        repo.append(
            actor="a",
            actor_role="platform_admin",
            action="FIRST",
            resource_type="t",
            resource_id="1",
            correlation_id="c",
            payload={},
        )
        repo.append(
            actor="a",
            actor_role="platform_admin",
            action="SECOND",
            resource_type="t",
            resource_id="2",
            correlation_id="c",
            payload={},
        )
        with db_engine.begin() as conn:
            conn.execute(text("DELETE FROM audit_events WHERE sequence = 1"))

        result = SqlAlchemyAuditEventRepository(session).verify_chain()
        assert result.is_valid is False

    def test_list_recent_returns_newest_first(self, session):
        repo = SqlAlchemyAuditEventRepository(session)
        repo.append(
            actor="a",
            actor_role="platform_admin",
            action="FIRST",
            resource_type="t",
            resource_id="1",
            correlation_id="c",
            payload={},
        )
        repo.append(
            actor="a",
            actor_role="platform_admin",
            action="SECOND",
            resource_type="t",
            resource_id="2",
            correlation_id="c",
            payload={},
        )
        recent = repo.list_recent(limit=10)
        assert recent[0].action == "SECOND"
        assert recent[1].action == "FIRST"

    def test_list_for_resource_filters_correctly(self, session):
        repo = SqlAlchemyAuditEventRepository(session)
        repo.append(
            actor="a",
            actor_role="platform_admin",
            action="A",
            resource_type="policy_exception",
            resource_id="exc-1",
            correlation_id="c",
            payload={},
        )
        repo.append(
            actor="a",
            actor_role="platform_admin",
            action="B",
            resource_type="managed_system",
            resource_id="sys-1",
            correlation_id="c",
            payload={},
        )
        events = repo.list_for_resource("policy_exception", "exc-1")
        assert len(events) == 1
        assert events[0].action == "A"


class TestKillSwitchRepository:
    def test_no_row_yet_raises_unavailable_fail_closed(self, session):
        repo = SqlAlchemyKillSwitchRepository(session)
        with pytest.raises(KillSwitchStateUnavailableError):
            repo.get_state()

    def test_set_then_get_round_trip(self, session):
        repo = SqlAlchemyKillSwitchRepository(session)
        repo.set_state(KillSwitchState(mode=SystemMode.PAUSED, changed_by="admin.one", reason="maintenance"))
        state = repo.get_state()
        assert state.mode == SystemMode.PAUSED
        assert state.changed_by == "admin.one"

    def test_set_state_is_idempotent_single_row(self, session):
        repo = SqlAlchemyKillSwitchRepository(session)
        repo.set_state(KillSwitchState(mode=SystemMode.NORMAL))
        repo.set_state(KillSwitchState(mode=SystemMode.EMERGENCY_STOP, reason="incident"))
        state = repo.get_state()
        assert state.mode == SystemMode.EMERGENCY_STOP
