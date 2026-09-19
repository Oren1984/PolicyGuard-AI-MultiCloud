"""Minimal in-memory fakes for the application-use-case test tier. These
exist purely to isolate use-case orchestration logic (authorization calls,
audit calls, id/clock injection, correct port method usage) from PostgreSQL
-- the real adapters are already exercised for real against Postgres in
tests/integration and tests/api. Never used as a substitute for
PostgreSQL-specific test coverage (spec section 20 / this phase's brief)."""

from __future__ import annotations

from src.domain.entities.audit_event import AuditEvent
from src.domain.entities.policy_exception import PolicyException
from src.domain.enums.exception_status import ExceptionStatus
from src.domain.policies.audit_chain import GENESIS_HASH, ChainLink, canonicalize_payload, compute_hash
from src.domain.policies.audit_chain import verify_chain as _verify_chain_links
from src.domain.policies.kill_switch_policy import KillSwitchState
from src.ports.exception_repository import PolicyExceptionNotFoundError


class FakeAuditEventRepository:
    """A real hash chain, kept in memory instead of Postgres -- exercises
    the same canonicalization/hashing rules as the production adapter so
    use-case tests can assert real audit invariants (e.g. "N events were
    appended") without a database round trip."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def append(
        self,
        *,
        actor: str,
        actor_role: str,
        action: str,
        resource_type: str,
        resource_id: str,
        correlation_id: str,
        payload: dict,
        outcome: str = "SUCCESS",
    ) -> AuditEvent:
        previous_hash = self.events[-1].current_hash if self.events else GENESIS_HASH
        sequence = len(self.events) + 1
        canonical = canonicalize_payload(
            {
                "sequence": sequence,
                "actor": actor,
                "actor_role": actor_role,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "correlation_id": correlation_id,
                "payload": payload,
                "outcome": outcome,
            }
        )
        current_hash = compute_hash(previous_hash, canonical)
        event = AuditEvent(
            event_id=f"evt-{sequence}",
            sequence=sequence,
            previous_hash=previous_hash,
            current_hash=current_hash,
            actor=actor,
            actor_role=actor_role,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            correlation_id=correlation_id,
            payload=payload,
            outcome=outcome,
        )
        self._canonical_by_sequence = getattr(self, "_canonical_by_sequence", {})
        self._canonical_by_sequence[sequence] = canonical
        self.events.append(event)
        return event

    def verify_chain(self):
        links = [
            ChainLink(
                sequence=e.sequence,
                previous_hash=e.previous_hash,
                canonical_payload=self._canonical_by_sequence[e.sequence],
                current_hash=e.current_hash,
            )
            for e in self.events
        ]
        return _verify_chain_links(links)

    def list_recent(self, limit: int = 50) -> list[AuditEvent]:
        return list(reversed(self.events))[:limit]

    def list_for_resource(self, resource_type: str, resource_id: str) -> list[AuditEvent]:
        return [e for e in self.events if e.resource_type == resource_type and e.resource_id == resource_id]


class FakePolicyExceptionRepository:
    def __init__(self) -> None:
        self._store: dict[str, PolicyException] = {}

    def create(self, exception: PolicyException) -> PolicyException:
        self._store[exception.exception_id] = exception
        return exception

    def get(self, exception_id: str) -> PolicyException:
        if exception_id not in self._store:
            raise PolicyExceptionNotFoundError(exception_id)
        return self._store[exception_id]

    def update(self, exception: PolicyException) -> PolicyException:
        self._store[exception.exception_id] = exception
        return exception

    def list(self, *, managed_system_id=None, status=None, limit=50, offset=0):
        items = list(self._store.values())
        if managed_system_id is not None:
            items = [e for e in items if e.managed_system_id == managed_system_id]
        if status is not None:
            items = [e for e in items if e.status == status]
        return items[offset : offset + limit], len(items)

    def list_active_for_system(self, managed_system_id: str):
        relevant = (
            ExceptionStatus.APPROVED,
            ExceptionStatus.ACTIVE,
            ExceptionStatus.EXPIRED,
            ExceptionStatus.REVOKED,
        )
        return [
            e
            for e in self._store.values()
            if e.managed_system_id == managed_system_id and e.status in relevant
        ]

    def list_expiring_before(self, cutoff):
        return [
            e
            for e in self._store.values()
            if e.status == ExceptionStatus.ACTIVE and e.expires_at is not None and e.expires_at < cutoff
        ]


class FakeKillSwitchRepository:
    def __init__(self, initial: KillSwitchState | None = None) -> None:
        self._state = initial

    def get_state(self) -> KillSwitchState:
        from src.adapters.persistence.kill_switch_repository_sqlalchemy import KillSwitchStateUnavailableError

        if self._state is None:
            raise KillSwitchStateUnavailableError("no state seeded")
        return self._state

    def set_state(self, state: KillSwitchState) -> KillSwitchState:
        self._state = state
        return state
