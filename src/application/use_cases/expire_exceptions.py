from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from src.domain.entities.actor import Actor
from src.domain.entities.policy_exception import PolicyException
from src.domain.enums.exception_status import ExceptionStatus
from src.domain.state_machine.exception_transitions import validate_transition
from src.ports.audit_repository import AuditEventRepository
from src.ports.exception_repository import PolicyExceptionRepository


class ExpireExceptionsUseCase:
    """Sweeps ACTIVE exceptions whose expiration has passed and transitions
    them to EXPIRED. An expired exception must stop suppressing findings
    immediately (spec section 12); this use case is what makes that
    transition durable and audited rather than left implicit."""

    def __init__(
        self,
        exception_repo: PolicyExceptionRepository,
        audit_repo: AuditEventRepository,
        clock: Callable[[], datetime],
    ) -> None:
        self._exception_repo = exception_repo
        self._audit_repo = audit_repo
        self._clock = clock

    def execute(self, *, actor: Actor, correlation_id: str) -> tuple[PolicyException, ...]:
        now = self._clock()
        expired: list[PolicyException] = []
        for exception in self._exception_repo.list_expiring_before(now):
            if exception.status != ExceptionStatus.ACTIVE:
                continue
            validate_transition(exception.status, ExceptionStatus.EXPIRED)
            updated = self._exception_repo.update(exception.with_status(ExceptionStatus.EXPIRED))
            expired.append(updated)
            self._audit_repo.append(
                actor=actor.actor_id,
                actor_role=actor.role.value,
                action="POLICY_EXCEPTION_EXPIRED",
                resource_type="policy_exception",
                resource_id=exception.exception_id,
                correlation_id=correlation_id,
                payload={"expires_at": exception.expires_at.isoformat() if exception.expires_at else None},
            )
        return tuple(expired)
