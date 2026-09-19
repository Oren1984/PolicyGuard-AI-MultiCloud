from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from src.application.services.exception_authorization import ExceptionAuthorizationService
from src.domain.entities.actor import Actor
from src.domain.entities.policy_exception import PolicyException
from src.domain.enums.exception_status import ExceptionStatus
from src.domain.state_machine.exception_transitions import validate_transition
from src.ports.audit_repository import AuditEventRepository
from src.ports.exception_repository import PolicyExceptionRepository


class RevokePolicyExceptionUseCase:
    """Revokes an ACTIVE (or APPROVED-but-not-yet-active) exception ahead
    of its expiration. Revocation must stop suppressing findings
    immediately (spec section 12) — callers re-run evaluation afterward to
    surface the now-unsuppressed violation."""

    def __init__(
        self,
        exception_repo: PolicyExceptionRepository,
        audit_repo: AuditEventRepository,
        authz: ExceptionAuthorizationService,
        clock: Callable[[], datetime],
    ) -> None:
        self._exception_repo = exception_repo
        self._audit_repo = audit_repo
        self._authz = authz
        self._clock = clock

    def execute(
        self, exception_id: str, *, reason: str, actor: Actor, correlation_id: str
    ) -> PolicyException:
        self._authz.authorize_revocation(actor)
        exception = self._exception_repo.get(exception_id)
        validate_transition(exception.status, ExceptionStatus.REVOKED)

        updated = exception.with_status(
            ExceptionStatus.REVOKED,
            revoked_at=self._clock(),
            revoked_by=actor.actor_id,
            revoked_reason=reason,
        )
        saved = self._exception_repo.update(updated)
        self._audit_repo.append(
            actor=actor.actor_id,
            actor_role=actor.role.value,
            action="POLICY_EXCEPTION_REVOKED",
            resource_type="policy_exception",
            resource_id=exception_id,
            correlation_id=correlation_id,
            payload={"reason": reason},
        )
        return saved
