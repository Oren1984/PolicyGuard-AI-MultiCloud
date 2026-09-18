from __future__ import annotations

from src.application.services.exception_authorization import ExceptionAuthorizationService
from src.domain.entities.actor import Actor
from src.domain.entities.policy_exception import PolicyException
from src.domain.enums.exception_status import ExceptionStatus
from src.domain.state_machine.exception_transitions import validate_transition
from src.ports.audit_repository import AuditEventRepository
from src.ports.exception_repository import PolicyExceptionRepository


class ReviewPolicyExceptionUseCase:
    """Moves an exception from REQUESTED to UNDER_REVIEW. Subject to the
    same separation-of-duties rule as the final decision: a requester may
    not review their own request."""

    def __init__(
        self,
        exception_repo: PolicyExceptionRepository,
        audit_repo: AuditEventRepository,
        authz: ExceptionAuthorizationService,
    ) -> None:
        self._exception_repo = exception_repo
        self._audit_repo = audit_repo
        self._authz = authz

    def execute(self, exception_id: str, *, actor: Actor, correlation_id: str) -> PolicyException:
        exception = self._exception_repo.get(exception_id)
        self._authz.authorize_decision(exception, actor)
        validate_transition(exception.status, ExceptionStatus.UNDER_REVIEW)

        updated = exception.with_status(ExceptionStatus.UNDER_REVIEW)
        saved = self._exception_repo.update(updated)
        self._audit_repo.append(
            actor=actor.actor_id,
            actor_role=actor.role.value,
            action="POLICY_EXCEPTION_UNDER_REVIEW",
            resource_type="policy_exception",
            resource_id=exception_id,
            correlation_id=correlation_id,
            payload={},
        )
        return saved
