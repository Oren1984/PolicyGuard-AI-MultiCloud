from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from src.application.services.exception_authorization import ExceptionAuthorizationService
from src.domain.entities.actor import Actor
from src.domain.entities.policy_exception import ExceptionApproval, PolicyException
from src.domain.enums.exception_status import ExceptionStatus
from src.domain.state_machine.exception_transitions import validate_transition
from src.ports.audit_repository import AuditEventRepository
from src.ports.exception_repository import PolicyExceptionRepository


class DecidePolicyExceptionUseCase:
    """Records the approve/reject decision on a policy exception (spec
    section 12). A requester can never decide their own exception —
    enforced via ExceptionAuthorizationService before any state change."""

    def __init__(
        self,
        exception_repo: PolicyExceptionRepository,
        audit_repo: AuditEventRepository,
        authz: ExceptionAuthorizationService,
        id_factory: Callable[[], str],
        clock: Callable[[], datetime],
    ) -> None:
        self._exception_repo = exception_repo
        self._audit_repo = audit_repo
        self._authz = authz
        self._id_factory = id_factory
        self._clock = clock

    def execute(
        self, exception_id: str, *, approve: bool, rationale: str, actor: Actor, correlation_id: str
    ) -> PolicyException:
        exception = self._exception_repo.get(exception_id)
        self._authz.authorize_decision(exception, actor)

        target_status = ExceptionStatus.APPROVED if approve else ExceptionStatus.REJECTED
        validate_transition(exception.status, target_status)

        approval = ExceptionApproval(
            approval_id=self._id_factory(),
            exception_id=exception_id,
            decision="APPROVED" if approve else "REJECTED",
            rationale=rationale,
            decided_by=actor.actor_id,
            decided_role=actor.role.value,
            decided_at=self._clock(),
        )
        updated = exception.with_status(target_status, approvals=(*exception.approvals, approval))

        if approve:
            active_status = ExceptionStatus.ACTIVE
            validate_transition(target_status, active_status)
            updated = updated.with_status(
                active_status,
                approvals=updated.approvals,
                activated_at=self._clock(),
                expires_at=exception.requested_expiration,
            )

        saved = self._exception_repo.update(updated)
        self._audit_repo.append(
            actor=actor.actor_id,
            actor_role=actor.role.value,
            action="POLICY_EXCEPTION_APPROVED" if approve else "POLICY_EXCEPTION_REJECTED",
            resource_type="policy_exception",
            resource_id=exception_id,
            correlation_id=correlation_id,
            payload={"rationale": rationale},
        )
        return saved
