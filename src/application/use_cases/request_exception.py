from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from src.application.services.exception_authorization import ExceptionAuthorizationService
from src.domain.entities.actor import Actor
from src.domain.entities.policy_exception import PolicyException
from src.ports.audit_repository import AuditEventRepository
from src.ports.exception_repository import PolicyExceptionRepository


class RequestPolicyExceptionUseCase:
    """Spec section 12: a requester submits an exception with business
    justification, risk statement, compensating controls, requested
    expiration, and evidence. `requested_by` is always the authenticated
    actor id, never a client-supplied field — enforced via
    ExceptionAuthorizationService, below the API layer."""

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
        self,
        *,
        policy_id: str,
        resource_id: str,
        finding_id: str,
        managed_system_id: str,
        business_justification: str,
        risk_statement: str,
        compensating_controls: tuple[str, ...],
        requested_expiration: datetime,
        evidence: tuple[str, ...],
        claimed_requester_id: str,
        actor: Actor,
        correlation_id: str,
    ) -> PolicyException:
        self._authz.authorize_request(requested_by_field=claimed_requester_id, authenticated_actor=actor)

        exception = PolicyException(
            exception_id=self._id_factory(),
            policy_id=policy_id,
            resource_id=resource_id,
            finding_id=finding_id,
            managed_system_id=managed_system_id,
            business_justification=business_justification,
            risk_statement=risk_statement,
            compensating_controls=compensating_controls,
            requested_expiration=requested_expiration,
            requested_by=actor.actor_id,
            evidence=evidence,
            correlation_id=correlation_id,
            created_at=self._clock(),
        )
        created = self._exception_repo.create(exception)
        self._audit_repo.append(
            actor=actor.actor_id,
            actor_role=actor.role.value,
            action="POLICY_EXCEPTION_REQUESTED",
            resource_type="policy_exception",
            resource_id=created.exception_id,
            correlation_id=correlation_id,
            payload={"policy_id": policy_id, "resource_id": resource_id, "finding_id": finding_id},
        )
        return created
