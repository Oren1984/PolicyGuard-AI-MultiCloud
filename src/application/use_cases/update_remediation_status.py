from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from src.domain.entities.actor import Actor
from src.domain.entities.remediation_plan import RemediationPlan
from src.domain.enums.remediation_status import RemediationStatus
from src.domain.state_machine.remediation_transitions import validate_transition
from src.ports.audit_repository import AuditEventRepository
from src.ports.remediation_repository import RemediationPlanRepository


class UpdateRemediationStatusUseCase:
    """Records human-reported remediation progress through valid state
    transitions only (spec sections 5, 15). PolicyGuard never remediates
    automatically — this only records status an authorized operator
    reports."""

    def __init__(
        self,
        remediation_repo: RemediationPlanRepository,
        audit_repo: AuditEventRepository,
        clock: Callable[[], datetime],
    ) -> None:
        self._remediation_repo = remediation_repo
        self._audit_repo = audit_repo
        self._clock = clock

    def execute(
        self,
        plan_id: str,
        *,
        target_status: RemediationStatus,
        verification_evidence: tuple[str, ...] = (),
        actor: Actor,
        correlation_id: str,
    ) -> RemediationPlan:
        plan = self._remediation_repo.get(plan_id)
        validate_transition(plan.status, target_status)

        updated = self._remediation_repo.update_status(
            plan_id, target_status, verification_evidence=verification_evidence
        )
        self._audit_repo.append(
            actor=actor.actor_id,
            actor_role=actor.role.value,
            action="REMEDIATION_STATUS_UPDATED",
            resource_type="remediation_plan",
            resource_id=plan_id,
            correlation_id=correlation_id,
            payload={"from": plan.status.value, "to": target_status.value},
        )
        return updated
