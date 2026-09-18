from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Literal

from src.application.routing.decision_router import GovernanceDecisionContext, route_governance_decision
from src.domain.entities.actor import Actor
from src.domain.entities.governance_decision import GovernanceDecision
from src.domain.enums.exception_status import ExceptionStatus
from src.domain.enums.policy_severity import PolicySeverity
from src.domain.enums.resource_criticality import ResourceCriticality
from src.ports.audit_repository import AuditEventRepository
from src.ports.decision_repository import GovernanceDecisionRepository
from src.ports.exception_repository import PolicyExceptionRepository
from src.ports.finding_repository import ComplianceFindingRepository, DriftFindingRepository
from src.ports.kill_switch_repository import KillSwitchRepository
from src.ports.managed_system_repository import ManagedSystemRepository
from src.ports.snapshot_repository import ObservedStateSnapshotRepository

FindingKind = Literal["compliance", "drift"]

# Findings within this many prior evaluations count toward the router's
# "repeated violations" input.
_REPEATED_VIOLATION_LOOKBACK = 10


class GenerateGovernanceDecisionUseCase:
    """Gathers the deterministic evidence for a single finding and asks the
    pure decision router (src/application/routing/decision_router.py) for a
    GovernanceDecision (spec section 9). This is the only place that
    assembles a GovernanceDecisionContext — it never passes AI output to it."""

    def __init__(
        self,
        *,
        managed_system_repo: ManagedSystemRepository,
        observed_snapshot_repo: ObservedStateSnapshotRepository,
        compliance_finding_repo: ComplianceFindingRepository,
        drift_finding_repo: DriftFindingRepository,
        exception_repo: PolicyExceptionRepository,
        decision_repo: GovernanceDecisionRepository,
        kill_switch_repo: KillSwitchRepository,
        audit_repo: AuditEventRepository,
        id_factory: Callable[[], str],
        clock: Callable[[], datetime],
    ) -> None:
        self._managed_system_repo = managed_system_repo
        self._observed_snapshot_repo = observed_snapshot_repo
        self._compliance_finding_repo = compliance_finding_repo
        self._drift_finding_repo = drift_finding_repo
        self._exception_repo = exception_repo
        self._decision_repo = decision_repo
        self._kill_switch_repo = kill_switch_repo
        self._audit_repo = audit_repo
        self._id_factory = id_factory
        self._clock = clock

    def execute(
        self, *, finding_id: str, finding_kind: FindingKind, actor: Actor, correlation_id: str
    ) -> GovernanceDecision:
        if finding_kind == "compliance":
            finding = self._compliance_finding_repo.get(finding_id)
            severity: PolicySeverity = finding.severity
            resource_id = finding.resource_id
            managed_system_id = finding.managed_system_id
            policy_id: str | None = finding.policy_id
            exception_eligible = finding.exception_eligible
            evidence_present = bool(finding.evidence)
        else:
            drift_finding = self._drift_finding_repo.get(finding_id)
            severity = drift_finding.severity
            resource_id = drift_finding.resource_id
            managed_system_id = drift_finding.managed_system_id
            policy_id = drift_finding.policy_id
            exception_eligible = drift_finding.exception_eligible
            evidence_present = bool(drift_finding.evidence)

        managed_system = self._managed_system_repo.get(managed_system_id)
        resource_criticality = self._resolve_resource_criticality(managed_system_id, resource_id)
        exception_status = self._resolve_exception_status(managed_system_id, policy_id, resource_id)
        repeated_violation_count = (
            self._compliance_finding_repo.count_recent_violations(
                policy_id=policy_id, resource_id=resource_id, within_last=_REPEATED_VIOLATION_LOOKBACK
            )
            if finding_kind == "compliance" and policy_id is not None
            else 0
        )
        kill_switch_state = self._kill_switch_repo.get_state()

        context = GovernanceDecisionContext(
            has_violation=True,
            severity=severity,
            environment=managed_system.environment,
            resource_criticality=resource_criticality,
            evidence_complete=evidence_present,
            exception_status=exception_status,
            exception_eligible=exception_eligible,
            critical_non_eligible=(severity == PolicySeverity.CRITICAL and not exception_eligible),
            repeated_violation_count=repeated_violation_count,
            system_mode=kill_switch_state.mode,
            gates=None,  # AI assurance gate pipeline is a later phase.
            policy_id=policy_id,
        )
        result = route_governance_decision(context)

        decision = GovernanceDecision.from_routing_result(
            decision_id=self._id_factory(),
            managed_system_id=managed_system_id,
            finding_ids=(finding_id,),
            result=result,
            correlation_id=correlation_id,
        )
        created = self._decision_repo.create(decision)
        self._audit_repo.append(
            actor=actor.actor_id,
            actor_role=actor.role.value,
            action="GOVERNANCE_DECISION_GENERATED",
            resource_type=f"{finding_kind}_finding",
            resource_id=finding_id,
            correlation_id=correlation_id,
            payload={"decision": created.decision.value, "reasons": list(created.reasons)},
        )
        return created

    def _resolve_resource_criticality(self, managed_system_id: str, resource_id: str) -> ResourceCriticality:
        snapshot = self._observed_snapshot_repo.get_latest_for_system(managed_system_id)
        if snapshot is None:
            return ResourceCriticality.STANDARD
        resource = snapshot.resource_by_id().get(resource_id)
        return resource.criticality if resource is not None else ResourceCriticality.STANDARD

    def _resolve_exception_status(
        self, managed_system_id: str, policy_id: str | None, resource_id: str
    ) -> ExceptionStatus | None:
        if policy_id is None:
            return None
        for exception in self._exception_repo.list_active_for_system(managed_system_id):
            if exception.policy_id == policy_id and exception.resource_id == resource_id:
                return exception.status
        return None
