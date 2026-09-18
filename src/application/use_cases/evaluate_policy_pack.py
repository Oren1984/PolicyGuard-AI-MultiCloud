from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from src.domain.entities.actor import Actor
from src.domain.entities.policy_evaluation import PolicyEvaluation
from src.domain.entities.state_snapshot import ArchitectureBaseline
from src.domain.policies.kill_switch_policy import blocks_new_evaluations
from src.domain.policy_engine.evaluator import evaluate_policy_pack
from src.ports.audit_repository import AuditEventRepository
from src.ports.exception_repository import PolicyExceptionRepository
from src.ports.finding_repository import ComplianceFindingRepository
from src.ports.kill_switch_repository import KillSwitchRepository
from src.ports.managed_system_repository import ManagedSystemRepository
from src.ports.policy_repository import PolicyPackRepository
from src.ports.snapshot_repository import DesiredStateSnapshotRepository, ObservedStateSnapshotRepository


class EvaluationBlockedError(Exception):
    """Raised when the kill switch is not NORMAL. Fail closed: no new
    evaluation may run while PAUSED or EMERGENCY_STOP (spec section 13)."""


class EvaluatePolicyPackUseCase:
    """Runs a deterministic policy-pack evaluation against a managed
    system's latest observed snapshot, producing ComplianceFindings (spec
    section 15, "Evaluate a snapshot against a policy pack")."""

    def __init__(
        self,
        *,
        managed_system_repo: ManagedSystemRepository,
        desired_snapshot_repo: DesiredStateSnapshotRepository,
        observed_snapshot_repo: ObservedStateSnapshotRepository,
        policy_pack_repo: PolicyPackRepository,
        finding_repo: ComplianceFindingRepository,
        exception_repo: PolicyExceptionRepository,
        kill_switch_repo: KillSwitchRepository,
        audit_repo: AuditEventRepository,
        id_factory: Callable[[], str],
        clock: Callable[[], datetime],
    ) -> None:
        self._managed_system_repo = managed_system_repo
        self._desired_snapshot_repo = desired_snapshot_repo
        self._observed_snapshot_repo = observed_snapshot_repo
        self._policy_pack_repo = policy_pack_repo
        self._finding_repo = finding_repo
        self._exception_repo = exception_repo
        self._kill_switch_repo = kill_switch_repo
        self._audit_repo = audit_repo
        self._id_factory = id_factory
        self._clock = clock

    def execute(
        self, *, managed_system_id: str, policy_pack_id: str, actor: Actor, correlation_id: str
    ) -> PolicyEvaluation:
        kill_switch_state = self._kill_switch_repo.get_state()
        if blocks_new_evaluations(kill_switch_state):
            raise EvaluationBlockedError(f"evaluations are blocked while mode={kill_switch_state.mode.value}")

        managed_system = self._managed_system_repo.get(managed_system_id)
        pack = self._policy_pack_repo.get(policy_pack_id)
        observed = self._observed_snapshot_repo.get_latest_for_system(managed_system_id)
        if observed is None:
            raise ValueError(f"no observed snapshot exists for managed system {managed_system_id}")
        desired = self._desired_snapshot_repo.get_latest_for_system(managed_system_id)
        desired_by_id = desired.resource_by_id() if desired is not None else {}
        active_exceptions = self._exception_repo.list_active_for_system(managed_system_id)

        evaluation_time = self._clock()
        findings = evaluate_policy_pack(
            pack=pack,
            resources=observed.resources,
            desired_by_resource_id=desired_by_id,
            managed_system=managed_system,
            baseline=desired.baseline if desired is not None else ArchitectureBaseline(),
            active_exceptions=active_exceptions,
            evaluation_time=evaluation_time,
            correlation_id=correlation_id,
            id_factory=self._id_factory,
        )
        created = self._finding_repo.create_many(list(findings)) if findings else []

        evaluation = PolicyEvaluation(
            evaluation_id=self._id_factory(),
            managed_system_id=managed_system_id,
            policy_pack_id=policy_pack_id,
            observed_snapshot_id=observed.snapshot_id,
            finding_ids=tuple(f.finding_id for f in created),
            resources_evaluated=len(observed.resources),
            correlation_id=correlation_id,
            evaluated_at=evaluation_time,
        )
        self._audit_repo.append(
            actor=actor.actor_id,
            actor_role=actor.role.value,
            action="POLICY_PACK_EVALUATED",
            resource_type="managed_system",
            resource_id=managed_system_id,
            correlation_id=correlation_id,
            payload={
                "policy_pack_id": policy_pack_id,
                "observed_snapshot_id": observed.snapshot_id,
                "finding_count": len(created),
            },
        )
        return evaluation
