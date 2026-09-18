from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from src.domain.drift.detector import detect_drift
from src.domain.entities.actor import Actor
from src.domain.entities.drift_finding import DriftFinding
from src.domain.policies.kill_switch_policy import blocks_new_evaluations
from src.ports.audit_repository import AuditEventRepository
from src.ports.exception_repository import PolicyExceptionRepository
from src.ports.finding_repository import DriftFindingRepository
from src.ports.kill_switch_repository import KillSwitchRepository
from src.ports.snapshot_repository import DesiredStateSnapshotRepository, ObservedStateSnapshotRepository


class DriftDetectionBlockedError(Exception):
    """Fail closed: no new drift evaluation may run while PAUSED or
    EMERGENCY_STOP (spec section 13)."""


class DriftMissingSnapshotError(Exception):
    pass


class DetectDriftUseCase:
    """Compares approved desired state, previously observed state, and the
    current observed snapshot for a managed system, producing DriftFindings
    (spec section 8)."""

    def __init__(
        self,
        *,
        desired_snapshot_repo: DesiredStateSnapshotRepository,
        observed_snapshot_repo: ObservedStateSnapshotRepository,
        drift_finding_repo: DriftFindingRepository,
        exception_repo: PolicyExceptionRepository,
        kill_switch_repo: KillSwitchRepository,
        audit_repo: AuditEventRepository,
        id_factory: Callable[[], str],
        clock: Callable[[], datetime],
    ) -> None:
        self._desired_snapshot_repo = desired_snapshot_repo
        self._observed_snapshot_repo = observed_snapshot_repo
        self._drift_finding_repo = drift_finding_repo
        self._exception_repo = exception_repo
        self._kill_switch_repo = kill_switch_repo
        self._audit_repo = audit_repo
        self._id_factory = id_factory
        self._clock = clock

    def execute(
        self, *, managed_system_id: str, actor: Actor, correlation_id: str
    ) -> tuple[DriftFinding, ...]:
        kill_switch_state = self._kill_switch_repo.get_state()
        if blocks_new_evaluations(kill_switch_state):
            raise DriftDetectionBlockedError(
                f"drift detection is blocked while mode={kill_switch_state.mode.value}"
            )

        desired = self._desired_snapshot_repo.get_latest_for_system(managed_system_id)
        current = self._observed_snapshot_repo.get_latest_for_system(managed_system_id)
        if desired is None or current is None:
            raise DriftMissingSnapshotError(
                f"managed system {managed_system_id} requires both a desired and an observed snapshot"
            )
        previous = self._observed_snapshot_repo.get_previous_for_system(
            managed_system_id, before_snapshot_id=current.snapshot_id
        )
        active_exceptions = self._exception_repo.list_active_for_system(managed_system_id)

        evaluation_time = self._clock()
        findings = detect_drift(
            desired=desired,
            previous_observed=previous,
            current_observed=current,
            active_exceptions=active_exceptions,
            evaluation_time=evaluation_time,
            correlation_id=correlation_id,
            id_factory=self._id_factory,
        )
        created = self._drift_finding_repo.create_many(list(findings)) if findings else ()

        self._audit_repo.append(
            actor=actor.actor_id,
            actor_role=actor.role.value,
            action="DRIFT_DETECTION_RUN",
            resource_type="managed_system",
            resource_id=managed_system_id,
            correlation_id=correlation_id,
            payload={
                "desired_snapshot_id": desired.snapshot_id,
                "current_snapshot_id": current.snapshot_id,
                "previous_snapshot_id": previous.snapshot_id if previous else None,
                "finding_count": len(created),
            },
        )
        return tuple(created)
