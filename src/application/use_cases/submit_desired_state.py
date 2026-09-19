from __future__ import annotations

from src.domain.entities.actor import Actor
from src.domain.entities.state_snapshot import DesiredStateSnapshot
from src.ports.audit_repository import AuditEventRepository
from src.ports.snapshot_repository import DesiredStateSnapshotRepository


class SubmitDesiredStateSnapshotUseCase:
    """Persists an approved desired-state snapshot (spec section 15,
    "Submit desired-state snapshots"). This represents the approved
    architecture a system is governed against."""

    def __init__(
        self, snapshot_repo: DesiredStateSnapshotRepository, audit_repo: AuditEventRepository
    ) -> None:
        self._snapshot_repo = snapshot_repo
        self._audit_repo = audit_repo

    def execute(
        self, snapshot: DesiredStateSnapshot, *, actor: Actor, correlation_id: str
    ) -> DesiredStateSnapshot:
        created = self._snapshot_repo.create(snapshot)
        self._audit_repo.append(
            actor=actor.actor_id,
            actor_role=actor.role.value,
            action="DESIRED_STATE_SNAPSHOT_SUBMITTED",
            resource_type="desired_state_snapshot",
            resource_id=created.snapshot_id,
            correlation_id=correlation_id,
            payload={
                "managed_system_id": created.managed_system_id,
                "resource_count": len(created.resources),
                "source": created.source,
            },
        )
        return created
