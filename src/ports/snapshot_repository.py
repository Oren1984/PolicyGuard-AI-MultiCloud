from __future__ import annotations

from typing import Protocol

from src.domain.entities.state_snapshot import DesiredStateSnapshot, ObservedStateSnapshot


class SnapshotNotFoundError(Exception):
    pass


class DesiredStateSnapshotRepository(Protocol):
    def create(self, snapshot: DesiredStateSnapshot) -> DesiredStateSnapshot: ...

    def get(self, snapshot_id: str) -> DesiredStateSnapshot:
        """Raises SnapshotNotFoundError if absent."""
        ...

    def get_latest_for_system(self, managed_system_id: str) -> DesiredStateSnapshot | None: ...

    def list_for_system(self, managed_system_id: str, *, limit: int = 50) -> list[DesiredStateSnapshot]: ...


class ObservedStateSnapshotRepository(Protocol):
    def create(self, snapshot: ObservedStateSnapshot) -> ObservedStateSnapshot: ...

    def get(self, snapshot_id: str) -> ObservedStateSnapshot:
        """Raises SnapshotNotFoundError if absent."""
        ...

    def get_latest_for_system(self, managed_system_id: str) -> ObservedStateSnapshot | None: ...

    def get_previous_for_system(
        self, managed_system_id: str, *, before_snapshot_id: str
    ) -> ObservedStateSnapshot | None:
        """The snapshot immediately preceding `before_snapshot_id`, used as
        the "previously observed state" input to drift detection."""
        ...

    def list_for_system(self, managed_system_id: str, *, limit: int = 50) -> list[ObservedStateSnapshot]: ...
