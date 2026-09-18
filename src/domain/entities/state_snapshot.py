from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from src.domain.entities.cloud_resource import CloudResource


@dataclass(frozen=True, slots=True)
class MaintenanceWindow:
    starts_at: datetime | None = None
    ends_at: datetime | None = None

    @property
    def is_defined(self) -> bool:
        return self.starts_at is not None and self.ends_at is not None


@dataclass(frozen=True, slots=True)
class ArchitectureBaseline:
    """The approved policy/architecture parameters a ManagedSystem is
    governed against, carried alongside the desired-state snapshot so
    evaluation is self-contained and reproducible."""

    allowed_regions: tuple[str, ...] = ()
    required_tag_keys: tuple[str, ...] = ()
    supported_runtime_versions: tuple[str, ...] = ()
    required_retention_days: int | None = None
    maintenance_window: MaintenanceWindow = field(default_factory=MaintenanceWindow)


@dataclass(frozen=True, slots=True)
class DesiredStateSnapshot:
    """The approved architecture: what the system is supposed to look like."""

    snapshot_id: str
    managed_system_id: str
    source: str  # e.g. "terraform-plan", "approved-architecture"
    resources: tuple[CloudResource, ...]
    baseline: ArchitectureBaseline
    submitted_by: str
    captured_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def resource_by_id(self) -> dict[str, CloudResource]:
        return {r.resource_id: r for r in self.resources}


@dataclass(frozen=True, slots=True)
class ObservedStateSnapshot:
    """A point-in-time capture of what the cloud inventory actually reports."""

    snapshot_id: str
    managed_system_id: str
    source: str  # e.g. mock inventory provider name
    resources: tuple[CloudResource, ...]
    captured_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    correlation_id: str | None = None

    def resource_by_id(self) -> dict[str, CloudResource]:
        return {r.resource_id: r for r in self.resources}
