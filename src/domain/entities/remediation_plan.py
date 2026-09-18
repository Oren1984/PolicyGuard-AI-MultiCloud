from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from src.domain.enums.remediation_status import RemediationStatus


@dataclass(frozen=True, slots=True)
class RemediationPlan:
    """Tracks human-driven remediation of a finding. PolicyGuard never
    performs remediation automatically (spec sections 3, 18, 25) — this
    entity only records status reported by an authorized human/operator
    workflow."""

    plan_id: str
    finding_id: str
    managed_system_id: str
    description: str
    status: RemediationStatus
    assigned_to: str | None
    correlation_id: str
    verification_evidence: tuple[str, ...] = ()
    due_by: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def with_status(self, status: RemediationStatus, *, updated_at: datetime) -> RemediationPlan:
        import dataclasses

        return dataclasses.replace(self, status=status, updated_at=updated_at)
