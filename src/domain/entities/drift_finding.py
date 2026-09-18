from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from src.domain.enums.drift_type import DriftType
from src.domain.enums.finding_status import FindingStatus
from src.domain.enums.policy_severity import PolicySeverity


@dataclass(frozen=True, slots=True)
class DriftFinding:
    """One detected drift between desired and observed state (spec section
    8). Every field required by the spec's explanation contract is present
    and typed — never a free-text diff.
    """

    finding_id: str
    managed_system_id: str
    resource_id: str
    drift_type: DriftType
    what_changed: str
    previous_value: str | None
    current_value: str | None
    expected_value: str | None
    why_it_matters: str
    severity: PolicySeverity
    evidence: tuple[str, ...]
    remediation: str
    exception_eligible: bool
    correlation_id: str
    policy_id: str | None = None
    status: FindingStatus = FindingStatus.OPEN
    detected_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def with_status(self, status: FindingStatus) -> DriftFinding:
        import dataclasses

        return dataclasses.replace(self, status=status)
