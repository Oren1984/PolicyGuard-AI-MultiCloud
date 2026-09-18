from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from src.domain.enums.finding_status import FindingStatus
from src.domain.enums.policy_category import PolicyCategory
from src.domain.enums.policy_severity import PolicySeverity


@dataclass(frozen=True, slots=True)
class ComplianceFinding:
    """One deterministic policy violation found on one resource."""

    finding_id: str
    managed_system_id: str
    resource_id: str
    policy_id: str
    category: PolicyCategory
    severity: PolicySeverity
    title: str
    explanation: str
    evidence: tuple[str, ...]
    remediation_guidance: str
    exception_eligible: bool
    correlation_id: str
    status: FindingStatus = FindingStatus.OPEN
    detected_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def with_status(self, status: FindingStatus) -> ComplianceFinding:
        import dataclasses

        return dataclasses.replace(self, status=status)
