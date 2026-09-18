from __future__ import annotations

from typing import Protocol

from src.domain.entities.compliance_finding import ComplianceFinding
from src.domain.entities.drift_finding import DriftFinding
from src.domain.enums.finding_status import FindingStatus


class FindingNotFoundError(Exception):
    pass


class ComplianceFindingRepository(Protocol):
    def create_many(self, findings: list[ComplianceFinding]) -> list[ComplianceFinding]: ...

    def get(self, finding_id: str) -> ComplianceFinding:
        """Raises FindingNotFoundError if absent."""
        ...

    def list(
        self,
        *,
        managed_system_id: str | None = None,
        status: FindingStatus | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[ComplianceFinding], int]: ...

    def update_status(self, finding_id: str, status: FindingStatus) -> ComplianceFinding: ...

    def count_recent_violations(
        self, *, policy_id: str, resource_id: str, within_last: int
    ) -> int:
        """Count of prior findings for this policy+resource, used as the
        decision router's "repeated violations" input."""
        ...


class DriftFindingRepository(Protocol):
    def create_many(self, findings: list[DriftFinding]) -> list[DriftFinding]: ...

    def get(self, finding_id: str) -> DriftFinding:
        """Raises FindingNotFoundError if absent."""
        ...

    def list(
        self,
        *,
        managed_system_id: str | None = None,
        status: FindingStatus | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[DriftFinding], int]: ...

    def update_status(self, finding_id: str, status: FindingStatus) -> DriftFinding: ...
