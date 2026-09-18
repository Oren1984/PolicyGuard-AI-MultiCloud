from __future__ import annotations

from typing import Protocol

from src.domain.entities.remediation_plan import RemediationPlan
from src.domain.enums.remediation_status import RemediationStatus


class RemediationPlanNotFoundError(Exception):
    pass


class RemediationPlanRepository(Protocol):
    def create(self, plan: RemediationPlan) -> RemediationPlan: ...

    def get(self, plan_id: str) -> RemediationPlan:
        """Raises RemediationPlanNotFoundError if absent."""
        ...

    def get_for_finding(self, finding_id: str) -> RemediationPlan | None: ...

    def update_status(
        self, plan_id: str, status: RemediationStatus, *, verification_evidence: tuple[str, ...] = ()
    ) -> RemediationPlan: ...

    def list(
        self, *, managed_system_id: str | None = None, limit: int = 50, offset: int = 0
    ) -> tuple[list[RemediationPlan], int]: ...
