from __future__ import annotations

from typing import Protocol

from src.domain.entities.governance_decision import GovernanceDecision


class GovernanceDecisionNotFoundError(Exception):
    pass


class GovernanceDecisionRepository(Protocol):
    def create(self, decision: GovernanceDecision) -> GovernanceDecision: ...

    def get(self, decision_id: str) -> GovernanceDecision:
        """Raises GovernanceDecisionNotFoundError if absent."""
        ...

    def list(
        self, *, managed_system_id: str | None = None, limit: int = 50, offset: int = 0
    ) -> tuple[list[GovernanceDecision], int]: ...
