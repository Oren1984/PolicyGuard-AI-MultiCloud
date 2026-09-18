from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from src.domain.enums.decision_type import DecisionType


@dataclass(frozen=True, slots=True)
class GovernanceRoutingResult:
    """The pure output of the deterministic decision router
    (src/application/routing/decision_router.py). Deliberately excludes any
    identifier or timestamp — those are orchestration concerns, not
    decisions — so the router stays a pure function of its inputs.
    """

    decision: DecisionType
    reasons: tuple[str, ...]
    policy_ids: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class GovernanceDecision:
    """The persisted aggregate: a GovernanceRoutingResult plus the
    identifiers and timestamp needed to store and audit it."""

    decision_id: str
    managed_system_id: str
    finding_ids: tuple[str, ...]
    decision: DecisionType
    reasons: tuple[str, ...]
    policy_ids: tuple[str, ...]
    correlation_id: str
    decided_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def from_routing_result(
        cls,
        *,
        decision_id: str,
        managed_system_id: str,
        finding_ids: tuple[str, ...],
        result: GovernanceRoutingResult,
        correlation_id: str,
    ) -> GovernanceDecision:
        return cls(
            decision_id=decision_id,
            managed_system_id=managed_system_id,
            finding_ids=finding_ids,
            decision=result.decision,
            reasons=result.reasons,
            policy_ids=result.policy_ids,
            correlation_id=correlation_id,
        )
