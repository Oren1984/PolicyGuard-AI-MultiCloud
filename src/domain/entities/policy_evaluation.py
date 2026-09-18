from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass(frozen=True, slots=True)
class PolicyEvaluation:
    """The aggregate record of one policy-pack run against one observed
    snapshot: which resources were checked, and which findings resulted."""

    evaluation_id: str
    managed_system_id: str
    policy_pack_id: str
    observed_snapshot_id: str
    finding_ids: tuple[str, ...]
    resources_evaluated: int
    correlation_id: str
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
