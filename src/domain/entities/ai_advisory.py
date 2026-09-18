from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass(frozen=True, slots=True)
class AIAdvisoryContent:
    """Advisory-only AI output (spec section 10). Untrusted until it has
    passed all five AI assurance gates (section 11 — gate interfaces only in
    this phase). Must never be granted authority to determine compliance,
    change severity, approve exceptions, close findings, or influence the
    governance decision router in any way.
    """

    provider_name: str
    kind: str  # "summary" | "impact_explanation" | "grouping" | "remediation_outline"
    content: str
    referenced_evidence: tuple[str, ...] = ()
    confidence: float = 0.0  # 0.0 - 1.0
    raw_response: dict = field(default_factory=dict)
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
