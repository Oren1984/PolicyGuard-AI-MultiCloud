"""Gate 5 of 5 (spec section 11): ensures AI advisory content does not
contradict the deterministic finding/decision it was generated to explain.

Unlike the other four gates, this one is a pure structural comparison
against `grounding_context` and is still meaningful even when Gate 1
(schema) failed on some other field -- checking for a contradiction in the
free-text `content` field does not depend on, say, `confidence` being in
range. The pipeline runner therefore still runs this gate when schema
validation fails upstream.
"""

from __future__ import annotations

from src.domain.entities.ai_advisory import AIAdvisoryContent
from src.domain.entities.gate_result import GateResult
from src.domain.enums.gate_name import GateName, GateStatus

_COMPLIANT_CLAIM_PHRASES = (
    "is compliant",
    "no violation",
    "no action needed",
    "safe to close",
    "fully compliant",
)
_LOW_RISK_CLAIM_PHRASES = ("low risk", "minor issue", "informational only", "not a concern")

# DecisionType values (as strings) that mean "this is not compliant" --
# an explanation that simultaneously claims compliance contradicts the
# deterministic decision it was generated to accompany.
_NON_COMPLIANT_DECISIONS = frozenset(
    {"remediation_required", "exception_review_required", "governance_block"}
)
_HIGH_SEVERITY_LABELS = frozenset({"HIGH", "CRITICAL"})


class ConsistencyGate:
    """AssuranceGate implementation for GateName.CONSISTENCY.

    `grounding_context` may carry `deterministic_decision` (a DecisionType
    value string) and `deterministic_severity` (a PolicySeverity label) --
    the deterministic facts this explanation must not contradict.
    """

    def evaluate(self, content: AIAdvisoryContent, *, grounding_context: dict) -> GateResult:
        haystack = content.content.lower()
        mismatches: list[str] = []

        decision = grounding_context.get("deterministic_decision")
        if decision in _NON_COMPLIANT_DECISIONS and any(p in haystack for p in _COMPLIANT_CLAIM_PHRASES):
            mismatches.append(
                f"content claims compliance/no-action while the deterministic decision is '{decision}'"
            )

        severity = grounding_context.get("deterministic_severity")
        if severity in _HIGH_SEVERITY_LABELS and any(p in haystack for p in _LOW_RISK_CLAIM_PHRASES):
            mismatches.append(f"content downplays risk while the deterministic severity is '{severity}'")

        if mismatches:
            return GateResult(
                gate=GateName.CONSISTENCY,
                status=GateStatus.WARNING,
                reason=(
                    "AI advisory content materially disagrees with deterministic findings/decisions; "
                    "mandatory human review required."
                ),
                details={"mismatches": mismatches},
            )

        return GateResult(
            gate=GateName.CONSISTENCY,
            status=GateStatus.PASSED,
            reason="AI advisory content is consistent with the deterministic findings/decisions.",
        )
