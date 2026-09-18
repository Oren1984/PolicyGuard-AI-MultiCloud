"""Gate 2 of 5 (spec section 11): ensures every evidence reference in AI
advisory content is grounded in deterministic evidence the caller actually
supplied -- never fabricated."""

from __future__ import annotations

from src.domain.entities.ai_advisory import AIAdvisoryContent
from src.domain.entities.gate_result import GateResult
from src.domain.enums.gate_name import GateName, GateStatus


class GroundingGate:
    """AssuranceGate implementation for GateName.GROUNDING.

    `grounding_context["known_evidence"]` must be an iterable of evidence
    identifiers (e.g. "finding:...", "resource:...", "policy:...") supplied
    by the deterministic caller -- never derived from the AI's own output.
    """

    def evaluate(self, content: AIAdvisoryContent, *, grounding_context: dict) -> GateResult:
        if not content.referenced_evidence:
            return GateResult(
                gate=GateName.GROUNDING,
                status=GateStatus.WARNING,
                reason="AI advisory content cited no evidence; mandatory human review required.",
            )

        known = set(grounding_context.get("known_evidence", ()))
        fabricated = [item for item in content.referenced_evidence if item not in known]
        if fabricated:
            return GateResult(
                gate=GateName.GROUNDING,
                status=GateStatus.FAILED,
                reason=(
                    "AI advisory content references evidence not present in the supplied "
                    "context (fabrication)."
                ),
                details={"fabricated_evidence": fabricated},
            )

        return GateResult(
            gate=GateName.GROUNDING,
            status=GateStatus.PASSED,
            reason="Every referenced evidence item is grounded in the supplied context.",
            details={"evidence_count": len(content.referenced_evidence)},
        )
