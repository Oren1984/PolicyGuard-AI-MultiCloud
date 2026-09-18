from __future__ import annotations

from typing import Protocol

from src.domain.entities.ai_advisory import AIAdvisoryContent
from src.domain.entities.gate_result import GateResult


class AssuranceGate(Protocol):
    """Contract for one of the five mandatory AI assurance gates (spec
    section 11): Schema, Grounding, Confidence, Safety, Consistency.

    Only the interface is defined in this phase — concrete gate
    implementations (and the pipeline that chains all five and fails
    closed on any mandatory failure) are built in a later phase. Every
    implementation must remain a pure function of its inputs: no network
    calls, no mutation of the content it is validating.
    """

    def evaluate(self, content: AIAdvisoryContent, *, grounding_context: dict) -> GateResult:
        """Return this gate's PASSED/WARNING/FAILED result for the given
        advisory content. `grounding_context` carries whatever deterministic
        evidence (findings, policies, resources) the gate needs to check
        the content against — never AI-generated data itself."""
        ...
