"""Gate 1 of 5 (spec section 11): validates AIAdvisoryContent against its
exact expected output structure before any semantic gate runs."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from src.domain.entities.ai_advisory import AIAdvisoryContent
from src.domain.entities.gate_result import GateResult
from src.domain.enums.gate_name import GateName, GateStatus

AdvisoryKind = Literal["summary", "impact_explanation", "grouping", "remediation_outline"]


class _AIAdvisoryContentSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider_name: str
    kind: AdvisoryKind
    content: str
    referenced_evidence: tuple[str, ...] = ()
    confidence: float


class SchemaGate:
    """AssuranceGate implementation for GateName.SCHEMA."""

    def evaluate(self, content: AIAdvisoryContent, *, grounding_context: dict) -> GateResult:
        payload = {
            "provider_name": content.provider_name,
            "kind": content.kind,
            "content": content.content,
            "referenced_evidence": tuple(content.referenced_evidence),
            "confidence": content.confidence,
        }
        try:
            validated = _AIAdvisoryContentSchema.model_validate(payload)
        except ValidationError as exc:
            return GateResult(
                gate=GateName.SCHEMA,
                status=GateStatus.FAILED,
                reason="AI advisory content failed strict schema validation.",
                details={"errors": exc.errors(include_url=False)},
            )

        if not validated.content.strip():
            return GateResult(
                gate=GateName.SCHEMA,
                status=GateStatus.FAILED,
                reason="AI advisory content is empty.",
            )
        if not (0.0 <= validated.confidence <= 1.0):
            return GateResult(
                gate=GateName.SCHEMA,
                status=GateStatus.FAILED,
                reason=f"confidence {validated.confidence} is outside the valid [0.0, 1.0] range.",
            )

        return GateResult(
            gate=GateName.SCHEMA,
            status=GateStatus.PASSED,
            reason="AI advisory content conforms to the strict output schema.",
        )
