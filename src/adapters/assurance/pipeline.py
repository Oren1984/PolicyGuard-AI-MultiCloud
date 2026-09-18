"""Runs all five mandatory AI assurance gates in order (spec section 11) and
fails closed to a deterministic fallback explanation if any gate FAILS.

Every gate result -- including SKIPPED ones -- is recorded in the returned
GatePipelineResult so a caller (a later phase's use case) can persist the
full pipeline outcome to the audit trail (spec: "record every gate result
in the audit trail"). This module itself performs no I/O -- it is a pure
orchestration layer over the five AssuranceGate implementations, consistent
with the AssuranceGate port's "no network calls, no mutation" contract.
"""

from __future__ import annotations

from src.adapters.assurance.confidence_gate import DEFAULT_THRESHOLDS, ConfidenceGate, ConfidenceThresholds
from src.adapters.assurance.consistency_gate import ConsistencyGate
from src.adapters.assurance.grounding_gate import GroundingGate
from src.adapters.assurance.safety_gate import SafetyGate
from src.adapters.assurance.schema_gate import SchemaGate
from src.domain.entities.ai_advisory import AIAdvisoryContent
from src.domain.entities.gate_result import GatePipelineResult, GateResult
from src.domain.enums.gate_name import GateName, GateStatus


def _skipped(gate: GateName, reason: str) -> GateResult:
    return GateResult(gate=gate, status=GateStatus.SKIPPED, reason=reason)


def build_fallback_advisory(kind: str, grounding_context: dict) -> AIAdvisoryContent:
    """Constructs a safe, deterministic AIAdvisoryContent from grounding
    context alone -- never from the rejected AI text -- used when the gate
    pipeline fails closed (spec: "use a deterministic fallback
    explanation")."""
    resource_id = grounding_context.get("resource_id", "the affected resource")
    parts = [
        f"An automated explanation for {resource_id} was withheld because it failed a "
        "mandatory AI assurance gate."
    ]
    policy_title = grounding_context.get("policy_title")
    if policy_title:
        parts.append(f"Deterministic policy: {policy_title}.")
    severity = grounding_context.get("deterministic_severity")
    if severity:
        parts.append(f"Severity: {severity}.")
    decision = grounding_context.get("deterministic_decision")
    if decision:
        parts.append(f"Governance decision: {decision}.")
    remediation = grounding_context.get("remediation_guidance")
    if remediation:
        parts.append(f"Remediation guidance: {remediation}.")
    parts.append("Refer to the deterministic finding record for full evidence.")

    return AIAdvisoryContent(
        provider_name="deterministic-fallback",
        kind=kind,
        content=" ".join(parts),
        referenced_evidence=(),
        confidence=1.0,
        raw_response={"fallback": True},
    )


class AssuranceGateRunner:
    """Concrete GatePipeline: runs the five AssuranceGate implementations in
    order and fails closed to a deterministic fallback on any FAILED gate.

    If Gate 1 (schema) fails, gates 2-4 (grounding/confidence/safety) are
    marked SKIPPED rather than run -- semantic checks on a structurally
    invalid response are meaningless. Gate 5 (consistency) always runs; it
    is a structural comparison against `grounding_context` independent of
    the response's own schema validity.
    """

    def __init__(self, confidence_thresholds: ConfidenceThresholds = DEFAULT_THRESHOLDS) -> None:
        self._schema_gate = SchemaGate()
        self._grounding_gate = GroundingGate()
        self._confidence_gate = ConfidenceGate(confidence_thresholds)
        self._safety_gate = SafetyGate()
        self._consistency_gate = ConsistencyGate()

    def run(
        self, content: AIAdvisoryContent, *, grounding_context: dict
    ) -> tuple[AIAdvisoryContent, GatePipelineResult]:
        schema_result = self._schema_gate.evaluate(content, grounding_context=grounding_context)

        if schema_result.status == GateStatus.FAILED:
            grounding_result = _skipped(GateName.GROUNDING, "skipped: Gate 1 (schema) failed upstream")
            confidence_result = _skipped(GateName.CONFIDENCE, "skipped: Gate 1 (schema) failed upstream")
            safety_result = _skipped(GateName.SAFETY, "skipped: Gate 1 (schema) failed upstream")
        else:
            grounding_result = self._grounding_gate.evaluate(content, grounding_context=grounding_context)
            confidence_result = self._confidence_gate.evaluate(content, grounding_context=grounding_context)
            safety_result = self._safety_gate.evaluate(content, grounding_context=grounding_context)

        consistency_result = self._consistency_gate.evaluate(content, grounding_context=grounding_context)

        pipeline_result = GatePipelineResult(
            results=(schema_result, grounding_result, confidence_result, safety_result, consistency_result)
        )

        if pipeline_result.any_failed:
            return build_fallback_advisory(content.kind, grounding_context), pipeline_result
        return content, pipeline_result
