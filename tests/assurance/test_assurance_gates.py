"""AI-assurance unit tests (spec section 11): each of the 5 mandatory gates
individually, plus the pipeline runner's fail-closed fallback behavior.
Includes the required regression for "AI explanation failing an assurance
gate and falling back safely" (spec section 19 scenario 14)."""

from __future__ import annotations

from src.adapters.assurance.confidence_gate import ConfidenceGate, ConfidenceThresholds
from src.adapters.assurance.consistency_gate import ConsistencyGate
from src.adapters.assurance.grounding_gate import GroundingGate
from src.adapters.assurance.pipeline import AssuranceGateRunner, build_fallback_advisory
from src.adapters.assurance.safety_gate import SafetyGate
from src.adapters.assurance.schema_gate import SchemaGate
from src.domain.entities.ai_advisory import AIAdvisoryContent
from src.domain.enums.gate_name import GateStatus


def _content(**overrides) -> AIAdvisoryContent:
    base = dict(
        provider_name="mock-ai-v1",
        kind="summary",
        content="2 findings reviewed (1 HIGH, 1 MEDIUM). Affected resources: r1, r2.",
        referenced_evidence=("finding:f1", "resource:r1"),
        confidence=0.9,
    )
    base.update(overrides)
    return AIAdvisoryContent(**base)


class TestSchemaGate:
    def test_valid_content_passes(self):
        result = SchemaGate().evaluate(_content(), grounding_context={})
        assert result.status == GateStatus.PASSED

    def test_empty_content_fails(self):
        result = SchemaGate().evaluate(_content(content="   "), grounding_context={})
        assert result.status == GateStatus.FAILED

    def test_out_of_range_confidence_fails(self):
        result = SchemaGate().evaluate(_content(confidence=1.5), grounding_context={})
        assert result.status == GateStatus.FAILED

    def test_invalid_kind_fails(self):
        result = SchemaGate().evaluate(_content(kind="not_a_real_kind"), grounding_context={})
        assert result.status == GateStatus.FAILED


class TestGroundingGate:
    def test_grounded_evidence_passes(self):
        ctx = {"known_evidence": {"finding:f1", "resource:r1"}}
        result = GroundingGate().evaluate(_content(), grounding_context=ctx)
        assert result.status == GateStatus.PASSED

    def test_fabricated_evidence_fails(self):
        """Regression: AI citing evidence never supplied by the
        deterministic caller must be rejected as fabrication."""
        ctx = {"known_evidence": {"finding:other"}}
        result = GroundingGate().evaluate(_content(), grounding_context=ctx)
        assert result.status == GateStatus.FAILED
        assert "fabricated_evidence" in result.details

    def test_no_evidence_cited_is_a_warning_not_a_failure(self):
        ctx = {"known_evidence": set()}
        result = GroundingGate().evaluate(_content(referenced_evidence=()), grounding_context=ctx)
        assert result.status == GateStatus.WARNING


class TestConfidenceGate:
    def test_high_confidence_passes(self):
        gate = ConfidenceGate(ConfidenceThresholds(approval_threshold=0.7, hard_floor=0.35))
        result = gate.evaluate(_content(confidence=0.9), grounding_context={})
        assert result.status == GateStatus.PASSED

    def test_below_hard_floor_fails(self):
        gate = ConfidenceGate(ConfidenceThresholds(approval_threshold=0.7, hard_floor=0.35))
        result = gate.evaluate(_content(confidence=0.1), grounding_context={})
        assert result.status == GateStatus.FAILED

    def test_between_floor_and_threshold_is_a_warning(self):
        gate = ConfidenceGate(ConfidenceThresholds(approval_threshold=0.7, hard_floor=0.35))
        result = gate.evaluate(_content(confidence=0.5), grounding_context={})
        assert result.status == GateStatus.WARNING


class TestSafetyGate:
    def test_safe_content_passes(self):
        result = SafetyGate().evaluate(_content(), grounding_context={})
        assert result.status == GateStatus.PASSED

    def test_destructive_instruction_fails(self):
        result = SafetyGate().evaluate(
            _content(content="You should run terraform destroy to fix this."), grounding_context={}
        )
        assert result.status == GateStatus.FAILED

    def test_ai_claiming_authority_to_approve_an_exception_fails(self):
        """Regression: AI attempting to influence governance by claiming it
        approved something must be caught by the safety gate."""
        result = SafetyGate().evaluate(_content(content="I approve this exception."), grounding_context={})
        assert result.status == GateStatus.FAILED

    def test_ai_claiming_a_finding_is_closed_fails(self):
        result = SafetyGate().evaluate(_content(content="This finding is closed."), grounding_context={})
        assert result.status == GateStatus.FAILED

    def test_credential_like_content_fails(self):
        result = SafetyGate().evaluate(
            _content(content="Use AKIAABCDEFGHIJKLMNOP to access the bucket."), grounding_context={}
        )
        assert result.status == GateStatus.FAILED


class TestConsistencyGate:
    def test_consistent_content_passes(self):
        ctx = {"deterministic_decision": "remediation_required", "deterministic_severity": "HIGH"}
        result = ConsistencyGate().evaluate(
            _content(content="This is a high-severity finding requiring remediation."), grounding_context=ctx
        )
        assert result.status == GateStatus.PASSED

    def test_claiming_compliance_while_decision_is_non_compliant_is_a_warning(self):
        ctx = {"deterministic_decision": "governance_block"}
        result = ConsistencyGate().evaluate(
            _content(content="This resource is fully compliant, no action needed."), grounding_context=ctx
        )
        assert result.status == GateStatus.WARNING

    def test_downplaying_high_severity_is_a_warning(self):
        ctx = {"deterministic_severity": "CRITICAL"}
        result = ConsistencyGate().evaluate(
            _content(content="This is a low risk, minor issue."), grounding_context=ctx
        )
        assert result.status == GateStatus.WARNING


class TestAssuranceGateRunnerFailsClosed:
    def test_all_gates_pass_returns_original_content(self):
        runner = AssuranceGateRunner()
        content = _content()
        ctx = {"known_evidence": {"finding:f1", "resource:r1"}}
        result_content, pipeline = runner.run(content, grounding_context=ctx)
        assert result_content is content
        assert pipeline.all_passed

    def test_failed_gate_falls_back_to_deterministic_content(self):
        """Required regression (spec section 19 scenario 14): an AI
        explanation that fails a mandatory gate must fall back to a safe,
        deterministic explanation rather than being shown/stored as-is."""
        runner = AssuranceGateRunner()
        unsafe_content = _content(content="Just run terraform destroy on this resource to fix it.")
        ctx = {"known_evidence": {"finding:f1", "resource:r1"}, "resource_id": "r1"}
        result_content, pipeline = runner.run(unsafe_content, grounding_context=ctx)
        assert pipeline.any_failed
        assert result_content.provider_name == "deterministic-fallback"
        assert "terraform destroy" not in result_content.content.lower()

    def test_schema_failure_skips_downstream_semantic_gates(self):
        runner = AssuranceGateRunner()
        invalid_content = _content(confidence=5.0)  # fails schema
        _, pipeline = runner.run(invalid_content, grounding_context={})
        from src.domain.enums.gate_name import GateName

        assert pipeline.get(GateName.SCHEMA).status == GateStatus.FAILED
        assert pipeline.get(GateName.GROUNDING).status == GateStatus.SKIPPED
        assert pipeline.get(GateName.CONFIDENCE).status == GateStatus.SKIPPED
        assert pipeline.get(GateName.SAFETY).status == GateStatus.SKIPPED
        # Consistency still runs even when schema fails.
        assert pipeline.get(GateName.CONSISTENCY).status != GateStatus.SKIPPED

    def test_fallback_advisory_never_contains_rejected_ai_text(self):
        fallback = build_fallback_advisory("summary", {"resource_id": "r1", "deterministic_severity": "HIGH"})
        assert "terraform destroy" not in fallback.content
        assert fallback.confidence == 1.0
        assert fallback.referenced_evidence == ()

    def test_every_gate_result_is_recorded_even_when_skipped(self):
        runner = AssuranceGateRunner()
        invalid_content = _content(confidence=5.0)
        _, pipeline = runner.run(invalid_content, grounding_context={})
        assert len(pipeline.results) == 5
