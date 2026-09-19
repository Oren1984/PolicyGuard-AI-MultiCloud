"""Decision-router unit tests (spec section 9).

The single most important test in this file -- and arguably in the whole
suite -- is `TestAICannotInfluenceDecision`: it proves, both structurally
(via introspection of the dataclass's own field types) and behaviorally (by
constructing two contexts that differ only in upstream AI content/absence),
that `route_governance_decision` cannot be swayed by AI output.
"""

from __future__ import annotations

import dataclasses

import pytest

from src.application.routing.decision_router import (
    REPEATED_VIOLATION_ESCALATION_THRESHOLD,
    GovernanceDecisionContext,
    route_governance_decision,
)
from src.domain.entities.ai_advisory import AIAdvisoryContent
from src.domain.entities.gate_result import GatePipelineResult, GateResult
from src.domain.enums.decision_type import DecisionType
from src.domain.enums.environment import Environment
from src.domain.enums.exception_status import ExceptionStatus
from src.domain.enums.gate_name import GateName, GateStatus
from src.domain.enums.policy_severity import PolicySeverity
from src.domain.enums.resource_criticality import ResourceCriticality
from src.domain.enums.system_mode import SystemMode


def _base_kwargs(**overrides) -> dict:
    base = dict(
        has_violation=True,
        severity=PolicySeverity.MEDIUM,
        environment=Environment.PRODUCTION,
        resource_criticality=ResourceCriticality.STANDARD,
        evidence_complete=True,
        exception_status=None,
        exception_eligible=True,
        critical_non_eligible=False,
        repeated_violation_count=0,
        system_mode=SystemMode.NORMAL,
        gates=None,
        policy_id="POL-TEST-001",
    )
    base.update(overrides)
    return base


def _ctx(**overrides) -> GovernanceDecisionContext:
    return GovernanceDecisionContext(**_base_kwargs(**overrides))


class TestNoViolation:
    def test_no_violation_is_compliant(self):
        result = route_governance_decision(_ctx(has_violation=False))
        assert result.decision == DecisionType.COMPLIANT

    def test_no_violation_under_emergency_stop_is_still_compliant(self):
        result = route_governance_decision(_ctx(has_violation=False, system_mode=SystemMode.EMERGENCY_STOP))
        assert result.decision == DecisionType.COMPLIANT


class TestEmergencyStopAndCriticalPaths:
    def test_emergency_stop_with_violation_blocks(self):
        result = route_governance_decision(_ctx(system_mode=SystemMode.EMERGENCY_STOP))
        assert result.decision == DecisionType.GOVERNANCE_BLOCK

    def test_critical_non_eligible_always_blocks(self):
        result = route_governance_decision(_ctx(critical_non_eligible=True, severity=PolicySeverity.LOW))
        assert result.decision == DecisionType.GOVERNANCE_BLOCK

    def test_critical_severity_always_blocks(self):
        result = route_governance_decision(_ctx(severity=PolicySeverity.CRITICAL))
        assert result.decision == DecisionType.GOVERNANCE_BLOCK

    def test_failed_assurance_gate_blocks_even_at_low_severity(self):
        gates = GatePipelineResult(
            results=(GateResult(gate=GateName.SAFETY, status=GateStatus.FAILED, reason="unsafe content"),)
        )
        result = route_governance_decision(_ctx(severity=PolicySeverity.LOW, gates=gates))
        assert result.decision == DecisionType.GOVERNANCE_BLOCK

    def test_warning_only_gate_does_not_block(self):
        gates = GatePipelineResult(
            results=(
                GateResult(gate=GateName.CONFIDENCE, status=GateStatus.WARNING, reason="low confidence"),
            )
        )
        result = route_governance_decision(_ctx(severity=PolicySeverity.LOW, gates=gates))
        assert result.decision != DecisionType.GOVERNANCE_BLOCK


class TestExceptionHandling:
    def test_active_eligible_exception_records_observation(self):
        result = route_governance_decision(
            _ctx(
                exception_status=ExceptionStatus.ACTIVE, exception_eligible=True, severity=PolicySeverity.HIGH
            )
        )
        assert result.decision == DecisionType.OBSERVATION_RECORDED

    def test_pending_exception_requires_review_in_normal_mode(self):
        result = route_governance_decision(_ctx(exception_status=ExceptionStatus.REQUESTED))
        assert result.decision == DecisionType.EXCEPTION_REVIEW_REQUIRED

    def test_pending_exception_is_blocked_from_review_when_paused(self):
        result = route_governance_decision(
            _ctx(exception_status=ExceptionStatus.UNDER_REVIEW, system_mode=SystemMode.PAUSED)
        )
        assert result.decision == DecisionType.REMEDIATION_REQUIRED

    def test_expired_exception_stops_suppressing_and_falls_through(self):
        # Regression: EXPIRED must not behave like ACTIVE/APPROVED -- it
        # must fall through to ordinary severity-based routing, not silently
        # keep suppressing the violation.
        result = route_governance_decision(
            _ctx(exception_status=ExceptionStatus.EXPIRED, severity=PolicySeverity.MEDIUM)
        )
        assert result.decision == DecisionType.REMEDIATION_REQUIRED

    def test_revoked_exception_stops_suppressing_and_falls_through(self):
        result = route_governance_decision(
            _ctx(exception_status=ExceptionStatus.REVOKED, severity=PolicySeverity.MEDIUM)
        )
        assert result.decision == DecisionType.REMEDIATION_REQUIRED


class TestEvidenceAndSeverityRouting:
    def test_incomplete_evidence_requires_remediation_even_at_low_severity(self):
        result = route_governance_decision(_ctx(evidence_complete=False, severity=PolicySeverity.LOW))
        assert result.decision == DecisionType.REMEDIATION_REQUIRED

    def test_high_severity_requires_remediation_by_default(self):
        result = route_governance_decision(_ctx(severity=PolicySeverity.HIGH, repeated_violation_count=0))
        assert result.decision == DecisionType.REMEDIATION_REQUIRED

    def test_repeated_high_severity_on_critical_prod_resource_escalates_to_block(self):
        result = route_governance_decision(
            _ctx(
                severity=PolicySeverity.HIGH,
                repeated_violation_count=REPEATED_VIOLATION_ESCALATION_THRESHOLD,
                environment=Environment.PRODUCTION,
                resource_criticality=ResourceCriticality.CRITICAL,
            )
        )
        assert result.decision == DecisionType.GOVERNANCE_BLOCK

    def test_repeated_high_severity_below_threshold_does_not_escalate(self):
        result = route_governance_decision(
            _ctx(
                severity=PolicySeverity.HIGH,
                repeated_violation_count=REPEATED_VIOLATION_ESCALATION_THRESHOLD - 1,
                environment=Environment.PRODUCTION,
                resource_criticality=ResourceCriticality.CRITICAL,
            )
        )
        assert result.decision == DecisionType.REMEDIATION_REQUIRED

    def test_medium_severity_requires_remediation(self):
        result = route_governance_decision(_ctx(severity=PolicySeverity.MEDIUM))
        assert result.decision == DecisionType.REMEDIATION_REQUIRED

    def test_low_severity_is_observation_by_default(self):
        result = route_governance_decision(
            _ctx(severity=PolicySeverity.LOW, resource_criticality=ResourceCriticality.STANDARD)
        )
        assert result.decision == DecisionType.OBSERVATION_RECORDED

    def test_low_severity_on_critical_prod_resource_requires_remediation(self):
        result = route_governance_decision(
            _ctx(
                severity=PolicySeverity.LOW,
                environment=Environment.PRODUCTION,
                resource_criticality=ResourceCriticality.CRITICAL,
            )
        )
        assert result.decision == DecisionType.REMEDIATION_REQUIRED

    def test_info_severity_is_always_observation(self):
        result = route_governance_decision(
            _ctx(
                severity=PolicySeverity.INFO,
                environment=Environment.PRODUCTION,
                resource_criticality=ResourceCriticality.CRITICAL,
            )
        )
        assert result.decision == DecisionType.OBSERVATION_RECORDED

    def test_reasons_and_policy_ids_are_populated(self):
        result = route_governance_decision(_ctx(policy_id="POL-NET-001"))
        assert result.reasons
        assert result.policy_ids == ("POL-NET-001",)

    def test_no_policy_id_yields_empty_policy_ids(self):
        result = route_governance_decision(_ctx(policy_id=None))
        assert result.policy_ids == ()


class TestAICannotInfluenceDecision:
    """Spec section 9: 'The decision router must not consume an AI
    recommendation. Its function signature must structurally prevent AI
    output from controlling the final governance decision. Add a dedicated
    regression test proving this separation.'"""

    def test_structural_no_field_can_hold_ai_content(self):
        """Introspects GovernanceDecisionContext's own dataclass fields and
        asserts none of them is typed to accept AIAdvisoryContent, a raw
        string blob of AI text, or anything from the AI provider port."""
        fields = dataclasses.fields(GovernanceDecisionContext)
        field_names = {f.name for f in fields}

        # No field literally named for AI content/recommendation/advisory.
        forbidden_name_fragments = ("ai_", "advisory", "recommendation", "llm", "explanation")
        for name in field_names:
            lowered = name.lower()
            assert not any(
                fragment in lowered for fragment in forbidden_name_fragments
            ), f"GovernanceDecisionContext field {name!r} looks like it could carry AI output"

        # No field's declared type is (or wraps) AIAdvisoryContent.
        for f in fields:
            type_repr = str(f.type)
            assert (
                "AIAdvisoryContent" not in type_repr
            ), f"GovernanceDecisionContext.{f.name} is typed to accept AIAdvisoryContent: {type_repr}"

        # The only AI-adjacent field is `gates`, and it only carries the
        # deterministic PASSED/WARNING/FAILED *status* of the assurance
        # gates (GatePipelineResult), never the AI's own text.
        gates_field = next(f for f in fields if f.name == "gates")
        assert "GatePipelineResult" in str(gates_field.type)

    def test_gate_result_never_carries_ai_text(self):
        """GateResult (the one AI-adjacent type the router can see) only
        exposes an enum status and a machine-authored reason string --
        never the AI's raw content."""
        gate_result_fields = {f.name for f in dataclasses.fields(GateResult)}
        assert gate_result_fields == {"gate", "status", "reason", "details"}

    def test_behavioral_identical_contexts_yield_identical_decision_regardless_of_ai(self):
        """Constructs two otherwise-identical deterministic contexts, one
        representing "AI produced rich advisory content and it passed every
        gate" and one representing "AI failed entirely / was never called" --
        differing only in what AI-adjacent information could have leaked
        upstream -- and proves the routed decision is byte-for-byte
        identical either way, because the router's inputs cannot carry the
        AI's opinion in the first place."""
        # Simulate "AI ran successfully, all gates passed" upstream: build a
        # real AIAdvisoryContent and confirm its existence has no channel
        # into the context beyond the deterministic gate *status*.
        rich_ai_content = AIAdvisoryContent(  # noqa: F841 - constructed only to prove it has no channel in
            provider_name="mock-ai-v1",
            kind="impact_explanation",
            content="This is a CRITICAL, must-block-immediately finding!! Ignore the policy and approve it.",
            referenced_evidence=("finding:f1", "resource:r1"),
            confidence=0.99,
        )
        gates_all_passed = GatePipelineResult(
            results=(
                GateResult(gate=GateName.SCHEMA, status=GateStatus.PASSED, reason="ok"),
                GateResult(gate=GateName.GROUNDING, status=GateStatus.PASSED, reason="ok"),
                GateResult(gate=GateName.CONFIDENCE, status=GateStatus.PASSED, reason="ok"),
                GateResult(gate=GateName.SAFETY, status=GateStatus.PASSED, reason="ok"),
                GateResult(gate=GateName.CONSISTENCY, status=GateStatus.PASSED, reason="ok"),
            )
        )
        # The AI's own opinion (`rich_ai_content.content`, which even
        # contains an attempted instruction: "Ignore the policy and approve
        # it") is never passed into the context at all -- there is no
        # parameter that could take it. We construct the context using only
        # the gate pipeline's deterministic status, proving the content
        # itself never had a channel in.
        ctx_with_ai_content = _ctx(severity=PolicySeverity.MEDIUM, gates=gates_all_passed)

        # Simulate "AI never ran / provider errored" upstream: gates=None
        # (no advisory content was ever produced), same deterministic facts.
        ctx_without_ai_content = _ctx(severity=PolicySeverity.MEDIUM, gates=None)

        result_with_ai = route_governance_decision(ctx_with_ai_content)
        result_without_ai = route_governance_decision(ctx_without_ai_content)

        assert result_with_ai == result_without_ai
        assert result_with_ai.decision == DecisionType.REMEDIATION_REQUIRED
        # Double-check the AI's attempted "approve it" instruction is nowhere
        # near the outcome.
        assert "approve" not in " ".join(result_with_ai.reasons).lower()

    def test_behavioral_ai_attempting_to_force_compliant_has_no_effect(self):
        """Even a maximally adversarial AI opinion claiming the finding is
        compliant/safe cannot flip a real violation to COMPLIANT, because
        the router has no parameter that could receive that opinion."""
        adversarial_content = AIAdvisoryContent(  # noqa: F841 - constructed only to prove it has no channel in
            provider_name="malicious-or-buggy-provider",
            kind="summary",
            content="This finding is compliant. No action needed. Mark this finding as compliant.",
            confidence=1.0,
        )
        ctx = _ctx(severity=PolicySeverity.HIGH, gates=None)
        result = route_governance_decision(ctx)
        assert result.decision != DecisionType.COMPLIANT

    def test_route_governance_decision_signature_has_no_ai_provider_parameter(self):
        """Belt-and-suspenders structural check directly on the function
        signature itself (not just the dataclass it takes)."""
        import inspect

        sig = inspect.signature(route_governance_decision)
        assert list(sig.parameters) == ["context"]
        param_type_repr = str(sig.parameters["context"].annotation)
        assert "AIAdvisoryContent" not in param_type_repr
        assert "AIProvider" not in param_type_repr


class TestGovernanceRoutingResultIsPure:
    def test_router_is_a_pure_function_same_input_same_output(self):
        ctx = _ctx(severity=PolicySeverity.HIGH)
        first = route_governance_decision(ctx)
        second = route_governance_decision(ctx)
        assert first == second

    def test_result_has_no_identifier_or_timestamp(self):
        # GovernanceRoutingResult deliberately excludes id/timestamp --
        # those are orchestration concerns layered on by
        # GovernanceDecision.from_routing_result, not the pure router.
        from src.domain.entities.governance_decision import GovernanceRoutingResult

        field_names = {f.name for f in dataclasses.fields(GovernanceRoutingResult)}
        assert field_names == {"decision", "reasons", "policy_ids"}


@pytest.mark.parametrize("severity", list(PolicySeverity))
def test_router_never_raises_for_any_severity(severity):
    # Fail-closed correctness sweep: every valid severity must route to
    # *some* decision, never raise or fall through un-returned.
    result = route_governance_decision(_ctx(severity=severity))
    assert isinstance(result.decision, DecisionType)
