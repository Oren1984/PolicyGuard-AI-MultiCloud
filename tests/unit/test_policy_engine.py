"""Policy-engine unit tests (spec section 7): the 20 required deterministic
policy categories, evaluated as pure functions with no I/O and no LLM call.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

import pytest

from src.domain.entities.cloud_resource import CloudResource, ResourceAttributes
from src.domain.entities.policy import PolicyEvaluationContext
from src.domain.entities.state_snapshot import ArchitectureBaseline
from src.domain.enums.cloud_provider import CloudProvider
from src.domain.enums.environment import Environment
from src.domain.enums.exception_status import ExceptionStatus
from src.domain.enums.policy_severity import PolicySeverity
from src.domain.enums.resource_criticality import ResourceCriticality
from src.domain.enums.resource_type import ResourceType
from src.domain.policy_engine.definitions import build_default_policy_pack
from src.domain.policy_engine.evaluator import evaluate_policy_pack
from tests.fixtures.builders import build_managed_system, build_resource

_POLICY_ID_PATTERN = re.compile(r"^POL-[A-Z]{3}-\d{3}$")


class TestDefaultPolicyPackStructure:
    def test_exactly_20_policies(self):
        pack = build_default_policy_pack()
        assert len(pack.policies) == 20

    def test_policy_ids_are_unique_and_stable_format(self):
        pack = build_default_policy_pack()
        ids = [p.policy_id for p in pack.policies]
        assert len(ids) == len(set(ids))
        for policy_id in ids:
            assert _POLICY_ID_PATTERN.match(policy_id), policy_id

    def test_every_policy_has_required_metadata(self):
        pack = build_default_policy_pack()
        for p in pack.policies:
            assert p.title
            assert p.description
            assert p.category is not None
            assert p.severity is not None
            assert callable(p.evaluate)
            assert p.explanation_template
            assert p.remediation_guidance
            assert isinstance(p.exception_eligible, bool)
            assert p.version >= 1

    def test_privilege_escalation_is_critical_and_not_exception_eligible(self):
        pack = build_default_policy_pack()
        pri = next(p for p in pack.policies if p.policy_id == "POL-PRI-015")
        assert pri.severity == PolicySeverity.CRITICAL
        assert pri.exception_eligible is False

    def test_expired_exception_policy_is_not_exception_eligible(self):
        # A policy about expired exceptions must never itself be
        # suppressible by another exception -- that would defeat its
        # purpose (spec section 12: "critical non-exception-eligible
        # policies must never be bypassed").
        pack = build_default_policy_pack()
        exc = next(p for p in pack.policies if p.policy_id == "POL-EXC-020")
        assert exc.exception_eligible is False


def _ctx(
    resource: CloudResource,
    *,
    baseline: ArchitectureBaseline | None = None,
    desired_resource: CloudResource | None = None,
    has_active_eligible_exception: bool = False,
    has_expired_or_revoked_exception_on_record: bool = False,
) -> PolicyEvaluationContext:
    return PolicyEvaluationContext(
        resource=resource,
        managed_system=build_managed_system(),
        baseline=baseline or ArchitectureBaseline(),
        desired_resource=desired_resource,
        has_active_eligible_exception=has_active_eligible_exception,
        has_expired_or_revoked_exception_on_record=has_expired_or_revoked_exception_on_record,
        evaluation_time=datetime.now(UTC),
    )


def _policy(policy_id: str):
    pack = build_default_policy_pack()
    return next(p for p in pack.policies if p.policy_id == policy_id)


class TestIndividualPolicies:
    def test_public_network_exposure_flags_public_resource(self):
        policy = _policy("POL-NET-001")
        resource = build_resource("r1", "sys1", attributes=ResourceAttributes(publicly_accessible=True))
        outcome = policy.evaluate(_ctx(resource))
        assert outcome.passed is False
        assert "publicly accessible" in outcome.explanation

    def test_public_network_exposure_passes_private_resource(self):
        policy = _policy("POL-NET-001")
        resource = build_resource("r1", "sys1", attributes=ResourceAttributes(publicly_accessible=False))
        outcome = policy.evaluate(_ctx(resource))
        assert outcome.passed is True

    def test_wildcard_iam_permissions_flagged(self):
        policy = _policy("POL-IAM-002")
        resource = build_resource(
            "r1",
            "sys1",
            resource_type=ResourceType.IAM_ROLE,
            attributes=ResourceAttributes(iam_wildcard_action=True),
        )
        outcome = policy.evaluate(_ctx(resource))
        assert outcome.passed is False

    def test_encryption_disabled_flagged_for_storage_types(self):
        policy = _policy("POL-ENC-003")
        resource = build_resource(
            "r1",
            "sys1",
            resource_type=ResourceType.OBJECT_STORAGE_BUCKET,
            attributes=ResourceAttributes(encryption_at_rest_enabled=False),
        )
        outcome = policy.evaluate(_ctx(resource))
        assert outcome.passed is False

    def test_encryption_policy_not_applicable_to_non_storage(self):
        policy = _policy("POL-ENC-003")
        resource = build_resource(
            "r1",
            "sys1",
            resource_type=ResourceType.IAM_ROLE,
            attributes=ResourceAttributes(encryption_at_rest_enabled=False),
        )
        outcome = policy.evaluate(_ctx(resource))
        assert outcome.passed is True

    def test_audit_logging_removed_flagged(self):
        policy = _policy("POL-LOG-004")
        resource = build_resource(
            "r1",
            "sys1",
            resource_type=ResourceType.AUDIT_LOG_CONFIG,
            attributes=ResourceAttributes(audit_logging_enabled=False),
        )
        outcome = policy.evaluate(_ctx(resource))
        assert outcome.passed is False

    def test_monitoring_disabled_flagged(self):
        policy = _policy("POL-MON-005")
        resource = build_resource(
            "r1",
            "sys1",
            resource_type=ResourceType.MONITORING_CONFIG,
            attributes=ResourceAttributes(monitoring_enabled=False),
        )
        outcome = policy.evaluate(_ctx(resource))
        assert outcome.passed is False

    def test_unauthorized_region_flagged_when_outside_allow_list(self):
        policy = _policy("POL-REG-010")
        resource = build_resource("r1", "sys1", region="ap-southeast-2")
        baseline = ArchitectureBaseline(allowed_regions=("us-east-1",))
        outcome = policy.evaluate(_ctx(resource, baseline=baseline))
        assert outcome.passed is False
        assert "unauthorized region" in outcome.explanation

    def test_unauthorized_region_passes_with_no_allow_list_configured(self):
        policy = _policy("POL-REG-010")
        resource = build_resource("r1", "sys1", region="anywhere")
        outcome = policy.evaluate(_ctx(resource, baseline=ArchitectureBaseline()))
        assert outcome.passed is True

    def test_missing_ownership_metadata_flagged(self):
        policy = _policy("POL-OWN-011")
        resource = build_resource("r1", "sys1", attributes=ResourceAttributes(owner_tag=None))
        outcome = policy.evaluate(_ctx(resource))
        assert outcome.passed is False

    def test_unapproved_baseline_resource_flagged_when_not_in_desired_state(self):
        policy = _policy("POL-ARC-009")
        resource = build_resource("r1", "sys1", attributes=ResourceAttributes(within_approved_baseline=False))
        outcome = policy.evaluate(_ctx(resource, desired_resource=None))
        assert outcome.passed is False

    def test_expired_exception_policy_flags_when_marked_on_record(self):
        policy = _policy("POL-EXC-020")
        resource = build_resource("r1", "sys1")
        outcome = policy.evaluate(_ctx(resource, has_expired_or_revoked_exception_on_record=True))
        assert outcome.passed is False
        assert "expired or revoked" in outcome.explanation

    def test_expired_exception_policy_passes_with_no_expired_exception_on_record(self):
        policy = _policy("POL-EXC-020")
        resource = build_resource("r1", "sys1")
        outcome = policy.evaluate(_ctx(resource, has_expired_or_revoked_exception_on_record=False))
        assert outcome.passed is True

    def test_high_availability_required_for_critical_resource(self):
        policy = _policy("POL-HAV-018")
        resource = build_resource(
            "r1",
            "sys1",
            criticality=ResourceCriticality.CRITICAL,
            attributes=ResourceAttributes(high_availability_configured=False),
        )
        outcome = policy.evaluate(_ctx(resource))
        assert outcome.passed is False

    def test_high_availability_not_required_for_standard_non_db_resource(self):
        policy = _policy("POL-HAV-018")
        resource = build_resource(
            "r1",
            "sys1",
            resource_type=ResourceType.OBJECT_STORAGE_BUCKET,
            criticality=ResourceCriticality.STANDARD,
            attributes=ResourceAttributes(high_availability_configured=False),
        )
        outcome = policy.evaluate(_ctx(resource))
        assert outcome.passed is True


class TestEvaluatePolicyPack:
    def test_violations_are_recorded_as_findings(self):
        pack = build_default_policy_pack()
        system = build_managed_system(cloud_provider=CloudProvider.AWS, environment=Environment.PRODUCTION)
        resource = build_resource(
            "r1", system.system_id, attributes=ResourceAttributes(publicly_accessible=True)
        )
        findings = evaluate_policy_pack(
            pack=pack,
            resources=[resource],
            desired_by_resource_id={},
            managed_system=system,
            baseline=ArchitectureBaseline(),
            active_exceptions=[],
            evaluation_time=datetime.now(UTC),
            correlation_id="corr-1",
            id_factory=lambda: "finding-1",
        )
        assert any(f.policy_id == "POL-NET-001" for f in findings)

    def test_compliant_resource_yields_no_public_exposure_finding(self):
        pack = build_default_policy_pack()
        system = build_managed_system()
        resource = build_resource("r1", system.system_id, attributes=ResourceAttributes())
        findings = evaluate_policy_pack(
            pack=pack,
            resources=[resource],
            desired_by_resource_id={},
            managed_system=system,
            baseline=ArchitectureBaseline(),
            active_exceptions=[],
            evaluation_time=datetime.now(UTC),
            correlation_id="corr-1",
            id_factory=lambda: "finding-1",
        )
        assert not any(f.policy_id == "POL-NET-001" for f in findings)

    def test_active_eligible_exception_does_not_hide_the_finding(self):
        """Spec section 12 + evaluator docstring: a violation is always
        recorded as a finding even when an active, eligible exception
        currently suppresses it -- suppression happens downstream via the
        decision router / finding status, never by dropping evidence here."""
        from src.domain.entities.policy_exception import PolicyException

        pack = build_default_policy_pack()
        system = build_managed_system()
        resource = build_resource(
            "r1", system.system_id, attributes=ResourceAttributes(publicly_accessible=True)
        )
        active_exception = PolicyException(
            exception_id="exc-1",
            policy_id="POL-NET-001",
            resource_id="r1",
            finding_id="f-old",
            managed_system_id=system.system_id,
            business_justification="justified",
            risk_statement="accepted",
            compensating_controls=(),
            requested_expiration=datetime.now(UTC),
            requested_by="owner.one",
            evidence=(),
            correlation_id="corr-1",
            status=ExceptionStatus.ACTIVE,
        )
        findings = evaluate_policy_pack(
            pack=pack,
            resources=[resource],
            desired_by_resource_id={},
            managed_system=system,
            baseline=ArchitectureBaseline(),
            active_exceptions=[active_exception],
            evaluation_time=datetime.now(UTC),
            correlation_id="corr-1",
            id_factory=lambda: "finding-1",
        )
        assert any(f.policy_id == "POL-NET-001" for f in findings)

    def test_inactive_policy_is_not_evaluated(self):
        import dataclasses

        pack = build_default_policy_pack()
        deactivated = tuple(
            dataclasses.replace(p, active=False) if p.policy_id == "POL-NET-001" else p for p in pack.policies
        )
        pack = dataclasses.replace(pack, policies=deactivated)
        system = build_managed_system()
        resource = build_resource(
            "r1", system.system_id, attributes=ResourceAttributes(publicly_accessible=True)
        )
        findings = evaluate_policy_pack(
            pack=pack,
            resources=[resource],
            desired_by_resource_id={},
            managed_system=system,
            baseline=ArchitectureBaseline(),
            active_exceptions=[],
            evaluation_time=datetime.now(UTC),
            correlation_id="corr-1",
            id_factory=lambda: "finding-1",
        )
        assert not any(f.policy_id == "POL-NET-001" for f in findings)


def test_all_policy_evaluate_functions_are_pure_and_deterministic():
    """Sweeps every registered policy's evaluate function against the same
    context twice and asserts identical output -- no hidden randomness,
    clock reads, or I/O."""
    pack = build_default_policy_pack()
    resource = build_resource("r1", "sys1")
    ctx = _ctx(resource)
    for policy in pack.policies:
        first = policy.evaluate(ctx)
        second = policy.evaluate(ctx)
        assert first == second


@pytest.mark.parametrize("policy", build_default_policy_pack().policies, ids=lambda p: p.policy_id)
def test_every_policy_evaluate_returns_outcome_for_a_generic_resource(policy):
    resource = build_resource("r1", "sys1")
    outcome = policy.evaluate(_ctx(resource))
    assert isinstance(outcome.passed, bool)
    assert isinstance(outcome.explanation, str)
