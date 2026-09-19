"""AI-provider boundary tests (spec section 10): the AIProvider port and
MockAIProvider must expose only summarize/explain/group/outline -- never a
method that could determine compliance, change severity, approve an
exception, or close a finding."""

from __future__ import annotations

import inspect

from src.adapters.ai.mock_provider import MockAIProvider
from src.ports.ai_provider import AIProvider

_FORBIDDEN_METHOD_NAME_FRAGMENTS = (
    "approve",
    "reject",
    "close",
    "decide",
    "compliance",
    "severity",
    "remediate",
    "override",
    "modify_resource",
)


def test_ai_provider_port_exposes_only_advisory_methods():
    methods = [
        name
        for name, _ in inspect.getmembers(AIProvider, predicate=inspect.isfunction)
        if not name.startswith("_")
    ]
    assert set(methods) == {
        "summarize_findings",
        "explain_impact",
        "group_related_violations",
        "generate_remediation_outline",
    }


def test_ai_provider_port_has_no_forbidden_method_names():
    methods = [
        name
        for name, _ in inspect.getmembers(AIProvider, predicate=inspect.isfunction)
        if not name.startswith("_")
    ]
    for method_name in methods:
        for fragment in _FORBIDDEN_METHOD_NAME_FRAGMENTS:
            assert fragment not in method_name.lower(), method_name


def test_mock_ai_provider_implements_only_the_port_surface():
    public_methods = {
        name
        for name, _ in inspect.getmembers(MockAIProvider, predicate=inspect.isfunction)
        if not name.startswith("_")
    }
    assert public_methods == {
        "summarize_findings",
        "explain_impact",
        "group_related_violations",
        "generate_remediation_outline",
    }


def test_mock_ai_provider_is_deterministic_given_the_same_findings():
    from src.domain.entities.compliance_finding import ComplianceFinding
    from src.domain.enums.finding_status import FindingStatus
    from src.domain.enums.policy_category import PolicyCategory
    from src.domain.enums.policy_severity import PolicySeverity

    finding = ComplianceFinding(
        finding_id="f1",
        managed_system_id="sys1",
        resource_id="r1",
        policy_id="POL-NET-001",
        category=PolicyCategory.PUBLIC_NETWORK_EXPOSURE,
        severity=PolicySeverity.HIGH,
        title="Public exposure",
        explanation="public",
        evidence=("attributes.publicly_accessible=true",),
        remediation_guidance="restrict",
        exception_eligible=True,
        correlation_id="c1",
        status=FindingStatus.OPEN,
    )
    provider = MockAIProvider()
    first = provider.summarize_findings([finding], correlation_id="c1")
    second = provider.summarize_findings([finding], correlation_id="c1")
    assert first.content == second.content
    assert first.confidence == second.confidence


def test_mock_ai_provider_evidence_is_grounded_by_construction():
    from src.domain.entities.compliance_finding import ComplianceFinding
    from src.domain.enums.finding_status import FindingStatus
    from src.domain.enums.policy_category import PolicyCategory
    from src.domain.enums.policy_severity import PolicySeverity

    finding = ComplianceFinding(
        finding_id="f1",
        managed_system_id="sys1",
        resource_id="r1",
        policy_id="POL-NET-001",
        category=PolicyCategory.PUBLIC_NETWORK_EXPOSURE,
        severity=PolicySeverity.HIGH,
        title="Public exposure",
        explanation="public",
        evidence=("attributes.publicly_accessible=true",),
        remediation_guidance="restrict",
        exception_eligible=True,
        correlation_id="c1",
        status=FindingStatus.OPEN,
    )
    content = MockAIProvider().explain_impact(finding, correlation_id="c1")
    known = {
        f"finding:{finding.finding_id}",
        f"resource:{finding.resource_id}",
        f"policy:{finding.policy_id}",
    }
    known.update(finding.evidence)
    assert set(content.referenced_evidence).issubset(known)
