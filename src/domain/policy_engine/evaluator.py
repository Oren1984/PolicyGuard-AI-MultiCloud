"""Pure policy-pack evaluator: turns a PolicyPack + snapshot + baseline +
active exceptions into a tuple of ComplianceFinding. No I/O, no id
generation via randomness beyond the injected id factory, fully
deterministic given the same inputs and clock.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime

from src.domain.entities.cloud_resource import CloudResource
from src.domain.entities.compliance_finding import ComplianceFinding
from src.domain.entities.managed_system import ManagedSystem
from src.domain.entities.policy import Policy, PolicyEvaluationContext, PolicyPack
from src.domain.entities.policy_exception import PolicyException
from src.domain.entities.state_snapshot import ArchitectureBaseline
from src.domain.enums.exception_status import ExceptionStatus

_ELIGIBLE_SUPPRESSING_STATUSES = frozenset({ExceptionStatus.APPROVED, ExceptionStatus.ACTIVE})
_INEFFECTIVE_STATUSES = frozenset({ExceptionStatus.EXPIRED, ExceptionStatus.REVOKED})


def evaluate_policy_pack(
    *,
    pack: PolicyPack,
    resources: Sequence[CloudResource],
    desired_by_resource_id: dict[str, CloudResource],
    managed_system: ManagedSystem,
    baseline: ArchitectureBaseline,
    active_exceptions: Sequence[PolicyException],
    evaluation_time: datetime,
    correlation_id: str,
    id_factory: Callable[[], str],
) -> tuple[ComplianceFinding, ...]:
    suppressing = {
        (e.policy_id, e.resource_id): e
        for e in active_exceptions
        if e.status in _ELIGIBLE_SUPPRESSING_STATUSES
    }
    ineffective_resource_ids = {
        e.resource_id for e in active_exceptions if e.status in _INEFFECTIVE_STATUSES
    }

    findings: list[ComplianceFinding] = []
    for policy in pack.active_policies:
        for resource in resources:
            ctx = PolicyEvaluationContext(
                resource=resource,
                managed_system=managed_system,
                baseline=baseline,
                desired_resource=desired_by_resource_id.get(resource.resource_id),
                has_active_eligible_exception=(
                    (policy.policy_id, resource.resource_id) in suppressing and policy.exception_eligible
                ),
                has_expired_or_revoked_exception_on_record=resource.resource_id in ineffective_resource_ids,
                evaluation_time=evaluation_time,
            )
            outcome = policy.evaluate(ctx)
            if outcome.passed:
                continue
            # A violation is always recorded as a finding, even when an
            # active eligible exception currently suppresses it — dropping
            # the finding would destroy auditability. Suppression is
            # expressed downstream via FindingStatus.EXCEPTION_GRANTED and
            # via `exception_status` fed into the governance decision
            # router, never by hiding evidence here.
            findings.append(
                _to_finding(
                    policy=policy,
                    resource=resource,
                    explanation=outcome.explanation,
                    evidence=outcome.evidence,
                    correlation_id=correlation_id,
                    evaluation_time=evaluation_time,
                    id_factory=id_factory,
                )
            )
    return tuple(findings)


def _to_finding(
    *,
    policy: Policy,
    resource: CloudResource,
    explanation: str,
    evidence: tuple[str, ...],
    correlation_id: str,
    evaluation_time: datetime,
    id_factory: Callable[[], str],
) -> ComplianceFinding:
    return ComplianceFinding(
        finding_id=id_factory(),
        managed_system_id=resource.managed_system_id,
        resource_id=resource.resource_id,
        policy_id=policy.policy_id,
        category=policy.category,
        severity=policy.severity,
        title=policy.title,
        explanation=explanation or policy.explanation_template.format(resource_name=resource.name),
        evidence=evidence,
        remediation_guidance=policy.remediation_guidance,
        exception_eligible=policy.exception_eligible,
        correlation_id=correlation_id,
        detected_at=evaluation_time,
    )
