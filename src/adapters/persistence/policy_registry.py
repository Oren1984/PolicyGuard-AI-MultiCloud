"""Reattaches each Policy's deterministic `evaluate` callable at read time.

`Policy.evaluate` (src/domain/entities/policy.py) is a pure Python callable
and cannot be persisted to PostgreSQL. Policy *metadata* (title, category,
severity, required_evidence, remediation_guidance, version, active, ...) is
fully persisted and versioned via SqlAlchemyPolicyRepository; the executable
rule itself remains code-defined in src/domain/policy_engine/definitions.py
and is looked up here by policy_id.

This is a deliberate phase-2 deviation from a "fully data-driven" policy
engine, noted in the phase report: PolicyRepository.create() lets a caller
register a custom policy_id/metadata row, but unless that same policy_id is
also registered in `build_default_policy_pack()` (or added to this
registry), it has no executable rule.

Fail-closed behavior: a policy_id with no registered evaluate function is
never silently treated as passing. `resolve_evaluate_fn` falls back to a
function that always reports a violation, because a policy that cannot be
deterministically evaluated must never be treated as satisfied.
"""

from __future__ import annotations

from src.domain.entities.policy import PolicyCheckOutcome, PolicyEvaluationContext, PolicyEvaluationFn
from src.domain.policy_engine.definitions import build_default_policy_pack

_REGISTRY: dict[str, PolicyEvaluationFn] = {
    policy.policy_id: policy.evaluate for policy in build_default_policy_pack().policies
}


def _fail_closed_evaluate(ctx: PolicyEvaluationContext) -> PolicyCheckOutcome:
    return PolicyCheckOutcome(
        passed=False,
        explanation=(
            f"{ctx.resource.name} could not be evaluated: no deterministic evaluate function is "
            "registered for this policy_id. Failing closed."
        ),
        evidence=("evaluate_fn_registered=false",),
    )


def resolve_evaluate_fn(policy_id: str) -> PolicyEvaluationFn:
    return _REGISTRY.get(policy_id, _fail_closed_evaluate)
