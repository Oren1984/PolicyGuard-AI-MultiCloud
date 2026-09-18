"""Pure, infrastructure-independent governance decision router (spec section
9). This is the single point that turns deterministic evaluation evidence
into one of the five DecisionType outcomes.

STRUCTURAL AI-EXCLUSION GUARANTEE
----------------------------------
`GovernanceDecisionContext` below has no field typed to accept raw AI
provider output (no `AIAdvisoryContent`, no free-text "recommendation"
string, nothing from src.ports.ai_provider or src.domain.entities.ai_advisory).
The only AI-adjacent input is `gates: GatePipelineResult | None`, which
carries nothing but the deterministic PASSED/WARNING/FAILED *status* of the
five assurance gates — never the AI's text. This is enforced by the type
system: to make an AI recommendation influence `route_governance_decision`,
a caller would have to change this dataclass's field types, which is a
visible, reviewable change to this file — the AI's opinion cannot silently
leak into the decision through any existing parameter.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.domain.entities.gate_result import GatePipelineResult
from src.domain.entities.governance_decision import GovernanceRoutingResult
from src.domain.enums.decision_type import DecisionType
from src.domain.enums.environment import Environment
from src.domain.enums.exception_status import ExceptionStatus
from src.domain.enums.policy_severity import PolicySeverity
from src.domain.enums.resource_criticality import ResourceCriticality
from src.domain.enums.system_mode import SystemMode

# A repeated HIGH-severity violation on a critical production resource is
# escalated to a hard governance block after this many prior occurrences.
REPEATED_VIOLATION_ESCALATION_THRESHOLD = 3


@dataclass(frozen=True, slots=True)
class GovernanceDecisionContext:
    """Every deterministic input the router may consider. Deliberately a
    plain, serializable bag of values so the router stays a pure,
    exhaustively unit-testable transformation from evidence to decision."""

    has_violation: bool
    severity: PolicySeverity
    environment: Environment
    resource_criticality: ResourceCriticality
    evidence_complete: bool
    exception_status: ExceptionStatus | None
    exception_eligible: bool
    critical_non_eligible: bool
    repeated_violation_count: int
    system_mode: SystemMode
    gates: GatePipelineResult | None
    policy_id: str | None = None


def route_governance_decision(context: GovernanceDecisionContext) -> GovernanceRoutingResult:
    reasons: list[str] = []
    policy_ids: tuple[str, ...] = (context.policy_id,) if context.policy_id else ()

    # 1. No violation at all -> compliant, regardless of everything else
    #    except an unresolved emergency stop (checked first for safety).
    if context.system_mode == SystemMode.EMERGENCY_STOP and context.has_violation:
        reasons.append("Emergency stop is active; the violation cannot proceed past a governance block.")
        return GovernanceRoutingResult(DecisionType.GOVERNANCE_BLOCK, tuple(reasons), policy_ids)

    if not context.has_violation:
        reasons.append("No policy or drift violation was detected.")
        return GovernanceRoutingResult(DecisionType.COMPLIANT, tuple(reasons), policy_ids)

    # 2. Critical, non-exception-eligible policies can never be bypassed.
    if context.critical_non_eligible:
        reasons.append("Critical severity finding on a policy that is not exception-eligible.")
        return GovernanceRoutingResult(DecisionType.GOVERNANCE_BLOCK, tuple(reasons), policy_ids)

    # 3. CRITICAL severity is always a hard block.
    if context.severity == PolicySeverity.CRITICAL:
        reasons.append("Finding severity is CRITICAL.")
        return GovernanceRoutingResult(DecisionType.GOVERNANCE_BLOCK, tuple(reasons), policy_ids)

    # 4. A failed AI assurance gate means we cannot trust any explanation
    #    that might accompany this finding; fail closed to a hard block
    #    rather than let a lighter decision stand on unverified advisory
    #    content. This uses only the gate's deterministic status.
    if context.gates is not None and context.gates.any_failed:
        reasons.append("A mandatory AI assurance gate failed; failing closed.")
        return GovernanceRoutingResult(DecisionType.GOVERNANCE_BLOCK, tuple(reasons), policy_ids)

    # 5. An active/approved, eligible exception suppresses the violation as
    #    an informational observation, not silence.
    if (
        context.exception_status in (ExceptionStatus.ACTIVE, ExceptionStatus.APPROVED)
        and context.exception_eligible
    ):
        reasons.append("An active, eligible policy exception currently covers this finding.")
        return GovernanceRoutingResult(DecisionType.OBSERVATION_RECORDED, tuple(reasons), policy_ids)

    # 6. A pending exception request routes to human review — unless the
    #    kill switch is not NORMAL, in which case new exception workflow is
    #    blocked and remediation is required instead.
    if context.exception_status in (ExceptionStatus.REQUESTED, ExceptionStatus.UNDER_REVIEW):
        if context.system_mode == SystemMode.NORMAL:
            reasons.append("A policy exception is pending review for this finding.")
            return GovernanceRoutingResult(DecisionType.EXCEPTION_REVIEW_REQUIRED, tuple(reasons), policy_ids)
        reasons.append("Exception review is blocked while the kill switch is not NORMAL.")
        return GovernanceRoutingResult(DecisionType.REMEDIATION_REQUIRED, tuple(reasons), policy_ids)

    # Note: EXPIRED/REJECTED/REVOKED exceptions intentionally fall through —
    # they must stop suppressing findings immediately (spec section 12).

    # 7. Incomplete evidence can never support a decision lighter than
    #    remediation-required.
    if not context.evidence_complete:
        reasons.append("Required evidence is missing or incomplete for this finding.")
        return GovernanceRoutingResult(DecisionType.REMEDIATION_REQUIRED, tuple(reasons), policy_ids)

    # 8. HIGH severity: escalate to a hard block on repeated violations
    #    against a critical production resource.
    if context.severity == PolicySeverity.HIGH:
        repeated_and_critical = (
            context.repeated_violation_count >= REPEATED_VIOLATION_ESCALATION_THRESHOLD
            and context.environment == Environment.PRODUCTION
            and context.resource_criticality == ResourceCriticality.CRITICAL
        )
        if repeated_and_critical:
            reasons.append(
                "Repeated HIGH-severity violation on a critical production resource escalated to a block."
            )
            return GovernanceRoutingResult(DecisionType.GOVERNANCE_BLOCK, tuple(reasons), policy_ids)
        reasons.append("Finding severity is HIGH.")
        return GovernanceRoutingResult(DecisionType.REMEDIATION_REQUIRED, tuple(reasons), policy_ids)

    # 9. MEDIUM severity requires remediation.
    if context.severity == PolicySeverity.MEDIUM:
        reasons.append("Finding severity is MEDIUM.")
        return GovernanceRoutingResult(DecisionType.REMEDIATION_REQUIRED, tuple(reasons), policy_ids)

    # 10. LOW severity is informational, unless it lands on a critical
    #     production resource, where even minor drift warrants remediation.
    if context.severity == PolicySeverity.LOW:
        if context.environment == Environment.PRODUCTION and context.resource_criticality == (
            ResourceCriticality.CRITICAL
        ):
            reasons.append("LOW-severity finding on a critical production resource requires remediation.")
            return GovernanceRoutingResult(DecisionType.REMEDIATION_REQUIRED, tuple(reasons), policy_ids)
        reasons.append("Finding severity is LOW; recorded as an informational observation.")
        return GovernanceRoutingResult(DecisionType.OBSERVATION_RECORDED, tuple(reasons), policy_ids)

    # 11. INFO severity is always informational.
    reasons.append("Finding severity is INFO; recorded as an informational observation.")
    return GovernanceRoutingResult(DecisionType.OBSERVATION_RECORDED, tuple(reasons), policy_ids)
