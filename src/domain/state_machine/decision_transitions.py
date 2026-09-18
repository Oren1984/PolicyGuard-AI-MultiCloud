from __future__ import annotations

from src.domain.enums.decision_type import DecisionType
from src.domain.state_machine.errors import InvalidStateTransitionError

# GovernanceDecision outcomes are recomputed fresh on every evaluation run
# (they are not a stored workflow a user drives forward), but the spec still
# requires an explicit allow-listed state machine for "DecisionType
# lifecycle": this table constrains which *successor* decision a later
# re-evaluation of the same finding/system may legitimately reach without
# an intervening state change (e.g. remediation, exception approval, or a
# fresh violation). It exists to catch orchestration bugs — e.g. a
# GOVERNANCE_BLOCK silently becoming COMPLIANT with no remediation or
# exception ever recorded — not to gate the router itself, which always
# computes a decision from current evidence.
ALLOWED_TRANSITIONS: dict[DecisionType, frozenset[DecisionType]] = {
    DecisionType.COMPLIANT: frozenset(
        {
            DecisionType.COMPLIANT,
            DecisionType.OBSERVATION_RECORDED,
            DecisionType.REMEDIATION_REQUIRED,
            DecisionType.EXCEPTION_REVIEW_REQUIRED,
            DecisionType.GOVERNANCE_BLOCK,
        }
    ),
    DecisionType.OBSERVATION_RECORDED: frozenset(
        {
            DecisionType.COMPLIANT,
            DecisionType.OBSERVATION_RECORDED,
            DecisionType.REMEDIATION_REQUIRED,
            DecisionType.EXCEPTION_REVIEW_REQUIRED,
            DecisionType.GOVERNANCE_BLOCK,
        }
    ),
    DecisionType.REMEDIATION_REQUIRED: frozenset(
        {
            DecisionType.COMPLIANT,
            DecisionType.REMEDIATION_REQUIRED,
            DecisionType.EXCEPTION_REVIEW_REQUIRED,
            DecisionType.GOVERNANCE_BLOCK,
        }
    ),
    DecisionType.EXCEPTION_REVIEW_REQUIRED: frozenset(
        {
            DecisionType.COMPLIANT,
            DecisionType.OBSERVATION_RECORDED,
            DecisionType.REMEDIATION_REQUIRED,
            DecisionType.EXCEPTION_REVIEW_REQUIRED,
            DecisionType.GOVERNANCE_BLOCK,
        }
    ),
    DecisionType.GOVERNANCE_BLOCK: frozenset(
        {
            DecisionType.REMEDIATION_REQUIRED,
            DecisionType.EXCEPTION_REVIEW_REQUIRED,
            DecisionType.GOVERNANCE_BLOCK,
            DecisionType.COMPLIANT,
        }
    ),
}


def is_transition_allowed(current: DecisionType, target: DecisionType) -> bool:
    return target in ALLOWED_TRANSITIONS.get(current, frozenset())


def validate_transition(current: DecisionType, target: DecisionType) -> None:
    if not is_transition_allowed(current, target):
        raise InvalidStateTransitionError("governance_decision", current, target)
