from enum import StrEnum


class DecisionType(StrEnum):
    """The 5 required governance decision outcomes (spec section 9)."""

    COMPLIANT = "compliant"
    OBSERVATION_RECORDED = "observation_recorded"
    REMEDIATION_REQUIRED = "remediation_required"
    EXCEPTION_REVIEW_REQUIRED = "exception_review_required"
    GOVERNANCE_BLOCK = "governance_block"
