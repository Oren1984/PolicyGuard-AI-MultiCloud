from enum import StrEnum


class FindingStatus(StrEnum):
    """Lifecycle status shared by DriftFinding and ComplianceFinding.

    Allow-listed transitions live in
    src/domain/state_machine/finding_transitions.py.
    """

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    EXCEPTION_GRANTED = "exception_granted"
    REMEDIATED = "remediated"
    CLOSED = "closed"
    REOPENED = "reopened"
