from enum import StrEnum


class RemediationStatus(StrEnum):
    """Allow-listed transitions live in
    src/domain/state_machine/remediation_transitions.py.
    """

    NOT_STARTED = "not_started"
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    VERIFIED = "verified"
    FAILED = "failed"
    CANCELLED = "cancelled"
