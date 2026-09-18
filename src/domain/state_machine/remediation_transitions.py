from __future__ import annotations

from src.domain.enums.remediation_status import RemediationStatus
from src.domain.state_machine.errors import InvalidStateTransitionError

ALLOWED_TRANSITIONS: dict[RemediationStatus, frozenset[RemediationStatus]] = {
    RemediationStatus.NOT_STARTED: frozenset(
        {RemediationStatus.PLANNED, RemediationStatus.IN_PROGRESS, RemediationStatus.CANCELLED}
    ),
    RemediationStatus.PLANNED: frozenset(
        {RemediationStatus.IN_PROGRESS, RemediationStatus.CANCELLED}
    ),
    RemediationStatus.IN_PROGRESS: frozenset(
        {RemediationStatus.COMPLETED, RemediationStatus.FAILED, RemediationStatus.CANCELLED}
    ),
    RemediationStatus.COMPLETED: frozenset(
        {RemediationStatus.VERIFIED, RemediationStatus.FAILED}
    ),
    RemediationStatus.VERIFIED: frozenset(),
    RemediationStatus.FAILED: frozenset(
        {RemediationStatus.IN_PROGRESS, RemediationStatus.CANCELLED}
    ),
    RemediationStatus.CANCELLED: frozenset(),
}


def is_transition_allowed(current: RemediationStatus, target: RemediationStatus) -> bool:
    return target in ALLOWED_TRANSITIONS.get(current, frozenset())


def validate_transition(current: RemediationStatus, target: RemediationStatus) -> None:
    if not is_transition_allowed(current, target):
        raise InvalidStateTransitionError("remediation_plan", current, target)
