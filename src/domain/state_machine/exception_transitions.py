from __future__ import annotations

from src.domain.enums.exception_status import ExceptionStatus
from src.domain.state_machine.errors import InvalidStateTransitionError

# Requested -> Under review -> Approved/Rejected -> Active -> Expired/Revoked
# (spec section 12). Rejected and Expired are terminal. Revoked is terminal.
ALLOWED_TRANSITIONS: dict[ExceptionStatus, frozenset[ExceptionStatus]] = {
    ExceptionStatus.REQUESTED: frozenset({ExceptionStatus.UNDER_REVIEW, ExceptionStatus.REJECTED}),
    ExceptionStatus.UNDER_REVIEW: frozenset({ExceptionStatus.APPROVED, ExceptionStatus.REJECTED}),
    ExceptionStatus.APPROVED: frozenset({ExceptionStatus.ACTIVE, ExceptionStatus.REVOKED}),
    ExceptionStatus.REJECTED: frozenset(),
    ExceptionStatus.ACTIVE: frozenset({ExceptionStatus.EXPIRED, ExceptionStatus.REVOKED}),
    ExceptionStatus.EXPIRED: frozenset(),
    ExceptionStatus.REVOKED: frozenset(),
}


def is_transition_allowed(current: ExceptionStatus, target: ExceptionStatus) -> bool:
    return target in ALLOWED_TRANSITIONS.get(current, frozenset())


def validate_transition(current: ExceptionStatus, target: ExceptionStatus) -> None:
    if not is_transition_allowed(current, target):
        raise InvalidStateTransitionError("policy_exception", current, target)
