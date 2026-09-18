from enum import StrEnum


class ExceptionStatus(StrEnum):
    """The policy-exception lifecycle (spec section 12).

    Allow-listed transitions live in
    src/domain/state_machine/exception_transitions.py.
    """

    REQUESTED = "requested"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
