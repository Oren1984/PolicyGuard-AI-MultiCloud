from __future__ import annotations

from src.domain.enums.finding_status import FindingStatus
from src.domain.state_machine.errors import InvalidStateTransitionError

# Explicit, exhaustive allow-list. Applies to both ComplianceFinding and
# DriftFinding, which share FindingStatus. Anything not listed here is
# forbidden — no API route, repository method, or AI output may bypass it.
ALLOWED_TRANSITIONS: dict[FindingStatus, frozenset[FindingStatus]] = {
    FindingStatus.OPEN: frozenset(
        {FindingStatus.ACKNOWLEDGED, FindingStatus.EXCEPTION_GRANTED, FindingStatus.REMEDIATED}
    ),
    FindingStatus.ACKNOWLEDGED: frozenset(
        {FindingStatus.EXCEPTION_GRANTED, FindingStatus.REMEDIATED, FindingStatus.OPEN}
    ),
    FindingStatus.EXCEPTION_GRANTED: frozenset({FindingStatus.REOPENED, FindingStatus.CLOSED}),
    FindingStatus.REMEDIATED: frozenset({FindingStatus.CLOSED, FindingStatus.REOPENED}),
    FindingStatus.CLOSED: frozenset({FindingStatus.REOPENED}),
    FindingStatus.REOPENED: frozenset(
        {FindingStatus.ACKNOWLEDGED, FindingStatus.EXCEPTION_GRANTED, FindingStatus.REMEDIATED}
    ),
}


def is_transition_allowed(current: FindingStatus, target: FindingStatus) -> bool:
    return target in ALLOWED_TRANSITIONS.get(current, frozenset())


def validate_transition(current: FindingStatus, target: FindingStatus) -> None:
    """Fail-closed: raises unless the transition is explicitly allow-listed."""
    if not is_transition_allowed(current, target):
        raise InvalidStateTransitionError("finding", current, target)
