from __future__ import annotations

from src.domain.entities.policy_exception import PolicyException
from src.domain.enums.actor_role import EXCEPTION_DECISION_ROLES, EXCEPTION_REVOCATION_ROLES, ActorRole

# Core separation-of-duties rules (spec section 12). This module is the
# single source of truth for these checks; the reusable application-layer
# service (src/application/services/exception_authorization.py) calls into
# it so the rule is enforced below the API layer, not just in handlers.


def can_decide_exception(exception: PolicyException, actor_id: str, role: ActorRole) -> tuple[bool, str]:
    """A requester may never approve/reject/review their own exception,
    regardless of role."""
    if actor_id == exception.requested_by:
        return False, "requester cannot review, approve, or reject their own exception"
    if role not in EXCEPTION_DECISION_ROLES:
        return False, f"role '{role.value}' is not authorized to decide a policy exception"
    return True, ""


def can_revoke_exception(actor_id: str, role: ActorRole) -> tuple[bool, str]:
    if role not in EXCEPTION_REVOCATION_ROLES:
        return False, f"role '{role.value}' is not authorized to revoke a policy exception"
    return True, ""


def can_request_exception(requested_by_actor_id: str, submitted_by_header_actor_id: str) -> tuple[bool, str]:
    """Client-supplied identity fields must never override the authenticated
    actor identity. Callers must pass the same trusted actor id for both
    parameters; a mismatch means something tried to spoof the requester."""
    if requested_by_actor_id != submitted_by_header_actor_id:
        return False, "requester identity must match the authenticated actor; spoofed identity rejected"
    return True, ""
