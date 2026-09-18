"""Reusable authorization service for the policy-exception workflow.

Spec section 12 explicitly requires separation-of-duties to be enforced
"below the API layer, not only in endpoint handlers." This service is that
enforcement point: every exception use case (request/review/decide/revoke)
calls through here rather than re-implementing the checks inline, so the
rule cannot be silently bypassed by a future endpoint or use case that
forgets to check.
"""

from __future__ import annotations

from src.domain.entities.actor import Actor
from src.domain.entities.policy_exception import PolicyException
from src.domain.policies.separation_of_duties import (
    can_decide_exception,
    can_request_exception,
    can_revoke_exception,
)


class ExceptionAuthorizationError(Exception):
    """Raised for any separation-of-duties or role-authorization failure.
    Fail closed: callers must treat this as a hard denial, never a warning."""


class ExceptionAuthorizationService:
    def authorize_request(self, *, requested_by_field: str, authenticated_actor: Actor) -> None:
        """`requested_by_field` is whatever the caller *claims* the
        requester is (e.g. a client-supplied body field, if one exists).
        It must always equal the authenticated actor's id — client-supplied
        identity fields must never override authenticated identity."""
        allowed, reason = can_request_exception(requested_by_field, authenticated_actor.actor_id)
        if not allowed:
            raise ExceptionAuthorizationError(reason)

    def authorize_decision(self, exception: PolicyException, actor: Actor) -> None:
        """Covers both "review" (moving to UNDER_REVIEW) and the final
        approve/reject decision — the same separation-of-duties rule
        applies to both."""
        allowed, reason = can_decide_exception(exception, actor.actor_id, actor.role)
        if not allowed:
            raise ExceptionAuthorizationError(reason)

    def authorize_revocation(self, actor: Actor) -> None:
        allowed, reason = can_revoke_exception(actor.actor_id, actor.role)
        if not allowed:
            raise ExceptionAuthorizationError(reason)
