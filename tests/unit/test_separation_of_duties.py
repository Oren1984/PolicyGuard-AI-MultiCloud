"""Domain-level separation-of-duties unit tests (spec section 12), tested
directly against the pure policy functions -- independent of the API layer,
so these regressions can never be bypassed by a future endpoint or use case
that forgets to call the reusable service."""

from __future__ import annotations

from datetime import UTC, datetime

from src.domain.entities.policy_exception import PolicyException
from src.domain.enums.actor_role import ActorRole
from src.domain.policies.separation_of_duties import (
    can_decide_exception,
    can_request_exception,
    can_revoke_exception,
)


def _exception(requested_by: str) -> PolicyException:
    return PolicyException(
        exception_id="exc-1",
        policy_id="POL-NET-001",
        resource_id="r1",
        finding_id="f1",
        managed_system_id="sys1",
        business_justification="justified",
        risk_statement="accepted",
        compensating_controls=(),
        requested_expiration=datetime.now(UTC),
        requested_by=requested_by,
        evidence=(),
        correlation_id="corr-1",
    )


class TestSelfApprovalPrevention:
    def test_requester_cannot_decide_their_own_exception(self):
        exception = _exception(requested_by="dev.one")
        allowed, reason = can_decide_exception(exception, "dev.one", ActorRole.SECURITY_REVIEWER)
        assert allowed is False
        assert "own exception" in reason

    def test_different_actor_with_authorized_role_can_decide(self):
        exception = _exception(requested_by="dev.one")
        allowed, _ = can_decide_exception(exception, "reviewer.one", ActorRole.SECURITY_REVIEWER)
        assert allowed is True

    def test_unauthorized_role_cannot_decide_even_if_not_requester(self):
        exception = _exception(requested_by="dev.one")
        allowed, reason = can_decide_exception(exception, "someone.else", ActorRole.SYSTEM_OWNER)
        assert allowed is False
        assert "not authorized" in reason

    def test_self_approval_check_happens_before_role_check(self):
        # Even if the requester happens to also hold an approving role, the
        # self-decision rule must still win.
        exception = _exception(requested_by="admin.one")
        allowed, reason = can_decide_exception(exception, "admin.one", ActorRole.PLATFORM_ADMIN)
        assert allowed is False
        assert "own exception" in reason


class TestSpoofedIdentityPrevention:
    def test_matching_ids_are_allowed(self):
        allowed, _ = can_request_exception("dev.one", "dev.one")
        assert allowed is True

    def test_mismatched_claimed_identity_is_rejected(self):
        # Regression: a client claiming to submit "as" someone else, while
        # authenticated as a different actor, must be rejected outright.
        allowed, reason = can_request_exception("someone.else", "dev.one")
        assert allowed is False
        assert "spoofed" in reason.lower()


class TestRevocationAuthorization:
    def test_authorized_role_can_revoke(self):
        allowed, _ = can_revoke_exception("reviewer.one", ActorRole.SECURITY_REVIEWER)
        assert allowed is True

    def test_unauthorized_role_cannot_revoke(self):
        allowed, reason = can_revoke_exception("owner.one", ActorRole.SYSTEM_OWNER)
        assert allowed is False
        assert "not authorized" in reason

    def test_auditor_role_cannot_revoke(self):
        # Auditor is read/verify-only by design -- never a mutation role.
        allowed, _ = can_revoke_exception("auditor.one", ActorRole.AUDITOR)
        assert allowed is False
