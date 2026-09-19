"""Application use-case tests, run against in-memory fakes (see
tests/fixtures/fake_repositories.py) so orchestration logic -- separation of
duties, audit-event emission, id/clock injection, and fail-closed kill-switch
checks -- is tested in isolation from PostgreSQL. The exception workflow's
own regressions (self-approval, spoofed identity, expired-exception reuse)
are the required spec-section-20 regressions; they are re-verified for real
over HTTP + Postgres in tests/security/test_security_regressions.py."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from src.application.services.exception_authorization import (
    ExceptionAuthorizationError,
    ExceptionAuthorizationService,
)
from src.application.use_cases.decide_exception import DecidePolicyExceptionUseCase
from src.application.use_cases.expire_exceptions import ExpireExceptionsUseCase
from src.application.use_cases.kill_switch import KillSwitchUseCase, UnauthorizedKillSwitchChangeError
from src.application.use_cases.request_exception import RequestPolicyExceptionUseCase
from src.application.use_cases.review_exception import ReviewPolicyExceptionUseCase
from src.application.use_cases.revoke_exception import RevokePolicyExceptionUseCase
from src.domain.enums.actor_role import ActorRole
from src.domain.enums.exception_status import ExceptionStatus
from src.domain.enums.system_mode import SystemMode
from src.domain.state_machine.errors import InvalidStateTransitionError
from tests.fixtures.builders import make_actor
from tests.fixtures.fake_repositories import (
    FakeAuditEventRepository,
    FakeKillSwitchRepository,
    FakePolicyExceptionRepository,
)

FIXED_NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _clock():
    return FIXED_NOW


def _id_factory_counter():
    counter = {"n": 0}

    def factory():
        counter["n"] += 1
        return f"id-{counter['n']}"

    return factory


@pytest.fixture()
def exception_repo():
    return FakePolicyExceptionRepository()


@pytest.fixture()
def audit_repo():
    return FakeAuditEventRepository()


@pytest.fixture()
def authz():
    return ExceptionAuthorizationService()


class TestRequestPolicyExceptionUseCase:
    def test_request_succeeds_when_identity_matches(self, exception_repo, audit_repo, authz):
        use_case = RequestPolicyExceptionUseCase(
            exception_repo, audit_repo, authz, _id_factory_counter(), _clock
        )
        actor = make_actor("dev.one", ActorRole.SYSTEM_OWNER)
        created = use_case.execute(
            policy_id="POL-NET-001",
            resource_id="r1",
            finding_id="f1",
            managed_system_id="sys1",
            business_justification="justified",
            risk_statement="accepted",
            compensating_controls=(),
            requested_expiration=FIXED_NOW + timedelta(days=30),
            evidence=("ticket:JIRA-1",),
            claimed_requester_id="dev.one",
            actor=actor,
            correlation_id="corr-1",
        )
        assert created.requested_by == "dev.one"
        assert created.status == ExceptionStatus.REQUESTED
        assert len(audit_repo.events) == 1
        assert audit_repo.events[0].action == "POLICY_EXCEPTION_REQUESTED"

    def test_spoofed_requester_identity_is_rejected(self, exception_repo, audit_repo, authz):
        """Regression: a client claiming `requested_by` is someone other
        than the authenticated actor must be rejected before any exception
        is created, and no exception should be persisted."""
        use_case = RequestPolicyExceptionUseCase(
            exception_repo, audit_repo, authz, _id_factory_counter(), _clock
        )
        actor = make_actor("dev.one", ActorRole.SYSTEM_OWNER)
        with pytest.raises(ExceptionAuthorizationError):
            use_case.execute(
                policy_id="POL-NET-001",
                resource_id="r1",
                finding_id="f1",
                managed_system_id="sys1",
                business_justification="justified",
                risk_statement="accepted",
                compensating_controls=(),
                requested_expiration=FIXED_NOW + timedelta(days=30),
                evidence=(),
                claimed_requester_id="someone.else",  # spoofed
                actor=actor,
                correlation_id="corr-1",
            )
        assert exception_repo._store == {}
        assert audit_repo.events == []


class TestDecidePolicyExceptionUseCase:
    def _requested_exception(self, exception_repo, requested_by="dev.one"):
        from src.domain.entities.policy_exception import PolicyException
        from tests.fixtures.builders import unique_id

        exc = PolicyException(
            exception_id=unique_id("exc"),
            policy_id="POL-NET-001",
            resource_id="r1",
            finding_id="f1",
            managed_system_id="sys1",
            business_justification="justified",
            risk_statement="accepted",
            compensating_controls=(),
            requested_expiration=FIXED_NOW + timedelta(days=30),
            requested_by=requested_by,
            evidence=(),
            correlation_id="corr-1",
            status=ExceptionStatus.UNDER_REVIEW,
        )
        return exception_repo.create(exc)

    def test_requester_cannot_approve_their_own_exception(self, exception_repo, audit_repo, authz):
        """Required regression: requester self-approval must be rejected."""
        exc = self._requested_exception(exception_repo, requested_by="dev.one")
        use_case = DecidePolicyExceptionUseCase(
            exception_repo, audit_repo, authz, _id_factory_counter(), _clock
        )
        self_approver = make_actor("dev.one", ActorRole.SECURITY_REVIEWER)  # same id as requester
        with pytest.raises(ExceptionAuthorizationError):
            use_case.execute(
                exc.exception_id, approve=True, rationale="lgtm", actor=self_approver, correlation_id="c1"
            )
        # State must not have changed.
        assert exception_repo.get(exc.exception_id).status == ExceptionStatus.UNDER_REVIEW

    def test_different_authorized_actor_can_approve_and_activates_immediately(
        self, exception_repo, audit_repo, authz
    ):
        exc = self._requested_exception(exception_repo, requested_by="dev.one")
        use_case = DecidePolicyExceptionUseCase(
            exception_repo, audit_repo, authz, _id_factory_counter(), _clock
        )
        reviewer = make_actor("reviewer.one", ActorRole.SECURITY_REVIEWER)
        updated = use_case.execute(
            exc.exception_id,
            approve=True,
            rationale="reviewed and accepted",
            actor=reviewer,
            correlation_id="c1",
        )
        assert updated.status == ExceptionStatus.ACTIVE
        assert updated.expires_at == exc.requested_expiration
        assert len(updated.approvals) == 1
        assert updated.approvals[0].decision == "APPROVED"

    def test_rejection_leaves_exception_in_terminal_rejected_state(self, exception_repo, audit_repo, authz):
        exc = self._requested_exception(exception_repo, requested_by="dev.one")
        use_case = DecidePolicyExceptionUseCase(
            exception_repo, audit_repo, authz, _id_factory_counter(), _clock
        )
        reviewer = make_actor("reviewer.one", ActorRole.SECURITY_REVIEWER)
        updated = use_case.execute(
            exc.exception_id,
            approve=False,
            rationale="insufficient evidence",
            actor=reviewer,
            correlation_id="c1",
        )
        assert updated.status == ExceptionStatus.REJECTED

    def test_unauthorized_role_cannot_decide(self, exception_repo, audit_repo, authz):
        exc = self._requested_exception(exception_repo, requested_by="dev.one")
        use_case = DecidePolicyExceptionUseCase(
            exception_repo, audit_repo, authz, _id_factory_counter(), _clock
        )
        unauthorized = make_actor("owner.two", ActorRole.SYSTEM_OWNER)
        with pytest.raises(ExceptionAuthorizationError):
            use_case.execute(
                exc.exception_id, approve=True, rationale="lgtm", actor=unauthorized, correlation_id="c1"
            )


class TestReviewPolicyExceptionUseCase:
    def test_requester_cannot_review_their_own_request(self, exception_repo, audit_repo, authz):
        from src.domain.entities.policy_exception import PolicyException
        from tests.fixtures.builders import unique_id

        exc = exception_repo.create(
            PolicyException(
                exception_id=unique_id("exc"),
                policy_id="POL-NET-001",
                resource_id="r1",
                finding_id="f1",
                managed_system_id="sys1",
                business_justification="j",
                risk_statement="r",
                compensating_controls=(),
                requested_expiration=FIXED_NOW + timedelta(days=30),
                requested_by="dev.one",
                evidence=(),
                correlation_id="c1",
                status=ExceptionStatus.REQUESTED,
            )
        )
        use_case = ReviewPolicyExceptionUseCase(exception_repo, audit_repo, authz)
        self_reviewer = make_actor("dev.one", ActorRole.SECURITY_REVIEWER)
        with pytest.raises(ExceptionAuthorizationError):
            use_case.execute(exc.exception_id, actor=self_reviewer, correlation_id="c1")


class TestExpireExceptionsUseCase:
    def test_active_expired_exceptions_transition_to_expired(self, exception_repo, audit_repo):
        from src.domain.entities.policy_exception import PolicyException
        from tests.fixtures.builders import unique_id

        expired_exc = exception_repo.create(
            PolicyException(
                exception_id=unique_id("exc"),
                policy_id="POL-NET-001",
                resource_id="r1",
                finding_id="f1",
                managed_system_id="sys1",
                business_justification="j",
                risk_statement="r",
                compensating_controls=(),
                requested_expiration=FIXED_NOW - timedelta(days=1),
                requested_by="dev.one",
                evidence=(),
                correlation_id="c1",
                status=ExceptionStatus.ACTIVE,
                expires_at=FIXED_NOW - timedelta(days=1),
            )
        )
        use_case = ExpireExceptionsUseCase(exception_repo, audit_repo, _clock)
        actor = make_actor("system.sweeper", ActorRole.PLATFORM_ADMIN)
        expired = use_case.execute(actor=actor, correlation_id="c1")
        assert len(expired) == 1
        assert expired[0].exception_id == expired_exc.exception_id
        assert exception_repo.get(expired_exc.exception_id).status == ExceptionStatus.EXPIRED

    def test_expired_exception_can_never_be_reactivated_via_state_machine(self, exception_repo, audit_repo):
        """Required regression: expired exception reuse. Once EXPIRED, the
        allow-listed state machine has no transition back to ACTIVE -- this
        is enforced independent of any application logic."""
        from src.domain.state_machine.exception_transitions import validate_transition

        with pytest.raises(InvalidStateTransitionError):
            validate_transition(ExceptionStatus.EXPIRED, ExceptionStatus.ACTIVE)


class TestRevokePolicyExceptionUseCase:
    def test_authorized_role_can_revoke_active_exception(self, exception_repo, audit_repo, authz):
        from src.domain.entities.policy_exception import PolicyException
        from tests.fixtures.builders import unique_id

        active = exception_repo.create(
            PolicyException(
                exception_id=unique_id("exc"),
                policy_id="POL-NET-001",
                resource_id="r1",
                finding_id="f1",
                managed_system_id="sys1",
                business_justification="j",
                risk_statement="r",
                compensating_controls=(),
                requested_expiration=FIXED_NOW + timedelta(days=30),
                requested_by="dev.one",
                evidence=(),
                correlation_id="c1",
                status=ExceptionStatus.ACTIVE,
                expires_at=FIXED_NOW + timedelta(days=30),
            )
        )
        use_case = RevokePolicyExceptionUseCase(exception_repo, audit_repo, authz, _clock)
        revoker = make_actor("reviewer.one", ActorRole.SECURITY_REVIEWER)
        updated = use_case.execute(
            active.exception_id, reason="risk changed", actor=revoker, correlation_id="c1"
        )
        assert updated.status == ExceptionStatus.REVOKED
        assert updated.revoked_by == "reviewer.one"


class TestKillSwitchUseCase:
    def test_authorized_platform_admin_can_change_mode(self, audit_repo):
        kill_switch_repo = FakeKillSwitchRepository()
        use_case = KillSwitchUseCase(kill_switch_repo, audit_repo)
        admin = make_actor("admin.one", ActorRole.PLATFORM_ADMIN)
        state = use_case.set_mode(
            SystemMode.EMERGENCY_STOP, reason="incident", actor=admin, correlation_id="c1"
        )
        assert state.mode == SystemMode.EMERGENCY_STOP
        assert audit_repo.events[-1].action == "KILL_SWITCH_MODE_CHANGED"

    def test_unauthorized_role_cannot_change_mode_and_is_audited_as_denied(self, audit_repo):
        """Required regression: kill-switch bypass attempts must be
        rejected and still recorded in the audit trail as DENIED."""
        kill_switch_repo = FakeKillSwitchRepository()
        use_case = KillSwitchUseCase(kill_switch_repo, audit_repo)
        non_admin = make_actor("dev.one", ActorRole.SYSTEM_OWNER)
        with pytest.raises(UnauthorizedKillSwitchChangeError):
            use_case.set_mode(
                SystemMode.NORMAL, reason="trying to bypass", actor=non_admin, correlation_id="c1"
            )
        assert audit_repo.events[-1].action == "KILL_SWITCH_CHANGE_DENIED"
        assert audit_repo.events[-1].outcome == "DENIED"

    def test_unreliable_state_read_is_treated_as_unavailable_not_normal(self):
        """Fail-closed regression: a kill switch that cannot be read
        reliably (no row ever seeded) must raise, never silently report
        NORMAL."""
        from src.adapters.persistence.kill_switch_repository_sqlalchemy import KillSwitchStateUnavailableError

        kill_switch_repo = FakeKillSwitchRepository(initial=None)
        with pytest.raises(KillSwitchStateUnavailableError):
            kill_switch_repo.get_state()
