"""Domain unit tests: every explicit, allow-listed state machine (spec
section 5: "All state transitions must use explicit allow-listed state
machines. Invalid transitions must fail closed.").

Required regression: invalid state transitions must raise, never silently
succeed or default-allow.
"""

from __future__ import annotations

import pytest

from src.domain.enums.decision_type import DecisionType
from src.domain.enums.exception_status import ExceptionStatus
from src.domain.enums.finding_status import FindingStatus
from src.domain.enums.remediation_status import RemediationStatus
from src.domain.state_machine import (
    decision_transitions,
    exception_transitions,
    finding_transitions,
    remediation_transitions,
)
from src.domain.state_machine.errors import InvalidStateTransitionError


class TestExceptionTransitions:
    def test_valid_lifecycle_path(self):
        exception_transitions.validate_transition(ExceptionStatus.REQUESTED, ExceptionStatus.UNDER_REVIEW)
        exception_transitions.validate_transition(ExceptionStatus.UNDER_REVIEW, ExceptionStatus.APPROVED)
        exception_transitions.validate_transition(ExceptionStatus.APPROVED, ExceptionStatus.ACTIVE)
        exception_transitions.validate_transition(ExceptionStatus.ACTIVE, ExceptionStatus.EXPIRED)

    def test_rejected_and_expired_and_revoked_are_terminal(self):
        for terminal in (ExceptionStatus.REJECTED, ExceptionStatus.EXPIRED, ExceptionStatus.REVOKED):
            for target in ExceptionStatus:
                assert not exception_transitions.is_transition_allowed(terminal, target)

    def test_invalid_transition_raises(self):
        # Regression: cannot skip straight from REQUESTED to ACTIVE.
        with pytest.raises(InvalidStateTransitionError):
            exception_transitions.validate_transition(ExceptionStatus.REQUESTED, ExceptionStatus.ACTIVE)

    def test_cannot_reactivate_an_expired_exception(self):
        # Regression: "expired exception reuse" must fail closed at the
        # state-machine level, independent of any application-layer check.
        with pytest.raises(InvalidStateTransitionError):
            exception_transitions.validate_transition(ExceptionStatus.EXPIRED, ExceptionStatus.ACTIVE)


class TestFindingTransitions:
    def test_open_can_move_to_acknowledged_exception_or_remediated(self):
        for target in (
            FindingStatus.ACKNOWLEDGED,
            FindingStatus.EXCEPTION_GRANTED,
            FindingStatus.REMEDIATED,
        ):
            finding_transitions.validate_transition(FindingStatus.OPEN, target)

    def test_open_cannot_jump_directly_to_closed(self):
        with pytest.raises(InvalidStateTransitionError):
            finding_transitions.validate_transition(FindingStatus.OPEN, FindingStatus.CLOSED)

    def test_closed_can_only_reopen(self):
        assert finding_transitions.is_transition_allowed(FindingStatus.CLOSED, FindingStatus.REOPENED)
        for target in FindingStatus:
            if target is FindingStatus.REOPENED:
                continue
            assert not finding_transitions.is_transition_allowed(FindingStatus.CLOSED, target)


class TestRemediationTransitions:
    def test_valid_forward_path(self):
        remediation_transitions.validate_transition(RemediationStatus.NOT_STARTED, RemediationStatus.PLANNED)
        remediation_transitions.validate_transition(RemediationStatus.PLANNED, RemediationStatus.IN_PROGRESS)
        remediation_transitions.validate_transition(
            RemediationStatus.IN_PROGRESS, RemediationStatus.COMPLETED
        )
        remediation_transitions.validate_transition(RemediationStatus.COMPLETED, RemediationStatus.VERIFIED)

    def test_verified_and_cancelled_are_terminal(self):
        for terminal in (RemediationStatus.VERIFIED, RemediationStatus.CANCELLED):
            for target in RemediationStatus:
                assert not remediation_transitions.is_transition_allowed(terminal, target)

    def test_cannot_skip_from_not_started_to_completed(self):
        with pytest.raises(InvalidStateTransitionError):
            remediation_transitions.validate_transition(
                RemediationStatus.NOT_STARTED, RemediationStatus.COMPLETED
            )


class TestDecisionTransitions:
    def test_governance_block_can_recover_to_remediation_or_compliant(self):
        decision_transitions.validate_transition(
            DecisionType.GOVERNANCE_BLOCK, DecisionType.REMEDIATION_REQUIRED
        )
        decision_transitions.validate_transition(DecisionType.GOVERNANCE_BLOCK, DecisionType.COMPLIANT)

    def test_governance_block_cannot_jump_to_observation_recorded(self):
        # A hard block silently becoming a mere observation with no
        # intervening remediation/exception is exactly the orchestration bug
        # this table exists to catch.
        with pytest.raises(InvalidStateTransitionError):
            decision_transitions.validate_transition(
                DecisionType.GOVERNANCE_BLOCK, DecisionType.OBSERVATION_RECORDED
            )

    def test_error_message_names_entity_and_both_states(self):
        with pytest.raises(InvalidStateTransitionError) as exc_info:
            finding_transitions.validate_transition(FindingStatus.OPEN, FindingStatus.CLOSED)
        err = exc_info.value
        assert err.entity == "finding"
        assert err.current == FindingStatus.OPEN
        assert err.target == FindingStatus.CLOSED
        assert "open" in str(err) and "closed" in str(err)
