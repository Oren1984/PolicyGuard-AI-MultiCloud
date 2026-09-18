"""DI wiring for every Phase 1 application use case, wired to the Phase 2
repositories from `repositories.py`. `id_factory`/`clock` are the same kind
of small, explicit, injected side-effect boundaries the use cases already
require (see e.g. `RequestPolicyExceptionUseCase.__init__`) -- a real UUID4
generator and `datetime.now(UTC)`, not a fake."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import Depends

from src.api.dependencies.repositories import (
    get_audit_repo,
    get_compliance_finding_repo,
    get_decision_repo,
    get_desired_snapshot_repo,
    get_drift_finding_repo,
    get_exception_repo,
    get_kill_switch_repo,
    get_managed_system_repo,
    get_observed_snapshot_repo,
    get_policy_pack_repo,
    get_remediation_repo,
)
from src.application.services.exception_authorization import ExceptionAuthorizationService
from src.application.use_cases.audit_use_cases import RecordAuditEventUseCase, VerifyAuditChainUseCase
from src.application.use_cases.decide_exception import DecidePolicyExceptionUseCase
from src.application.use_cases.detect_drift import DetectDriftUseCase
from src.application.use_cases.evaluate_policy_pack import EvaluatePolicyPackUseCase
from src.application.use_cases.expire_exceptions import ExpireExceptionsUseCase
from src.application.use_cases.generate_governance_decision import GenerateGovernanceDecisionUseCase
from src.application.use_cases.kill_switch import KillSwitchUseCase
from src.application.use_cases.request_exception import RequestPolicyExceptionUseCase
from src.application.use_cases.review_exception import ReviewPolicyExceptionUseCase
from src.application.use_cases.revoke_exception import RevokePolicyExceptionUseCase
from src.application.use_cases.submit_desired_state import SubmitDesiredStateSnapshotUseCase
from src.application.use_cases.submit_observed_state import SubmitObservedStateSnapshotUseCase
from src.application.use_cases.update_remediation_status import UpdateRemediationStatusUseCase


def _id_factory() -> str:
    return uuid.uuid4().hex


def _clock() -> datetime:
    return datetime.now(UTC)


def get_exception_authorization_service() -> ExceptionAuthorizationService:
    return ExceptionAuthorizationService()


def get_submit_desired_state_use_case(
    snapshot_repo=Depends(get_desired_snapshot_repo),
    audit_repo=Depends(get_audit_repo),
) -> SubmitDesiredStateSnapshotUseCase:
    return SubmitDesiredStateSnapshotUseCase(snapshot_repo, audit_repo)


def get_submit_observed_state_use_case(
    snapshot_repo=Depends(get_observed_snapshot_repo),
    audit_repo=Depends(get_audit_repo),
) -> SubmitObservedStateSnapshotUseCase:
    return SubmitObservedStateSnapshotUseCase(snapshot_repo, audit_repo)


def get_evaluate_policy_pack_use_case(
    managed_system_repo=Depends(get_managed_system_repo),
    desired_snapshot_repo=Depends(get_desired_snapshot_repo),
    observed_snapshot_repo=Depends(get_observed_snapshot_repo),
    policy_pack_repo=Depends(get_policy_pack_repo),
    finding_repo=Depends(get_compliance_finding_repo),
    exception_repo=Depends(get_exception_repo),
    kill_switch_repo=Depends(get_kill_switch_repo),
    audit_repo=Depends(get_audit_repo),
) -> EvaluatePolicyPackUseCase:
    return EvaluatePolicyPackUseCase(
        managed_system_repo=managed_system_repo,
        desired_snapshot_repo=desired_snapshot_repo,
        observed_snapshot_repo=observed_snapshot_repo,
        policy_pack_repo=policy_pack_repo,
        finding_repo=finding_repo,
        exception_repo=exception_repo,
        kill_switch_repo=kill_switch_repo,
        audit_repo=audit_repo,
        id_factory=_id_factory,
        clock=_clock,
    )


def get_detect_drift_use_case(
    desired_snapshot_repo=Depends(get_desired_snapshot_repo),
    observed_snapshot_repo=Depends(get_observed_snapshot_repo),
    drift_finding_repo=Depends(get_drift_finding_repo),
    exception_repo=Depends(get_exception_repo),
    kill_switch_repo=Depends(get_kill_switch_repo),
    audit_repo=Depends(get_audit_repo),
) -> DetectDriftUseCase:
    return DetectDriftUseCase(
        desired_snapshot_repo=desired_snapshot_repo,
        observed_snapshot_repo=observed_snapshot_repo,
        drift_finding_repo=drift_finding_repo,
        exception_repo=exception_repo,
        kill_switch_repo=kill_switch_repo,
        audit_repo=audit_repo,
        id_factory=_id_factory,
        clock=_clock,
    )


def get_generate_governance_decision_use_case(
    managed_system_repo=Depends(get_managed_system_repo),
    observed_snapshot_repo=Depends(get_observed_snapshot_repo),
    compliance_finding_repo=Depends(get_compliance_finding_repo),
    drift_finding_repo=Depends(get_drift_finding_repo),
    exception_repo=Depends(get_exception_repo),
    decision_repo=Depends(get_decision_repo),
    kill_switch_repo=Depends(get_kill_switch_repo),
    audit_repo=Depends(get_audit_repo),
) -> GenerateGovernanceDecisionUseCase:
    return GenerateGovernanceDecisionUseCase(
        managed_system_repo=managed_system_repo,
        observed_snapshot_repo=observed_snapshot_repo,
        compliance_finding_repo=compliance_finding_repo,
        drift_finding_repo=drift_finding_repo,
        exception_repo=exception_repo,
        decision_repo=decision_repo,
        kill_switch_repo=kill_switch_repo,
        audit_repo=audit_repo,
        id_factory=_id_factory,
        clock=_clock,
    )


def get_request_exception_use_case(
    exception_repo=Depends(get_exception_repo),
    audit_repo=Depends(get_audit_repo),
    authz: ExceptionAuthorizationService = Depends(get_exception_authorization_service),
) -> RequestPolicyExceptionUseCase:
    return RequestPolicyExceptionUseCase(exception_repo, audit_repo, authz, _id_factory, _clock)


def get_review_exception_use_case(
    exception_repo=Depends(get_exception_repo),
    audit_repo=Depends(get_audit_repo),
    authz: ExceptionAuthorizationService = Depends(get_exception_authorization_service),
) -> ReviewPolicyExceptionUseCase:
    return ReviewPolicyExceptionUseCase(exception_repo, audit_repo, authz)


def get_decide_exception_use_case(
    exception_repo=Depends(get_exception_repo),
    audit_repo=Depends(get_audit_repo),
    authz: ExceptionAuthorizationService = Depends(get_exception_authorization_service),
) -> DecidePolicyExceptionUseCase:
    return DecidePolicyExceptionUseCase(exception_repo, audit_repo, authz, _id_factory, _clock)


def get_revoke_exception_use_case(
    exception_repo=Depends(get_exception_repo),
    audit_repo=Depends(get_audit_repo),
    authz: ExceptionAuthorizationService = Depends(get_exception_authorization_service),
) -> RevokePolicyExceptionUseCase:
    return RevokePolicyExceptionUseCase(exception_repo, audit_repo, authz, _clock)


def get_expire_exceptions_use_case(
    exception_repo=Depends(get_exception_repo),
    audit_repo=Depends(get_audit_repo),
) -> ExpireExceptionsUseCase:
    return ExpireExceptionsUseCase(exception_repo, audit_repo, _clock)


def get_update_remediation_status_use_case(
    remediation_repo=Depends(get_remediation_repo),
    audit_repo=Depends(get_audit_repo),
) -> UpdateRemediationStatusUseCase:
    return UpdateRemediationStatusUseCase(remediation_repo, audit_repo, _clock)


def get_kill_switch_use_case(
    kill_switch_repo=Depends(get_kill_switch_repo),
    audit_repo=Depends(get_audit_repo),
) -> KillSwitchUseCase:
    return KillSwitchUseCase(kill_switch_repo, audit_repo)


def get_record_audit_event_use_case(
    audit_repo=Depends(get_audit_repo),
) -> RecordAuditEventUseCase:
    return RecordAuditEventUseCase(audit_repo)


def get_verify_audit_chain_use_case(
    audit_repo=Depends(get_audit_repo),
) -> VerifyAuditChainUseCase:
    return VerifyAuditChainUseCase(audit_repo, _clock)
