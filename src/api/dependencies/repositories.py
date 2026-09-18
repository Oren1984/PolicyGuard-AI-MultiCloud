"""DI wiring for every Phase 2 SqlAlchemy repository, one request-scoped
instance per port, all sharing the one request-scoped Session from
`get_db`."""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.orm import Session

from src.adapters.persistence.audit_repository_sqlalchemy import SqlAlchemyAuditEventRepository
from src.adapters.persistence.decision_repository_sqlalchemy import SqlAlchemyGovernanceDecisionRepository
from src.adapters.persistence.exception_repository_sqlalchemy import SqlAlchemyPolicyExceptionRepository
from src.adapters.persistence.finding_repository_sqlalchemy import (
    SqlAlchemyComplianceFindingRepository,
    SqlAlchemyDriftFindingRepository,
)
from src.adapters.persistence.kill_switch_repository_sqlalchemy import SqlAlchemyKillSwitchRepository
from src.adapters.persistence.managed_system_repository_sqlalchemy import SqlAlchemyManagedSystemRepository
from src.adapters.persistence.policy_repository_sqlalchemy import (
    SqlAlchemyPolicyPackRepository,
    SqlAlchemyPolicyRepository,
)
from src.adapters.persistence.remediation_repository_sqlalchemy import SqlAlchemyRemediationPlanRepository
from src.adapters.persistence.snapshot_repository_sqlalchemy import (
    SqlAlchemyDesiredStateSnapshotRepository,
    SqlAlchemyObservedStateSnapshotRepository,
)
from src.api.dependencies.db import get_db


def get_managed_system_repo(session: Session = Depends(get_db)) -> SqlAlchemyManagedSystemRepository:
    return SqlAlchemyManagedSystemRepository(session)


def get_desired_snapshot_repo(
    session: Session = Depends(get_db),
) -> SqlAlchemyDesiredStateSnapshotRepository:
    return SqlAlchemyDesiredStateSnapshotRepository(session)


def get_observed_snapshot_repo(
    session: Session = Depends(get_db),
) -> SqlAlchemyObservedStateSnapshotRepository:
    return SqlAlchemyObservedStateSnapshotRepository(session)


def get_policy_repo(session: Session = Depends(get_db)) -> SqlAlchemyPolicyRepository:
    return SqlAlchemyPolicyRepository(session)


def get_policy_pack_repo(session: Session = Depends(get_db)) -> SqlAlchemyPolicyPackRepository:
    return SqlAlchemyPolicyPackRepository(session)


def get_compliance_finding_repo(
    session: Session = Depends(get_db),
) -> SqlAlchemyComplianceFindingRepository:
    return SqlAlchemyComplianceFindingRepository(session)


def get_drift_finding_repo(session: Session = Depends(get_db)) -> SqlAlchemyDriftFindingRepository:
    return SqlAlchemyDriftFindingRepository(session)


def get_decision_repo(session: Session = Depends(get_db)) -> SqlAlchemyGovernanceDecisionRepository:
    return SqlAlchemyGovernanceDecisionRepository(session)


def get_exception_repo(session: Session = Depends(get_db)) -> SqlAlchemyPolicyExceptionRepository:
    return SqlAlchemyPolicyExceptionRepository(session)


def get_remediation_repo(session: Session = Depends(get_db)) -> SqlAlchemyRemediationPlanRepository:
    return SqlAlchemyRemediationPlanRepository(session)


def get_audit_repo(session: Session = Depends(get_db)) -> SqlAlchemyAuditEventRepository:
    return SqlAlchemyAuditEventRepository(session)


def get_kill_switch_repo(session: Session = Depends(get_db)) -> SqlAlchemyKillSwitchRepository:
    return SqlAlchemyKillSwitchRepository(session)
