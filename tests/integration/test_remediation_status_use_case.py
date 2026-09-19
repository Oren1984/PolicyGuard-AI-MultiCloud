"""Integration test for UpdateRemediationStatusUseCase against real
PostgreSQL, added specifically because the equivalent HTTP path is currently
unreachable due to a pre-existing route-shadowing bug in
src/api/routes/findings.py (see the xfail tests in
tests/api/test_findings_and_decisions.py::TestRemediationPlans for the exact
mechanism). This proves the use case's own logic -- valid/invalid state
transitions, audit emission -- is correct independent of that API bug."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import sessionmaker

from src.adapters.persistence.audit_repository_sqlalchemy import SqlAlchemyAuditEventRepository
from src.adapters.persistence.remediation_repository_sqlalchemy import SqlAlchemyRemediationPlanRepository
from src.application.use_cases.update_remediation_status import UpdateRemediationStatusUseCase
from src.domain.entities.remediation_plan import RemediationPlan
from src.domain.enums.actor_role import ActorRole
from src.domain.enums.remediation_status import RemediationStatus
from src.domain.state_machine.errors import InvalidStateTransitionError
from tests.fixtures.builders import make_actor, unique_id


@pytest.fixture()
def session(db_engine):
    factory = sessionmaker(bind=db_engine, future=True)
    s = factory()
    yield s
    s.close()


def _clock():
    return datetime.now(UTC)


def test_valid_transition_persists_and_is_audited(session):
    remediation_repo = SqlAlchemyRemediationPlanRepository(session)
    audit_repo = SqlAlchemyAuditEventRepository(session)
    plan = remediation_repo.create(
        RemediationPlan(
            plan_id=unique_id("plan"),
            finding_id="f1",
            managed_system_id="sys1",
            description="restrict ingress",
            status=RemediationStatus.NOT_STARTED,
            assigned_to="owner.one",
            correlation_id="corr-1",
        )
    )
    use_case = UpdateRemediationStatusUseCase(remediation_repo, audit_repo, _clock)
    actor = make_actor("owner.one", ActorRole.SYSTEM_OWNER)
    updated = use_case.execute(
        plan.plan_id, target_status=RemediationStatus.IN_PROGRESS, actor=actor, correlation_id="c1"
    )
    assert updated.status == RemediationStatus.IN_PROGRESS
    assert audit_repo.list_recent(limit=1)[0].action == "REMEDIATION_STATUS_UPDATED"


def test_invalid_transition_raises_and_does_not_persist(session):
    remediation_repo = SqlAlchemyRemediationPlanRepository(session)
    audit_repo = SqlAlchemyAuditEventRepository(session)
    plan = remediation_repo.create(
        RemediationPlan(
            plan_id=unique_id("plan"),
            finding_id="f1",
            managed_system_id="sys1",
            description="restrict ingress",
            status=RemediationStatus.NOT_STARTED,
            assigned_to="owner.one",
            correlation_id="corr-1",
        )
    )
    use_case = UpdateRemediationStatusUseCase(remediation_repo, audit_repo, _clock)
    actor = make_actor("owner.one", ActorRole.SYSTEM_OWNER)
    with pytest.raises(InvalidStateTransitionError):
        use_case.execute(
            plan.plan_id, target_status=RemediationStatus.VERIFIED, actor=actor, correlation_id="c1"
        )
    assert remediation_repo.get(plan.plan_id).status == RemediationStatus.NOT_STARTED
    assert audit_repo.list_recent(limit=10) == []
