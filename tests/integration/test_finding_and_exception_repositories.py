"""PostgreSQL integration tests: finding and policy-exception repositories."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import sessionmaker

from src.adapters.persistence.exception_repository_sqlalchemy import SqlAlchemyPolicyExceptionRepository
from src.adapters.persistence.finding_repository_sqlalchemy import (
    SqlAlchemyComplianceFindingRepository,
    SqlAlchemyDriftFindingRepository,
)
from src.domain.entities.compliance_finding import ComplianceFinding
from src.domain.entities.policy_exception import PolicyException
from src.domain.enums.exception_status import ExceptionStatus
from src.domain.enums.finding_status import FindingStatus
from src.domain.enums.policy_category import PolicyCategory
from src.domain.enums.policy_severity import PolicySeverity
from src.ports.exception_repository import PolicyExceptionNotFoundError
from src.ports.finding_repository import FindingNotFoundError
from tests.fixtures.builders import unique_id


@pytest.fixture()
def session(db_engine):
    factory = sessionmaker(bind=db_engine, future=True)
    s = factory()
    yield s
    s.close()


def _compliance_finding(**overrides) -> ComplianceFinding:
    base = dict(
        finding_id=unique_id("finding"),
        managed_system_id="sys1",
        resource_id="r1",
        policy_id="POL-NET-001",
        category=PolicyCategory.PUBLIC_NETWORK_EXPOSURE,
        severity=PolicySeverity.HIGH,
        title="Public exposure",
        explanation="resource is public",
        evidence=("attributes.publicly_accessible=true",),
        remediation_guidance="restrict access",
        exception_eligible=True,
        correlation_id="corr-1",
    )
    base.update(overrides)
    return ComplianceFinding(**base)


class TestComplianceFindingRepository:
    def test_create_many_and_get(self, session):
        repo = SqlAlchemyComplianceFindingRepository(session)
        finding = _compliance_finding()
        created = repo.create_many([finding])
        fetched = repo.get(created[0].finding_id)
        assert fetched.policy_id == "POL-NET-001"
        assert fetched.status == FindingStatus.OPEN

    def test_get_missing_raises(self, session):
        repo = SqlAlchemyComplianceFindingRepository(session)
        with pytest.raises(FindingNotFoundError):
            repo.get("nope")

    def test_update_status_persists(self, session):
        repo = SqlAlchemyComplianceFindingRepository(session)
        created = repo.create_many([_compliance_finding()])[0]
        updated = repo.update_status(created.finding_id, FindingStatus.ACKNOWLEDGED)
        assert updated.status == FindingStatus.ACKNOWLEDGED
        assert repo.get(created.finding_id).status == FindingStatus.ACKNOWLEDGED

    def test_count_recent_violations(self, session):
        repo = SqlAlchemyComplianceFindingRepository(session)
        for _ in range(3):
            repo.create_many([_compliance_finding(policy_id="POL-NET-001", resource_id="r-repeat")])
        count = repo.count_recent_violations(policy_id="POL-NET-001", resource_id="r-repeat", within_last=10)
        assert count == 3

    def test_list_filters_by_managed_system_and_status(self, session):
        repo = SqlAlchemyComplianceFindingRepository(session)
        repo.create_many([_compliance_finding(managed_system_id="sys-a")])
        repo.create_many([_compliance_finding(managed_system_id="sys-b")])
        items, total = repo.list(managed_system_id="sys-a", limit=50, offset=0)
        assert total == 1
        assert items[0].managed_system_id == "sys-a"


class TestDriftFindingRepository:
    def test_create_many_and_get(self, session):
        from src.domain.entities.drift_finding import DriftFinding
        from src.domain.enums.drift_type import DriftType

        repo = SqlAlchemyDriftFindingRepository(session)
        finding = DriftFinding(
            finding_id=unique_id("drift"),
            managed_system_id="sys1",
            resource_id="r1",
            drift_type=DriftType.SECURITY,
            what_changed="publicly accessible flag enabled",
            previous_value="False",
            current_value="True",
            expected_value="False",
            why_it_matters="attack surface increased",
            severity=PolicySeverity.CRITICAL,
            evidence=("attributes.publicly_accessible",),
            remediation="restrict access",
            exception_eligible=False,
            correlation_id="corr-1",
            policy_id="POL-NET-001",
        )
        created = repo.create_many([finding])[0]
        fetched = repo.get(created.finding_id)
        assert fetched.drift_type == DriftType.SECURITY
        assert fetched.exception_eligible is False


class TestPolicyExceptionRepository:
    def _exception(self, **overrides) -> PolicyException:
        base = dict(
            exception_id=unique_id("exc"),
            policy_id="POL-NET-001",
            resource_id="r1",
            finding_id="f1",
            managed_system_id="sys1",
            business_justification="justified",
            risk_statement="accepted",
            compensating_controls=("extra monitoring",),
            requested_expiration=datetime.now(UTC) + timedelta(days=30),
            requested_by="dev.one",
            evidence=("ticket:JIRA-1",),
            correlation_id="corr-1",
        )
        base.update(overrides)
        return PolicyException(**base)

    def test_create_and_get_round_trip(self, session):
        repo = SqlAlchemyPolicyExceptionRepository(session)
        exc = self._exception()
        repo.create(exc)
        fetched = repo.get(exc.exception_id)
        assert fetched.status == ExceptionStatus.REQUESTED
        assert fetched.compensating_controls == exc.compensating_controls

    def test_get_missing_raises(self, session):
        repo = SqlAlchemyPolicyExceptionRepository(session)
        with pytest.raises(PolicyExceptionNotFoundError):
            repo.get("nope")

    def test_update_persists_status_change(self, session):
        repo = SqlAlchemyPolicyExceptionRepository(session)
        exc = repo.create(self._exception())
        updated = repo.update(exc.with_status(ExceptionStatus.UNDER_REVIEW))
        assert updated.status == ExceptionStatus.UNDER_REVIEW
        assert repo.get(exc.exception_id).status == ExceptionStatus.UNDER_REVIEW

    def test_list_active_for_system_includes_expired_and_revoked(self, session):
        """Regression-relevant: EXPIRED/REVOKED exceptions must still be
        returned by list_active_for_system so evaluators can see them (and
        thus stop suppressing findings) -- see module docstring on the
        Protocol itself."""
        repo = SqlAlchemyPolicyExceptionRepository(session)
        active = repo.create(self._exception(status=ExceptionStatus.ACTIVE))
        expired = repo.create(self._exception(status=ExceptionStatus.EXPIRED, resource_id="r2"))
        rejected = repo.create(self._exception(status=ExceptionStatus.REJECTED, resource_id="r3"))

        relevant = repo.list_active_for_system("sys1")
        relevant_ids = {e.exception_id for e in relevant}
        assert active.exception_id in relevant_ids
        assert expired.exception_id in relevant_ids
        assert rejected.exception_id not in relevant_ids  # rejected was never suppressing anything

    def test_list_expiring_before_only_returns_active_with_past_cutoff(self, session):
        repo = SqlAlchemyPolicyExceptionRepository(session)
        soon_to_expire = repo.create(
            self._exception(status=ExceptionStatus.ACTIVE, expires_at=datetime.now(UTC) - timedelta(hours=1))
        )
        still_valid = repo.create(
            self._exception(
                status=ExceptionStatus.ACTIVE,
                resource_id="r2",
                expires_at=datetime.now(UTC) + timedelta(days=30),
            )
        )
        expiring = repo.list_expiring_before(datetime.now(UTC))
        ids = {e.exception_id for e in expiring}
        assert soon_to_expire.exception_id in ids
        assert still_valid.exception_id not in ids

    def test_list_filters_by_status_and_paginates(self, session):
        repo = SqlAlchemyPolicyExceptionRepository(session)
        for i in range(3):
            repo.create(self._exception(resource_id=f"r-{i}"))
        items, total = repo.list(status=ExceptionStatus.REQUESTED, limit=2, offset=0)
        assert total == 3
        assert len(items) == 2
