from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.adapters.persistence.mappers import (
    compliance_finding_to_orm,
    drift_finding_to_orm,
    orm_to_compliance_finding,
    orm_to_drift_finding,
)
from src.adapters.persistence.models import ComplianceFindingORM, DriftFindingORM
from src.domain.entities.compliance_finding import ComplianceFinding
from src.domain.entities.drift_finding import DriftFinding
from src.domain.enums.finding_status import FindingStatus
from src.ports.finding_repository import FindingNotFoundError


class SqlAlchemyComplianceFindingRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create_many(self, findings: list[ComplianceFinding]) -> list[ComplianceFinding]:
        orms = [compliance_finding_to_orm(f) for f in findings]
        self._session.add_all(orms)
        self._session.commit()
        return [orm_to_compliance_finding(o) for o in orms]

    def get(self, finding_id: str) -> ComplianceFinding:
        orm = self._session.get(ComplianceFindingORM, finding_id)
        if orm is None:
            raise FindingNotFoundError(f"compliance finding {finding_id!r} not found")
        return orm_to_compliance_finding(orm)

    def list(
        self,
        *,
        managed_system_id: str | None = None,
        status: FindingStatus | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[ComplianceFinding], int]:
        stmt = select(ComplianceFindingORM)
        count_stmt = select(func.count()).select_from(ComplianceFindingORM)
        if managed_system_id is not None:
            stmt = stmt.where(ComplianceFindingORM.managed_system_id == managed_system_id)
            count_stmt = count_stmt.where(ComplianceFindingORM.managed_system_id == managed_system_id)
        if status is not None:
            stmt = stmt.where(ComplianceFindingORM.status == status.value)
            count_stmt = count_stmt.where(ComplianceFindingORM.status == status.value)

        total = self._session.execute(count_stmt).scalar_one()
        rows = (
            self._session.execute(
                stmt.order_by(ComplianceFindingORM.detected_at.desc()).limit(limit).offset(offset)
            )
            .scalars()
            .all()
        )
        return [orm_to_compliance_finding(r) for r in rows], total

    def update_status(self, finding_id: str, status: FindingStatus) -> ComplianceFinding:
        orm = self._session.get(ComplianceFindingORM, finding_id)
        if orm is None:
            raise FindingNotFoundError(f"compliance finding {finding_id!r} not found")
        orm.status = status.value
        self._session.commit()
        return orm_to_compliance_finding(orm)

    def count_recent_violations(self, *, policy_id: str, resource_id: str, within_last: int) -> int:
        """Counts prior findings for this exact policy+resource pair, capped
        to the `within_last` most recent such findings (by detected_at)."""
        recent_ids_subquery = (
            select(ComplianceFindingORM.finding_id)
            .where(
                ComplianceFindingORM.policy_id == policy_id,
                ComplianceFindingORM.resource_id == resource_id,
            )
            .order_by(ComplianceFindingORM.detected_at.desc())
            .limit(within_last)
            .subquery()
        )
        return self._session.execute(
            select(func.count()).select_from(recent_ids_subquery)
        ).scalar_one()


class SqlAlchemyDriftFindingRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create_many(self, findings: list[DriftFinding]) -> list[DriftFinding]:
        orms = [drift_finding_to_orm(f) for f in findings]
        self._session.add_all(orms)
        self._session.commit()
        return [orm_to_drift_finding(o) for o in orms]

    def get(self, finding_id: str) -> DriftFinding:
        orm = self._session.get(DriftFindingORM, finding_id)
        if orm is None:
            raise FindingNotFoundError(f"drift finding {finding_id!r} not found")
        return orm_to_drift_finding(orm)

    def list(
        self,
        *,
        managed_system_id: str | None = None,
        status: FindingStatus | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[DriftFinding], int]:
        stmt = select(DriftFindingORM)
        count_stmt = select(func.count()).select_from(DriftFindingORM)
        if managed_system_id is not None:
            stmt = stmt.where(DriftFindingORM.managed_system_id == managed_system_id)
            count_stmt = count_stmt.where(DriftFindingORM.managed_system_id == managed_system_id)
        if status is not None:
            stmt = stmt.where(DriftFindingORM.status == status.value)
            count_stmt = count_stmt.where(DriftFindingORM.status == status.value)

        total = self._session.execute(count_stmt).scalar_one()
        rows = (
            self._session.execute(
                stmt.order_by(DriftFindingORM.detected_at.desc()).limit(limit).offset(offset)
            )
            .scalars()
            .all()
        )
        return [orm_to_drift_finding(r) for r in rows], total

    def update_status(self, finding_id: str, status: FindingStatus) -> DriftFinding:
        orm = self._session.get(DriftFindingORM, finding_id)
        if orm is None:
            raise FindingNotFoundError(f"drift finding {finding_id!r} not found")
        orm.status = status.value
        self._session.commit()
        return orm_to_drift_finding(orm)
