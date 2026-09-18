from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.adapters.persistence.mappers import orm_to_remediation_plan, remediation_plan_to_orm
from src.adapters.persistence.models import RemediationPlanORM
from src.domain.entities.remediation_plan import RemediationPlan
from src.domain.enums.remediation_status import RemediationStatus
from src.ports.remediation_repository import RemediationPlanNotFoundError


class SqlAlchemyRemediationPlanRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, plan: RemediationPlan) -> RemediationPlan:
        orm = remediation_plan_to_orm(plan)
        self._session.add(orm)
        self._session.commit()
        return orm_to_remediation_plan(orm)

    def get(self, plan_id: str) -> RemediationPlan:
        orm = self._session.get(RemediationPlanORM, plan_id)
        if orm is None:
            raise RemediationPlanNotFoundError(f"remediation plan {plan_id!r} not found")
        return orm_to_remediation_plan(orm)

    def get_for_finding(self, finding_id: str) -> RemediationPlan | None:
        orm = self._session.execute(
            select(RemediationPlanORM)
            .where(RemediationPlanORM.finding_id == finding_id)
            .order_by(RemediationPlanORM.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        return orm_to_remediation_plan(orm) if orm is not None else None

    def update_status(
        self,
        plan_id: str,
        status: RemediationStatus,
        *,
        verification_evidence: tuple[str, ...] = (),
    ) -> RemediationPlan:
        orm = self._session.get(RemediationPlanORM, plan_id)
        if orm is None:
            raise RemediationPlanNotFoundError(f"remediation plan {plan_id!r} not found")
        orm.status = status.value
        if verification_evidence:
            orm.verification_evidence = list(verification_evidence)
        orm.updated_at = datetime.now(UTC)
        self._session.commit()
        return orm_to_remediation_plan(orm)

    def list(
        self, *, managed_system_id: str | None = None, limit: int = 50, offset: int = 0
    ) -> tuple[list[RemediationPlan], int]:
        stmt = select(RemediationPlanORM)
        count_stmt = select(func.count()).select_from(RemediationPlanORM)
        if managed_system_id is not None:
            stmt = stmt.where(RemediationPlanORM.managed_system_id == managed_system_id)
            count_stmt = count_stmt.where(RemediationPlanORM.managed_system_id == managed_system_id)

        total = self._session.execute(count_stmt).scalar_one()
        rows = (
            self._session.execute(
                stmt.order_by(RemediationPlanORM.created_at.desc()).limit(limit).offset(offset)
            )
            .scalars()
            .all()
        )
        return [orm_to_remediation_plan(r) for r in rows], total
