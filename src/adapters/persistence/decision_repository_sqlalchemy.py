from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.adapters.persistence.mappers import governance_decision_to_orm, orm_to_governance_decision
from src.adapters.persistence.models import GovernanceDecisionORM
from src.domain.entities.governance_decision import GovernanceDecision
from src.ports.decision_repository import GovernanceDecisionNotFoundError


class SqlAlchemyGovernanceDecisionRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, decision: GovernanceDecision) -> GovernanceDecision:
        orm = governance_decision_to_orm(decision)
        self._session.add(orm)
        self._session.commit()
        return orm_to_governance_decision(orm)

    def get(self, decision_id: str) -> GovernanceDecision:
        orm = self._session.get(GovernanceDecisionORM, decision_id)
        if orm is None:
            raise GovernanceDecisionNotFoundError(f"governance decision {decision_id!r} not found")
        return orm_to_governance_decision(orm)

    def list(
        self, *, managed_system_id: str | None = None, limit: int = 50, offset: int = 0
    ) -> tuple[list[GovernanceDecision], int]:
        stmt = select(GovernanceDecisionORM)
        count_stmt = select(func.count()).select_from(GovernanceDecisionORM)
        if managed_system_id is not None:
            stmt = stmt.where(GovernanceDecisionORM.managed_system_id == managed_system_id)
            count_stmt = count_stmt.where(GovernanceDecisionORM.managed_system_id == managed_system_id)

        total = self._session.execute(count_stmt).scalar_one()
        rows = (
            self._session.execute(
                stmt.order_by(GovernanceDecisionORM.decided_at.desc()).limit(limit).offset(offset)
            )
            .scalars()
            .all()
        )
        return [orm_to_governance_decision(r) for r in rows], total
