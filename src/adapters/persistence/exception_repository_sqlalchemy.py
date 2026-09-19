from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.adapters.persistence.mappers import orm_to_policy_exception, policy_exception_to_orm
from src.adapters.persistence.models import PolicyExceptionORM
from src.domain.entities.policy_exception import PolicyException
from src.domain.enums.exception_status import ExceptionStatus
from src.ports.exception_repository import PolicyExceptionNotFoundError

# Statuses relevant to policy/drift re-evaluation: those currently
# suppressing a violation, or that recently stopped doing so (spec section
# 12 -- an expired/revoked exception must stop suppressing findings
# immediately, so evaluators must still see it on record).
_RELEVANT_FOR_EVALUATION = (
    ExceptionStatus.APPROVED,
    ExceptionStatus.ACTIVE,
    ExceptionStatus.EXPIRED,
    ExceptionStatus.REVOKED,
)


class SqlAlchemyPolicyExceptionRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, exception: PolicyException) -> PolicyException:
        orm = policy_exception_to_orm(exception)
        self._session.add(orm)
        self._session.commit()
        return orm_to_policy_exception(orm)

    def get(self, exception_id: str) -> PolicyException:
        orm = self._session.get(PolicyExceptionORM, exception_id)
        if orm is None:
            raise PolicyExceptionNotFoundError(f"policy exception {exception_id!r} not found")
        return orm_to_policy_exception(orm)

    def update(self, exception: PolicyException) -> PolicyException:
        orm = self._session.get(PolicyExceptionORM, exception.exception_id)
        if orm is None:
            raise PolicyExceptionNotFoundError(f"policy exception {exception.exception_id!r} not found")
        updated = policy_exception_to_orm(exception)
        for column in PolicyExceptionORM.__table__.columns.keys():
            if column == "exception_id":
                continue
            setattr(orm, column, getattr(updated, column))
        self._session.commit()
        return orm_to_policy_exception(orm)

    def list(
        self,
        *,
        managed_system_id: str | None = None,
        status: ExceptionStatus | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[PolicyException], int]:
        stmt = select(PolicyExceptionORM)
        count_stmt = select(func.count()).select_from(PolicyExceptionORM)
        if managed_system_id is not None:
            stmt = stmt.where(PolicyExceptionORM.managed_system_id == managed_system_id)
            count_stmt = count_stmt.where(PolicyExceptionORM.managed_system_id == managed_system_id)
        if status is not None:
            stmt = stmt.where(PolicyExceptionORM.status == status.value)
            count_stmt = count_stmt.where(PolicyExceptionORM.status == status.value)

        total = self._session.execute(count_stmt).scalar_one()
        rows = (
            self._session.execute(
                stmt.order_by(PolicyExceptionORM.created_at.desc()).limit(limit).offset(offset)
            )
            .scalars()
            .all()
        )
        return [orm_to_policy_exception(r) for r in rows], total

    def list_active_for_system(self, managed_system_id: str) -> Sequence[PolicyException]:
        rows = (
            self._session.execute(
                select(PolicyExceptionORM).where(
                    PolicyExceptionORM.managed_system_id == managed_system_id,
                    PolicyExceptionORM.status.in_([s.value for s in _RELEVANT_FOR_EVALUATION]),
                )
            )
            .scalars()
            .all()
        )
        return [orm_to_policy_exception(r) for r in rows]

    def list_expiring_before(self, cutoff: datetime) -> Sequence[PolicyException]:
        rows = (
            self._session.execute(
                select(PolicyExceptionORM).where(
                    PolicyExceptionORM.status == ExceptionStatus.ACTIVE.value,
                    PolicyExceptionORM.expires_at.is_not(None),
                    PolicyExceptionORM.expires_at < cutoff,
                )
            )
            .scalars()
            .all()
        )
        return [orm_to_policy_exception(r) for r in rows]
