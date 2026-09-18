from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.adapters.persistence.mappers import managed_system_to_orm, orm_to_managed_system
from src.adapters.persistence.models import ManagedSystemORM
from src.domain.entities.managed_system import ManagedSystem
from src.ports.managed_system_repository import ManagedSystemNotFoundError


class SqlAlchemyManagedSystemRepository:
    """PostgreSQL implementation of ManagedSystemRepository. All queries use
    SQLAlchemy Core/ORM constructs (select/where/get) -- no raw or
    string-interpolated SQL anywhere in this class."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, system: ManagedSystem) -> ManagedSystem:
        orm = managed_system_to_orm(system)
        self._session.add(orm)
        self._session.commit()
        return orm_to_managed_system(orm)

    def get(self, system_id: str) -> ManagedSystem:
        orm = self._session.get(ManagedSystemORM, system_id)
        if orm is None:
            raise ManagedSystemNotFoundError(f"managed system {system_id!r} not found")
        return orm_to_managed_system(orm)

    def exists(self, system_id: str) -> bool:
        return self._session.get(ManagedSystemORM, system_id) is not None

    def list(self, *, limit: int = 50, offset: int = 0) -> tuple[list[ManagedSystem], int]:
        total = self._session.execute(select(func.count()).select_from(ManagedSystemORM)).scalar_one()
        rows = (
            self._session.execute(
                select(ManagedSystemORM)
                .order_by(ManagedSystemORM.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            .scalars()
            .all()
        )
        return [orm_to_managed_system(r) for r in rows], total
