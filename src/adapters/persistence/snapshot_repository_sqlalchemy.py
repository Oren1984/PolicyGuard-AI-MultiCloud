from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.adapters.persistence.mappers import (
    desired_snapshot_to_orm,
    observed_snapshot_to_orm,
    orm_to_desired_snapshot,
    orm_to_observed_snapshot,
)
from src.adapters.persistence.models import DesiredStateSnapshotORM, ObservedStateSnapshotORM
from src.domain.entities.state_snapshot import DesiredStateSnapshot, ObservedStateSnapshot
from src.ports.snapshot_repository import SnapshotNotFoundError


class SqlAlchemyDesiredStateSnapshotRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, snapshot: DesiredStateSnapshot) -> DesiredStateSnapshot:
        orm = desired_snapshot_to_orm(snapshot)
        self._session.add(orm)
        self._session.commit()
        return orm_to_desired_snapshot(orm)

    def get(self, snapshot_id: str) -> DesiredStateSnapshot:
        orm = self._session.get(DesiredStateSnapshotORM, snapshot_id)
        if orm is None:
            raise SnapshotNotFoundError(f"desired-state snapshot {snapshot_id!r} not found")
        return orm_to_desired_snapshot(orm)

    def get_latest_for_system(self, managed_system_id: str) -> DesiredStateSnapshot | None:
        orm = self._session.execute(
            select(DesiredStateSnapshotORM)
            .where(DesiredStateSnapshotORM.managed_system_id == managed_system_id)
            .order_by(DesiredStateSnapshotORM.captured_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        return orm_to_desired_snapshot(orm) if orm is not None else None

    def list_for_system(
        self, managed_system_id: str, *, limit: int = 50
    ) -> list[DesiredStateSnapshot]:
        rows = (
            self._session.execute(
                select(DesiredStateSnapshotORM)
                .where(DesiredStateSnapshotORM.managed_system_id == managed_system_id)
                .order_by(DesiredStateSnapshotORM.captured_at.desc())
                .limit(limit)
            )
            .scalars()
            .all()
        )
        return [orm_to_desired_snapshot(r) for r in rows]


class SqlAlchemyObservedStateSnapshotRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, snapshot: ObservedStateSnapshot) -> ObservedStateSnapshot:
        orm = observed_snapshot_to_orm(snapshot)
        self._session.add(orm)
        self._session.commit()
        return orm_to_observed_snapshot(orm)

    def get(self, snapshot_id: str) -> ObservedStateSnapshot:
        orm = self._session.get(ObservedStateSnapshotORM, snapshot_id)
        if orm is None:
            raise SnapshotNotFoundError(f"observed-state snapshot {snapshot_id!r} not found")
        return orm_to_observed_snapshot(orm)

    def get_latest_for_system(self, managed_system_id: str) -> ObservedStateSnapshot | None:
        orm = self._session.execute(
            select(ObservedStateSnapshotORM)
            .where(ObservedStateSnapshotORM.managed_system_id == managed_system_id)
            .order_by(ObservedStateSnapshotORM.captured_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        return orm_to_observed_snapshot(orm) if orm is not None else None

    def get_previous_for_system(
        self, managed_system_id: str, *, before_snapshot_id: str
    ) -> ObservedStateSnapshot | None:
        anchor = self._session.get(ObservedStateSnapshotORM, before_snapshot_id)
        if anchor is None:
            raise SnapshotNotFoundError(f"observed-state snapshot {before_snapshot_id!r} not found")
        orm = self._session.execute(
            select(ObservedStateSnapshotORM)
            .where(
                ObservedStateSnapshotORM.managed_system_id == managed_system_id,
                ObservedStateSnapshotORM.captured_at < anchor.captured_at,
            )
            .order_by(ObservedStateSnapshotORM.captured_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        return orm_to_observed_snapshot(orm) if orm is not None else None

    def list_for_system(
        self, managed_system_id: str, *, limit: int = 50
    ) -> list[ObservedStateSnapshot]:
        rows = (
            self._session.execute(
                select(ObservedStateSnapshotORM)
                .where(ObservedStateSnapshotORM.managed_system_id == managed_system_id)
                .order_by(ObservedStateSnapshotORM.captured_at.desc())
                .limit(limit)
            )
            .scalars()
            .all()
        )
        return [orm_to_observed_snapshot(r) for r in rows]
