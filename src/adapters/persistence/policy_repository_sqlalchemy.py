from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.adapters.persistence.mappers import orm_to_policy, policy_to_orm
from src.adapters.persistence.models import PolicyORM, PolicyPackORM
from src.adapters.persistence.policy_registry import resolve_evaluate_fn
from src.domain.entities.policy import Policy, PolicyPack
from src.ports.policy_repository import PolicyNotFoundError, PolicyPackNotFoundError


def _load_policy(session: Session, policy_id: str) -> Policy:
    orm = session.get(PolicyORM, policy_id)
    if orm is None:
        raise PolicyNotFoundError(f"policy {policy_id!r} not found")
    return orm_to_policy(orm, evaluate=resolve_evaluate_fn(policy_id))


class SqlAlchemyPolicyRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, policy: Policy) -> Policy:
        orm = policy_to_orm(policy)
        self._session.add(orm)
        self._session.commit()
        return _load_policy(self._session, policy.policy_id)

    def get(self, policy_id: str) -> Policy:
        return _load_policy(self._session, policy_id)

    def list(self, *, active_only: bool = False) -> list[Policy]:
        stmt = select(PolicyORM)
        if active_only:
            stmt = stmt.where(PolicyORM.active.is_(True))
        rows = self._session.execute(stmt.order_by(PolicyORM.policy_id)).scalars().all()
        return [orm_to_policy(r, evaluate=resolve_evaluate_fn(r.policy_id)) for r in rows]

    def set_active(self, policy_id: str, active: bool) -> Policy:
        orm = self._session.get(PolicyORM, policy_id)
        if orm is None:
            raise PolicyNotFoundError(f"policy {policy_id!r} not found")
        orm.active = active
        self._session.commit()
        return _load_policy(self._session, policy_id)


class SqlAlchemyPolicyPackRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, pack: PolicyPack) -> PolicyPack:
        orm = PolicyPackORM(
            pack_id=pack.pack_id,
            name=pack.name,
            version=pack.version,
            policy_ids=[p.policy_id for p in pack.policies],
            active=pack.active,
            description=pack.description,
        )
        self._session.add(orm)
        self._session.commit()
        return self._to_domain(orm)

    def get(self, pack_id: str) -> PolicyPack:
        orm = self._session.get(PolicyPackORM, pack_id)
        if orm is None:
            raise PolicyPackNotFoundError(f"policy pack {pack_id!r} not found")
        return self._to_domain(orm)

    def list(self, *, active_only: bool = False) -> list[PolicyPack]:
        stmt = select(PolicyPackORM)
        if active_only:
            stmt = stmt.where(PolicyPackORM.active.is_(True))
        rows = self._session.execute(stmt.order_by(PolicyPackORM.pack_id)).scalars().all()
        return [self._to_domain(r) for r in rows]

    def set_active(self, pack_id: str, active: bool) -> PolicyPack:
        orm = self._session.get(PolicyPackORM, pack_id)
        if orm is None:
            raise PolicyPackNotFoundError(f"policy pack {pack_id!r} not found")
        orm.active = active
        self._session.commit()
        return self._to_domain(orm)

    def _to_domain(self, orm: PolicyPackORM) -> PolicyPack:
        policies = tuple(_load_policy(self._session, pid) for pid in (orm.policy_ids or ()))
        return PolicyPack(
            pack_id=orm.pack_id,
            name=orm.name,
            version=orm.version,
            policies=policies,
            active=orm.active,
            description=orm.description,
        )
