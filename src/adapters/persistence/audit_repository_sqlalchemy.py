from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.adapters.persistence.models import AuditEventORM
from src.adapters.security.redaction import redact_mapping
from src.domain.entities.audit_event import AuditEvent
from src.domain.policies.audit_chain import (
    GENESIS_HASH,
    ChainLink,
    ChainVerificationResult,
    canonicalize_payload,
    compute_hash,
    verify_chain,
)
from src.ports.audit_repository import AuditPersistenceError


class SqlAlchemyAuditEventRepository:
    """Hash-chained, append-only audit trail (spec section 14).

    `append` locks the latest row (SELECT ... FOR UPDATE) before computing
    the next sequence/hash so concurrent writers cannot race and produce two
    records claiming the same previous_hash. The payload is redacted
    (secrets/tokens/credentials/connection strings -- see
    src/adapters/security/redaction.py) before it is canonicalized, hashed,
    or stored -- never after, so no unredacted secret is ever part of the
    hashed/persisted record.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def append(
        self,
        *,
        actor: str,
        actor_role: str,
        action: str,
        resource_type: str,
        resource_id: str,
        correlation_id: str,
        payload: dict,
        outcome: str = "SUCCESS",
    ) -> AuditEvent:
        sanitized_payload = redact_mapping(payload)
        try:
            latest = self._session.execute(
                select(AuditEventORM).order_by(AuditEventORM.sequence.desc()).limit(1).with_for_update()
            ).scalar_one_or_none()

            previous_hash = latest.current_hash if latest else GENESIS_HASH
            next_sequence = (latest.sequence + 1) if latest else 1
            timestamp = datetime.now(UTC)

            canonical = canonicalize_payload(
                {
                    "sequence": next_sequence,
                    "timestamp": timestamp.isoformat(),
                    "actor": actor,
                    "actor_role": actor_role,
                    "action": action,
                    "resource_type": resource_type,
                    "resource_id": resource_id,
                    "correlation_id": correlation_id,
                    "payload": sanitized_payload,
                    "outcome": outcome,
                }
            )
            current_hash = compute_hash(previous_hash, canonical)

            orm = AuditEventORM(
                event_id=uuid.uuid4().hex,
                sequence=next_sequence,
                previous_hash=previous_hash,
                current_hash=current_hash,
                actor=actor,
                actor_role=actor_role,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                correlation_id=correlation_id,
                payload=sanitized_payload,
                outcome=outcome,
                timestamp=timestamp,
                canonical_payload=canonical,
            )
            self._session.add(orm)
            self._session.commit()
        except Exception as exc:
            self._session.rollback()
            raise AuditPersistenceError(f"failed to append audit event: {exc}") from exc

        return self._to_entity(orm)

    def verify_chain(self) -> ChainVerificationResult:
        rows = (
            self._session.execute(select(AuditEventORM).order_by(AuditEventORM.sequence.asc()))
            .scalars()
            .all()
        )
        links = [
            ChainLink(
                sequence=r.sequence,
                previous_hash=r.previous_hash,
                canonical_payload=r.canonical_payload,
                current_hash=r.current_hash,
            )
            for r in rows
        ]
        return verify_chain(links)

    def list_recent(self, limit: int = 50) -> list[AuditEvent]:
        rows = (
            self._session.execute(select(AuditEventORM).order_by(AuditEventORM.sequence.desc()).limit(limit))
            .scalars()
            .all()
        )
        return [self._to_entity(r) for r in rows]

    def list_for_resource(self, resource_type: str, resource_id: str) -> list[AuditEvent]:
        rows = (
            self._session.execute(
                select(AuditEventORM)
                .where(
                    AuditEventORM.resource_type == resource_type,
                    AuditEventORM.resource_id == resource_id,
                )
                .order_by(AuditEventORM.sequence.asc())
            )
            .scalars()
            .all()
        )
        return [self._to_entity(r) for r in rows]

    @staticmethod
    def _to_entity(orm: AuditEventORM) -> AuditEvent:
        return AuditEvent(
            event_id=orm.event_id,
            sequence=orm.sequence,
            previous_hash=orm.previous_hash,
            current_hash=orm.current_hash,
            actor=orm.actor,
            actor_role=orm.actor_role,
            action=orm.action,
            resource_type=orm.resource_type,
            resource_id=orm.resource_id,
            correlation_id=orm.correlation_id,
            payload=dict(orm.payload or {}),
            outcome=orm.outcome,
            timestamp=orm.timestamp,
        )
