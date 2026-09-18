from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from src.domain.entities.actor import Actor
from src.domain.entities.audit_event import AuditEvent
from src.domain.policies.audit_chain import ChainVerificationResult
from src.ports.audit_repository import AuditEventRepository


class RecordAuditEventUseCase:
    """Thin, explicit entry point for recording an audit event (spec
    section 14). Other use cases call their injected AuditEventRepository
    directly for their own actions; this use case exists for callers (e.g.
    a future API middleware) that need to record an event without owning
    a specific domain use case of their own."""

    def __init__(self, audit_repo: AuditEventRepository) -> None:
        self._audit_repo = audit_repo

    def execute(
        self,
        *,
        actor: Actor,
        action: str,
        resource_type: str,
        resource_id: str,
        correlation_id: str,
        payload: dict,
        outcome: str = "SUCCESS",
    ) -> AuditEvent:
        return self._audit_repo.append(
            actor=actor.actor_id,
            actor_role=actor.role.value,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            correlation_id=correlation_id,
            payload=payload,
            outcome=outcome,
        )


@dataclass(frozen=True, slots=True)
class AuditChainVerificationReport:
    """Wraps the pure ChainVerificationResult with the verification
    timestamp the spec's report contract also requires — a wall-clock read
    is an orchestration concern, not something the pure domain policy
    (src/domain/policies/audit_chain.py) should perform itself."""

    result: ChainVerificationResult
    verified_at: datetime


class VerifyAuditChainUseCase:
    """Spec section 14: validates the full hash chain and reports whether
    it is valid, the first broken event (if any), how many events were
    verified, and when verification ran."""

    def __init__(self, audit_repo: AuditEventRepository, clock: Callable[[], datetime]) -> None:
        self._audit_repo = audit_repo
        self._clock = clock

    def execute(self) -> AuditChainVerificationReport:
        result = self._audit_repo.verify_chain()
        return AuditChainVerificationReport(result=result, verified_at=self._clock())
