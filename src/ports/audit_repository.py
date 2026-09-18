from __future__ import annotations

from typing import Protocol

from src.domain.entities.audit_event import AuditEvent
from src.domain.policies.audit_chain import ChainVerificationResult


class AuditPersistenceError(Exception):
    """Raised when an audit record cannot be durably persisted. Any action
    that cannot be audited must not be considered to have happened."""


class AuditEventRepository(Protocol):
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
        """Appends a new hash-chained record. Raises AuditPersistenceError on
        failure. Implementations must sanitize `payload` (redact secrets,
        tokens, credentials) before it is canonicalized/persisted."""
        ...

    def verify_chain(self) -> ChainVerificationResult: ...

    def list_recent(self, limit: int = 50) -> list[AuditEvent]: ...

    def list_for_resource(self, resource_type: str, resource_id: str) -> list[AuditEvent]: ...
