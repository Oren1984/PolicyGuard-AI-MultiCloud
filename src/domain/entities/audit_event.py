from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One entry in the hash-chained, append-only audit trail (spec section
    14). `current_hash` = SHA-256(previous_hash || canonical_payload) — see
    src/domain/policies/audit_chain.py for the canonicalization/hashing
    rules, which must be applied identically at write and verify time.

    Tamper-evident, not immutable: this in-database chain can *detect*
    retroactive mutation, but does not by itself prevent someone with direct
    database access from rewriting the whole chain consistently.
    """

    event_id: str
    sequence: int
    previous_hash: str
    current_hash: str
    actor: str
    actor_role: str
    action: str
    resource_type: str
    resource_id: str
    correlation_id: str
    payload: dict = field(default_factory=dict)  # sanitized before storage
    outcome: str = "SUCCESS"  # "SUCCESS" | "FAILURE" | "DENIED"
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
