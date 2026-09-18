"""Strict schemas for audit query/verification endpoints (spec section 14)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class AuditEventResponse(BaseModel):
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
    payload: dict
    outcome: str
    timestamp: datetime


class AuditEventListResponse(BaseModel):
    items: list[AuditEventResponse]


class AuditVerificationResponse(BaseModel):
    is_valid: bool
    total_records: int
    first_invalid_sequence: int | None
    reason: str | None
    verified_at: datetime
