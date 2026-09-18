"""Strict schemas for the policy-exception workflow (spec section 12)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class PolicyExceptionRequestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(min_length=1, max_length=64)
    resource_id: str = Field(min_length=1, max_length=256)
    finding_id: str = Field(min_length=1, max_length=128)
    managed_system_id: str = Field(min_length=1, max_length=128)
    business_justification: str = Field(min_length=1, max_length=4000)
    risk_statement: str = Field(min_length=1, max_length=4000)
    compensating_controls: list[str] = Field(default_factory=list, max_length=50)
    requested_expiration: datetime
    evidence: list[str] = Field(default_factory=list, max_length=50)
    # What the client *claims* the requester is. Deliberately compared
    # against the authenticated actor (never trusted on its own) by
    # ExceptionAuthorizationService.authorize_request -- a mismatch is a
    # spoofing attempt and is rejected with 403 (spec section 12, demo
    # scenario 13).
    requested_by: str | None = Field(default=None, max_length=256)


class ExceptionApprovalResponse(BaseModel):
    approval_id: str
    exception_id: str
    decision: str
    rationale: str
    decided_by: str
    decided_role: str
    decided_at: datetime


class PolicyExceptionResponse(BaseModel):
    exception_id: str
    policy_id: str
    resource_id: str
    finding_id: str
    managed_system_id: str
    business_justification: str
    risk_statement: str
    compensating_controls: list[str]
    requested_expiration: datetime
    requested_by: str
    evidence: list[str]
    correlation_id: str
    status: str
    approvals: list[ExceptionApprovalResponse]
    created_at: datetime
    activated_at: datetime | None
    expires_at: datetime | None
    revoked_at: datetime | None
    revoked_by: str | None
    revoked_reason: str | None


class PolicyExceptionListResponse(BaseModel):
    items: list[PolicyExceptionResponse]
    total: int
    limit: int
    offset: int


class ExceptionDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approve: bool
    rationale: str = Field(min_length=1, max_length=4000)


class ExceptionRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=1, max_length=4000)


class ExceptionExpirySweepResponse(BaseModel):
    expired: list[PolicyExceptionResponse]
