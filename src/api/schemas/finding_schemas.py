"""Strict schemas for the "findings and decisions" capability group (spec
section 15), including remediation and AI-advisory sub-resources."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

FindingKindLiteral = Literal["compliance", "drift"]


class ComplianceFindingResponse(BaseModel):
    kind: Literal["compliance"] = "compliance"
    finding_id: str
    managed_system_id: str
    resource_id: str
    policy_id: str
    category: str
    severity: str
    title: str
    explanation: str
    evidence: list[str]
    remediation_guidance: str
    exception_eligible: bool
    correlation_id: str
    status: str
    detected_at: datetime


class DriftFindingResponse(BaseModel):
    kind: Literal["drift"] = "drift"
    finding_id: str
    managed_system_id: str
    resource_id: str
    drift_type: str
    what_changed: str
    previous_value: str | None
    current_value: str | None
    expected_value: str | None
    why_it_matters: str
    severity: str
    evidence: list[str]
    remediation: str
    exception_eligible: bool
    correlation_id: str
    policy_id: str | None
    status: str
    detected_at: datetime


FindingResponse = ComplianceFindingResponse | DriftFindingResponse


class FindingListResponse(BaseModel):
    items: list[FindingResponse]
    total: int
    limit: int
    offset: int


class FindingStatusUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_status: Literal["open", "acknowledged", "exception_granted", "remediated", "closed", "reopened"]


class GovernanceDecisionResponse(BaseModel):
    decision_id: str
    managed_system_id: str
    finding_ids: list[str]
    decision: str
    reasons: list[str]
    policy_ids: list[str]
    correlation_id: str
    decided_at: datetime


class RemediationPlanCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    description: str = Field(min_length=1, max_length=4000)
    assigned_to: str | None = Field(default=None, max_length=256)
    due_by: datetime | None = None


class RemediationPlanResponse(BaseModel):
    plan_id: str
    finding_id: str
    managed_system_id: str
    description: str
    status: str
    assigned_to: str | None
    correlation_id: str
    verification_evidence: list[str]
    due_by: datetime | None
    created_at: datetime
    updated_at: datetime


RemediationStatusLiteral = Literal[
    "not_started", "planned", "in_progress", "completed", "verified", "failed", "cancelled"
]


class RemediationStatusUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_status: RemediationStatusLiteral
    verification_evidence: list[str] = Field(default_factory=list, max_length=50)


class FindingRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    finding_id: str = Field(min_length=1, max_length=128)
    kind: FindingKindLiteral = "compliance"


class AISummaryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    findings: list[FindingRef] = Field(min_length=1, max_length=100)


class GateResultResponse(BaseModel):
    gate: str
    status: str
    reason: str
    details: dict


class AIAdvisoryResponse(BaseModel):
    provider_name: str
    kind: str
    content: str
    referenced_evidence: list[str]
    confidence: float
    gate_results: list[GateResultResponse]
    fell_back: bool
