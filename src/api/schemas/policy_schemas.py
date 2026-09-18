"""Strict schemas for the "policies" capability group (spec section 15)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from src.domain.enums.policy_category import PolicyCategory

SeverityLiteral = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class PolicyCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.\-]+$")
    title: str = Field(min_length=1, max_length=256)
    description: str = Field(min_length=1, max_length=4000)
    category: PolicyCategory
    severity: SeverityLiteral
    required_evidence: list[str] = Field(default_factory=list, max_length=50)
    explanation_template: str = Field(min_length=1, max_length=2000)
    remediation_guidance: str = Field(min_length=1, max_length=2000)
    exception_eligible: bool = True
    version: int = Field(default=1, ge=1)
    active: bool = True


class PolicyResponse(BaseModel):
    policy_id: str
    title: str
    description: str
    category: str
    severity: str
    required_evidence: list[str]
    explanation_template: str
    remediation_guidance: str
    exception_eligible: bool
    version: int
    active: bool


class PolicyListResponse(BaseModel):
    items: list[PolicyResponse]


class PolicyPackCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pack_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.\-]+$")
    name: str = Field(min_length=1, max_length=256)
    version: int = Field(default=1, ge=1)
    policy_ids: list[str] = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    active: bool = True


class PolicyPackResponse(BaseModel):
    pack_id: str
    name: str
    version: int
    policies: list[PolicyResponse]
    active: bool
    description: str


class PolicyPackListResponse(BaseModel):
    items: list[PolicyPackResponse]


class EvaluatePolicyPackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    managed_system_id: str = Field(min_length=1, max_length=128)


class PolicyEvaluationResponse(BaseModel):
    evaluation_id: str
    managed_system_id: str
    policy_pack_id: str
    observed_snapshot_id: str
    finding_ids: list[str]
    resources_evaluated: int
    correlation_id: str
    evaluated_at: datetime
