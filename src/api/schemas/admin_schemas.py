"""Strict schemas for administration (kill-switch, system status) -- spec
section 15."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SystemModeLiteral = Literal["normal", "paused", "emergency_stop"]


class KillSwitchChangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: SystemModeLiteral
    reason: str = Field(min_length=1, max_length=1000)


class KillSwitchStateResponse(BaseModel):
    mode: str
    changed_by: str | None
    reason: str | None
    changed_at: datetime


class SystemStatusResponse(BaseModel):
    status: str
    environment: str
    ai_provider: str
    kill_switch_mode: str
    audit_chain_valid: bool
    managed_system_count: int
    compliance_finding_counts_by_status: dict[str, int]
    drift_finding_counts_by_status: dict[str, int]
    exception_counts_by_status: dict[str, int]
