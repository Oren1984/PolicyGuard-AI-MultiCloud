"""Strict request/response schemas for the "systems and inventory"
capability group (spec section 15). Every external-facing request schema
uses `extra="forbid"` (spec section 15/18)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from src.api.schemas.finding_schemas import DriftFindingResponse
from src.domain.enums.cloud_provider import CloudProvider
from src.domain.enums.environment import Environment
from src.domain.enums.resource_type import ResourceType

CriticalityLiteral = Literal["standard", "important", "critical"]

MAX_RESOURCES_PER_SNAPSHOT = 2000
MAX_TAGS = 100


class ManagedSystemCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    system_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.\-]+$")
    name: str = Field(min_length=1, max_length=256)
    cloud_provider: CloudProvider
    environment: Environment
    owner_actor_id: str | None = Field(default=None, max_length=256)
    criticality: CriticalityLiteral = "standard"
    description: str = Field(default="", max_length=2000)
    tags: dict[str, str] = Field(default_factory=dict, max_length=MAX_TAGS)


class ManagedSystemResponse(BaseModel):
    system_id: str
    name: str
    cloud_provider: str
    environment: str
    owner_actor_id: str
    criticality: str
    description: str
    tags: dict[str, str]
    created_at: datetime
    is_production: bool


class ManagedSystemListResponse(BaseModel):
    items: list[ManagedSystemResponse]
    total: int
    limit: int
    offset: int


class ResourceAttributesRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    publicly_accessible: bool = False
    iam_wildcard_action: bool = False
    iam_wildcard_resource: bool = False
    privilege_escalation_enabled: bool = False
    encryption_at_rest_enabled: bool = True
    audit_logging_enabled: bool = True
    monitoring_enabled: bool = True
    backup_enabled: bool = True
    secrets_in_plaintext_config: bool = False
    dev_grade_setting_in_production: bool = False
    within_approved_baseline: bool = True
    matches_architecture_baseline: bool = True
    owner_tag: str | None = Field(default=None, max_length=256)
    required_tags_present: bool = True
    runtime_version: str | None = Field(default=None, max_length=64)
    runtime_version_supported: bool = True
    modified_outside_maintenance_window: bool = False
    security_controls_removed_since_baseline: bool = False
    data_retention_days: int | None = Field(default=None, ge=0)
    data_retention_compliant: bool = True
    high_availability_configured: bool = True


class CloudResourceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resource_id: str = Field(min_length=1, max_length=256)
    resource_type: ResourceType
    region: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=256)
    criticality: CriticalityLiteral = "standard"
    tags: dict[str, str] = Field(default_factory=dict, max_length=MAX_TAGS)
    attributes: ResourceAttributesRequest = Field(default_factory=ResourceAttributesRequest)


class CloudResourceResponse(BaseModel):
    resource_id: str
    managed_system_id: str
    cloud_provider: str
    environment: str
    resource_type: str
    region: str
    name: str
    criticality: str
    tags: dict[str, str]
    attributes: ResourceAttributesRequest
    observed_at: datetime


class MaintenanceWindowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    starts_at: datetime | None = None
    ends_at: datetime | None = None


class ArchitectureBaselineRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allowed_regions: list[str] = Field(default_factory=list, max_length=100)
    required_tag_keys: list[str] = Field(default_factory=list, max_length=100)
    supported_runtime_versions: list[str] = Field(default_factory=list, max_length=100)
    required_retention_days: int | None = Field(default=None, ge=0)
    maintenance_window: MaintenanceWindowRequest = Field(default_factory=MaintenanceWindowRequest)


class DesiredStateSnapshotSubmitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    snapshot_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.\-]+$")
    source: str = Field(min_length=1, max_length=128)
    resources: list[CloudResourceRequest] = Field(default_factory=list, max_length=MAX_RESOURCES_PER_SNAPSHOT)
    baseline: ArchitectureBaselineRequest = Field(default_factory=ArchitectureBaselineRequest)


class ObservedStateSnapshotSubmitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    snapshot_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.\-]+$")
    source: str = Field(min_length=1, max_length=128)
    resources: list[CloudResourceRequest] = Field(default_factory=list, max_length=MAX_RESOURCES_PER_SNAPSHOT)


class SnapshotResponse(BaseModel):
    snapshot_id: str
    managed_system_id: str
    source: str
    resources: list[CloudResourceResponse]
    captured_at: datetime
    baseline: ArchitectureBaselineRequest | None = None
    correlation_id: str | None = None


class SnapshotComparisonResponse(BaseModel):
    managed_system_id: str
    desired: SnapshotResponse | None
    observed: SnapshotResponse | None


# Reuses finding_schemas.DriftFindingResponse (imported above) rather than
# declaring a second, structurally-identical class here -- an earlier draft
# duplicated the class in both modules, and because they were two distinct
# Pydantic model classes, FastAPI's strict response-model validation
# rejected the converter's real DriftFindingResponse instances (from
# src/api/routes/_converters.py) as "not an instance of" this module's
# separate class. Caught during Phase 3's own end-to-end smoke test.
class DriftDetectionResponse(BaseModel):
    managed_system_id: str
    findings: list[DriftFindingResponse]
