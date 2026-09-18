from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from src.domain.enums.cloud_provider import CloudProvider
from src.domain.enums.environment import Environment
from src.domain.enums.resource_criticality import ResourceCriticality
from src.domain.enums.resource_type import ResourceType


@dataclass(frozen=True, slots=True)
class ResourceAttributes:
    """Typed, normalized configuration facts about a resource.

    Drift and policy evaluation compare these typed fields directly rather
    than diffing raw provider payloads as text (spec section 8). Cloud
    adapters (a later phase) are responsible for normalizing provider-
    specific config into this shape; the domain layer never sees raw AWS or
    GCP API responses.
    """

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
    owner_tag: str | None = None
    required_tags_present: bool = True
    runtime_version: str | None = None
    runtime_version_supported: bool = True
    modified_outside_maintenance_window: bool = False
    security_controls_removed_since_baseline: bool = False
    data_retention_days: int | None = None
    data_retention_compliant: bool = True
    high_availability_configured: bool = True


@dataclass(frozen=True, slots=True)
class CloudResource:
    """A single normalized, provider-independent resource observation."""

    resource_id: str
    managed_system_id: str
    cloud_provider: CloudProvider
    environment: Environment
    resource_type: ResourceType
    region: str
    name: str
    criticality: ResourceCriticality = ResourceCriticality.STANDARD
    tags: dict[str, str] = field(default_factory=dict)
    attributes: ResourceAttributes = field(default_factory=ResourceAttributes)
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
