"""Shared, reusable test data builders: domain entities for unit/application
tests, and API request-payload dicts for API/security/e2e/demo-style tests.
Deliberately synthetic and deterministic -- no production data anywhere
(global CLAUDE.md rule: no production data in tests)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from src.domain.entities.actor import Actor
from src.domain.entities.cloud_resource import CloudResource, ResourceAttributes
from src.domain.entities.managed_system import ManagedSystem
from src.domain.entities.state_snapshot import (
    ArchitectureBaseline,
    DesiredStateSnapshot,
    ObservedStateSnapshot,
)
from src.domain.enums.actor_role import ActorRole
from src.domain.enums.cloud_provider import CloudProvider
from src.domain.enums.environment import Environment
from src.domain.enums.resource_criticality import ResourceCriticality
from src.domain.enums.resource_type import ResourceType
from src.domain.policy_engine.definitions import build_default_policy_pack

# ---------------------------------------------------------------------------
# Actors / headers
# ---------------------------------------------------------------------------


def make_actor(actor_id: str, role: ActorRole) -> Actor:
    return Actor(actor_id=actor_id, display_name=actor_id, role=role)


def actor_headers(actor_id: str, role: ActorRole | str) -> dict[str, str]:
    role_value = role.value if isinstance(role, ActorRole) else role
    return {"X-PolicyGuard-Actor": actor_id, "X-PolicyGuard-Role": role_value}


SYSTEM_OWNER = ActorRole.SYSTEM_OWNER
SECURITY_REVIEWER = ActorRole.SECURITY_REVIEWER
COMPLIANCE_APPROVER = ActorRole.COMPLIANCE_APPROVER
PLATFORM_ADMIN = ActorRole.PLATFORM_ADMIN
AUDITOR = ActorRole.AUDITOR


def unique_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Domain entities (for unit/application-layer tests, no HTTP involved)
# ---------------------------------------------------------------------------


def build_managed_system(
    system_id: str | None = None,
    *,
    cloud_provider: CloudProvider = CloudProvider.AWS,
    environment: Environment = Environment.PRODUCTION,
    criticality: ResourceCriticality = ResourceCriticality.CRITICAL,
    owner_actor_id: str = "owner.one",
) -> ManagedSystem:
    return ManagedSystem(
        system_id=system_id or unique_id("sys"),
        name="Test Managed System",
        cloud_provider=cloud_provider,
        environment=environment,
        owner_actor_id=owner_actor_id,
        criticality=criticality,
    )


def build_resource(
    resource_id: str,
    managed_system_id: str,
    *,
    cloud_provider: CloudProvider = CloudProvider.AWS,
    environment: Environment = Environment.PRODUCTION,
    resource_type: ResourceType = ResourceType.OBJECT_STORAGE_BUCKET,
    criticality: ResourceCriticality = ResourceCriticality.STANDARD,
    region: str = "us-east-1",
    attributes: ResourceAttributes | None = None,
) -> CloudResource:
    return CloudResource(
        resource_id=resource_id,
        managed_system_id=managed_system_id,
        cloud_provider=cloud_provider,
        environment=environment,
        resource_type=resource_type,
        region=region,
        name=resource_id,
        criticality=criticality,
        attributes=attributes or ResourceAttributes(),
    )


def build_desired_snapshot(
    managed_system_id: str,
    resources: tuple[CloudResource, ...],
    *,
    baseline: ArchitectureBaseline | None = None,
) -> DesiredStateSnapshot:
    return DesiredStateSnapshot(
        snapshot_id=unique_id("desired"),
        managed_system_id=managed_system_id,
        source="test-baseline",
        resources=resources,
        baseline=baseline or ArchitectureBaseline(allowed_regions=("us-east-1",)),
        submitted_by="test-harness",
    )


def build_observed_snapshot(
    managed_system_id: str, resources: tuple[CloudResource, ...], *, correlation_id: str | None = None
) -> ObservedStateSnapshot:
    return ObservedStateSnapshot(
        snapshot_id=unique_id("observed"),
        managed_system_id=managed_system_id,
        source="test-inventory",
        resources=resources,
        correlation_id=correlation_id or unique_id("corr"),
    )


# ---------------------------------------------------------------------------
# API payload builders (for api/security/e2e/demo-style tests over HTTP)
# ---------------------------------------------------------------------------


def managed_system_payload(
    system_id: str | None = None,
    *,
    cloud_provider: str = "aws",
    environment: str = "production",
    criticality: str = "critical",
) -> dict:
    return {
        "system_id": system_id or unique_id("sys"),
        "name": "Test Managed System",
        "cloud_provider": cloud_provider,
        "environment": environment,
        "criticality": criticality,
        "description": "synthetic test system",
        "tags": {"team": "platform"},
    }


def resource_attributes_payload(**overrides) -> dict:
    base = {
        "publicly_accessible": False,
        "iam_wildcard_action": False,
        "iam_wildcard_resource": False,
        "privilege_escalation_enabled": False,
        "encryption_at_rest_enabled": True,
        "audit_logging_enabled": True,
        "monitoring_enabled": True,
        "backup_enabled": True,
        "secrets_in_plaintext_config": False,
        "dev_grade_setting_in_production": False,
        "within_approved_baseline": True,
        "matches_architecture_baseline": True,
        "owner_tag": "platform-team",
        "required_tags_present": True,
        "runtime_version": "python3.12",
        "runtime_version_supported": True,
        "modified_outside_maintenance_window": False,
        "security_controls_removed_since_baseline": False,
        "data_retention_days": 90,
        "data_retention_compliant": True,
        "high_availability_configured": True,
    }
    base.update(overrides)
    return base


def resource_payload(
    resource_id: str,
    *,
    resource_type: str = "object_storage_bucket",
    region: str = "us-east-1",
    criticality: str = "standard",
    attributes: dict | None = None,
) -> dict:
    return {
        "resource_id": resource_id,
        "resource_type": resource_type,
        "region": region,
        "name": resource_id,
        "criticality": criticality,
        "tags": {"owner": "platform-team"},
        "attributes": attributes if attributes is not None else resource_attributes_payload(),
    }


def desired_state_payload(resources: list[dict], *, allowed_regions: list[str] | None = None) -> dict:
    return {
        "snapshot_id": unique_id("desired"),
        "source": "terraform-plan",
        "resources": resources,
        "baseline": {
            "allowed_regions": allowed_regions if allowed_regions is not None else ["us-east-1"],
            "required_tag_keys": ["owner"],
            "supported_runtime_versions": ["python3.12"],
            "required_retention_days": 30,
            "maintenance_window": {},
        },
    }


def observed_state_payload(resources: list[dict]) -> dict:
    return {"snapshot_id": unique_id("observed"), "source": "mock-inventory", "resources": resources}


def exception_request_payload(
    *,
    policy_id: str,
    resource_id: str,
    finding_id: str,
    managed_system_id: str,
    requested_by: str | None = None,
    expires_in_days: int = 30,
    evidence: list[str] | None = None,
) -> dict:
    payload = {
        "policy_id": policy_id,
        "resource_id": resource_id,
        "finding_id": finding_id,
        "managed_system_id": managed_system_id,
        "business_justification": "temporary compensating control in place while remediation is scheduled",
        "risk_statement": "residual risk accepted for a bounded period",
        "compensating_controls": ["additional monitoring alert configured"],
        "requested_expiration": (datetime.now(UTC) + timedelta(days=expires_in_days)).isoformat(),
        "evidence": evidence if evidence is not None else ["ticket:JIRA-123"],
    }
    if requested_by is not None:
        payload["requested_by"] = requested_by
    return payload


# ---------------------------------------------------------------------------
# Default policy pack helper (registers all 20 spec policies via the real
# API, then bundles them into one active pack) -- shared by API/e2e/security/
# demo-style tests that need a real, evaluable policy pack.
# ---------------------------------------------------------------------------


def policy_create_payloads() -> list[dict]:
    pack = build_default_policy_pack()
    return [
        {
            "policy_id": p.policy_id,
            "title": p.title,
            "description": p.description,
            "category": p.category.value,
            "severity": p.severity.label,
            "required_evidence": list(p.required_evidence),
            "explanation_template": p.explanation_template,
            "remediation_guidance": p.remediation_guidance,
            "exception_eligible": p.exception_eligible,
            "version": p.version,
            "active": p.active,
        }
        for p in pack.policies
    ]


def register_default_policy_pack(client, *, pack_id: str | None = None) -> str:
    """Creates every default policy plus one pack bundling them, via the
    real HTTP API, as an authorized platform_admin actor. Returns the new
    pack_id. Tests call this once per managed system under test."""
    admin_headers = actor_headers("policy.admin", PLATFORM_ADMIN)
    policy_ids: list[str] = []
    for payload in policy_create_payloads():
        resp = client.post("/api/v1/policies", json=payload, headers=admin_headers)
        assert resp.status_code == 201, resp.text
        policy_ids.append(payload["policy_id"])

    pack_id = pack_id or unique_id("pack")
    resp = client.post(
        "/api/v1/policies/packs",
        json={"pack_id": pack_id, "name": "Test Default Pack", "policy_ids": policy_ids, "active": True},
        headers=admin_headers,
    )
    assert resp.status_code == 201, resp.text
    return pack_id
