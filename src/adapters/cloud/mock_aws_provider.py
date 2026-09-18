"""Deterministic, offline synthetic AWS inventory provider (spec section 6).

No network access and no AWS credentials are used or required. Resource
*configuration* is a fixed function of `managed_system_id` and
`environment` -- the same inputs always produce the same normalized
resources and compliance mix -- while `snapshot_id`/`captured_at` vary per
call the way a real inventory snapshot would. Covers all eight AWS resource
categories from spec section 6 (IAM roles/policies, security groups, S3
buckets, RDS, ECS services, Secrets Manager references, CloudTrail,
CloudWatch) with a deliberate mix of compliant and violating resources so
demo scenarios (spec section 19) have real, reproducible data to work with.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from src.domain.entities.cloud_resource import CloudResource, ResourceAttributes
from src.domain.entities.state_snapshot import ObservedStateSnapshot
from src.domain.enums.cloud_provider import CloudProvider
from src.domain.enums.environment import Environment
from src.domain.enums.resource_criticality import ResourceCriticality
from src.domain.enums.resource_type import ResourceType
from src.ports.cloud_inventory_provider import CloudInventoryProviderError


class MockAWSInventoryProvider:
    """Deterministic offline mock implementing CloudInventoryProvider for AWS."""

    provider = CloudProvider.AWS
    name = "mock-aws-inventory-v1"

    def fetch_observed_snapshot(
        self, *, managed_system_id: str, environment: Environment, correlation_id: str
    ) -> ObservedStateSnapshot:
        if not managed_system_id:
            raise CloudInventoryProviderError("managed_system_id is required to fetch AWS inventory")

        resources = tuple(self._build_resources(managed_system_id, environment))
        return ObservedStateSnapshot(
            snapshot_id=f"obs-aws-{uuid.uuid4().hex}",
            managed_system_id=managed_system_id,
            source=self.name,
            resources=resources,
            captured_at=datetime.now(UTC),
            correlation_id=correlation_id,
        )

    @staticmethod
    def _build_resources(sid: str, environment: Environment) -> list[CloudResource]:
        return [
            # IAM role -- compliant: scoped, owned.
            CloudResource(
                resource_id=f"{sid}-aws-iam-role-app",
                managed_system_id=sid,
                cloud_provider=CloudProvider.AWS,
                environment=environment,
                resource_type=ResourceType.IAM_ROLE,
                region="us-east-1",
                name="app-execution-role",
                criticality=ResourceCriticality.IMPORTANT,
                tags={"owner": "platform-team", "app": sid},
                attributes=ResourceAttributes(owner_tag="platform-team"),
            ),
            # IAM role -- violates POL-IAM-002 / POL-PRI-015 / POL-OWN-011.
            CloudResource(
                resource_id=f"{sid}-aws-iam-role-legacy",
                managed_system_id=sid,
                cloud_provider=CloudProvider.AWS,
                environment=environment,
                resource_type=ResourceType.IAM_ROLE,
                region="us-east-1",
                name="legacy-admin-role",
                criticality=ResourceCriticality.CRITICAL,
                tags={"app": sid},
                attributes=ResourceAttributes(
                    iam_wildcard_action=True,
                    iam_wildcard_resource=True,
                    privilege_escalation_enabled=True,
                    owner_tag=None,
                ),
            ),
            # Security group -- violates POL-NET-001 (publicly accessible).
            CloudResource(
                resource_id=f"{sid}-aws-sg-web",
                managed_system_id=sid,
                cloud_provider=CloudProvider.AWS,
                environment=environment,
                resource_type=ResourceType.SECURITY_GROUP,
                region="us-east-1",
                name="web-tier-sg",
                criticality=ResourceCriticality.STANDARD,
                tags={"owner": "platform-team"},
                attributes=ResourceAttributes(publicly_accessible=True, owner_tag="platform-team"),
            ),
            # S3 bucket -- compliant.
            CloudResource(
                resource_id=f"{sid}-aws-s3-artifacts",
                managed_system_id=sid,
                cloud_provider=CloudProvider.AWS,
                environment=environment,
                resource_type=ResourceType.OBJECT_STORAGE_BUCKET,
                region="us-east-1",
                name="app-artifacts-bucket",
                criticality=ResourceCriticality.STANDARD,
                tags={"owner": "platform-team", "data-classification": "internal"},
                attributes=ResourceAttributes(
                    encryption_at_rest_enabled=True, backup_enabled=True, owner_tag="platform-team"
                ),
            ),
            # S3 bucket -- violates POL-ENC-003 / POL-BAK-006 / POL-TAG-012 /
            # POL-OWN-011, and is deployed outside a typical region allow-list.
            CloudResource(
                resource_id=f"{sid}-aws-s3-logexport",
                managed_system_id=sid,
                cloud_provider=CloudProvider.AWS,
                environment=environment,
                resource_type=ResourceType.OBJECT_STORAGE_BUCKET,
                region="ap-southeast-2",
                name="log-export-bucket",
                criticality=ResourceCriticality.STANDARD,
                tags={},
                attributes=ResourceAttributes(
                    encryption_at_rest_enabled=False,
                    backup_enabled=False,
                    owner_tag=None,
                    required_tags_present=False,
                ),
            ),
            # RDS instance -- compliant, critical, HA.
            CloudResource(
                resource_id=f"{sid}-aws-rds-primary",
                managed_system_id=sid,
                cloud_provider=CloudProvider.AWS,
                environment=environment,
                resource_type=ResourceType.RELATIONAL_DATABASE,
                region="us-east-1",
                name="primary-postgres",
                criticality=ResourceCriticality.CRITICAL,
                tags={"owner": "data-team"},
                attributes=ResourceAttributes(
                    encryption_at_rest_enabled=True,
                    backup_enabled=True,
                    high_availability_configured=True,
                    owner_tag="data-team",
                    data_retention_days=90,
                ),
            ),
            # ECS service -- compliant runtime, dev-grade settings only if not prod.
            CloudResource(
                resource_id=f"{sid}-aws-ecs-api",
                managed_system_id=sid,
                cloud_provider=CloudProvider.AWS,
                environment=environment,
                resource_type=ResourceType.CONTAINER_SERVICE,
                region="us-east-1",
                name="api-service",
                criticality=ResourceCriticality.IMPORTANT,
                tags={"owner": "platform-team"},
                attributes=ResourceAttributes(
                    runtime_version="python3.12",
                    runtime_version_supported=True,
                    owner_tag="platform-team",
                ),
            ),
            # Secrets Manager reference -- compliant (no plaintext secrets).
            CloudResource(
                resource_id=f"{sid}-aws-secret-db",
                managed_system_id=sid,
                cloud_provider=CloudProvider.AWS,
                environment=environment,
                resource_type=ResourceType.SECRETS_REFERENCE,
                region="us-east-1",
                name="db-credentials-ref",
                criticality=ResourceCriticality.CRITICAL,
                tags={"owner": "data-team"},
                attributes=ResourceAttributes(secrets_in_plaintext_config=False, owner_tag="data-team"),
            ),
            # CloudTrail config -- violates POL-LOG-004 (audit logging disabled).
            CloudResource(
                resource_id=f"{sid}-aws-cloudtrail",
                managed_system_id=sid,
                cloud_provider=CloudProvider.AWS,
                environment=environment,
                resource_type=ResourceType.AUDIT_LOG_CONFIG,
                region="us-east-1",
                name="org-cloudtrail",
                criticality=ResourceCriticality.IMPORTANT,
                tags={"owner": "security-team"},
                attributes=ResourceAttributes(audit_logging_enabled=False, owner_tag="security-team"),
            ),
            # CloudWatch config -- violates POL-MON-005 (monitoring disabled).
            CloudResource(
                resource_id=f"{sid}-aws-cloudwatch",
                managed_system_id=sid,
                cloud_provider=CloudProvider.AWS,
                environment=environment,
                resource_type=ResourceType.MONITORING_CONFIG,
                region="us-east-1",
                name="app-cloudwatch-alarms",
                criticality=ResourceCriticality.STANDARD,
                tags={"owner": "platform-team"},
                attributes=ResourceAttributes(monitoring_enabled=False, owner_tag="platform-team"),
            ),
        ]
