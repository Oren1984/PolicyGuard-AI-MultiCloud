"""Deterministic, offline synthetic GCP inventory provider (spec section 6).

No network access and no GCP credentials are used or required. See
mock_aws_provider.py for the shared determinism contract. Covers all eight
GCP resource categories from spec section 6 (IAM bindings/service accounts,
VPC firewall rules, Cloud Storage buckets, Cloud SQL, Cloud Run, Secret
Manager references, Cloud Audit Logs, Cloud Monitoring) with a deliberate
mix of compliant and violating resources.
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


class MockGCPInventoryProvider:
    """Deterministic offline mock implementing CloudInventoryProvider for GCP."""

    provider = CloudProvider.GCP
    name = "mock-gcp-inventory-v1"

    def fetch_observed_snapshot(
        self, *, managed_system_id: str, environment: Environment, correlation_id: str
    ) -> ObservedStateSnapshot:
        if not managed_system_id:
            raise CloudInventoryProviderError("managed_system_id is required to fetch GCP inventory")

        resources = tuple(self._build_resources(managed_system_id, environment))
        return ObservedStateSnapshot(
            snapshot_id=f"obs-gcp-{uuid.uuid4().hex}",
            managed_system_id=managed_system_id,
            source=self.name,
            resources=resources,
            captured_at=datetime.now(UTC),
            correlation_id=correlation_id,
        )

    @staticmethod
    def _build_resources(sid: str, environment: Environment) -> list[CloudResource]:
        return [
            # IAM binding -- compliant, scoped service account.
            CloudResource(
                resource_id=f"{sid}-gcp-iam-binding-app",
                managed_system_id=sid,
                cloud_provider=CloudProvider.GCP,
                environment=environment,
                resource_type=ResourceType.IAM_BINDING,
                region="us-central1",
                name="app-runtime-sa-binding",
                criticality=ResourceCriticality.IMPORTANT,
                tags={"owner": "platform-team", "app": sid},
                attributes=ResourceAttributes(owner_tag="platform-team"),
            ),
            # IAM binding -- violates POL-IAM-002 / POL-PRI-015 (broad role grant).
            CloudResource(
                resource_id=f"{sid}-gcp-iam-binding-legacy",
                managed_system_id=sid,
                cloud_provider=CloudProvider.GCP,
                environment=environment,
                resource_type=ResourceType.IAM_BINDING,
                region="us-central1",
                name="legacy-owner-binding",
                criticality=ResourceCriticality.CRITICAL,
                tags={"app": sid},
                attributes=ResourceAttributes(
                    iam_wildcard_action=True,
                    iam_wildcard_resource=True,
                    privilege_escalation_enabled=True,
                    owner_tag=None,
                ),
            ),
            # Firewall rule -- violates POL-NET-001 (open to 0.0.0.0/0).
            CloudResource(
                resource_id=f"{sid}-gcp-firewall-web",
                managed_system_id=sid,
                cloud_provider=CloudProvider.GCP,
                environment=environment,
                resource_type=ResourceType.FIREWALL_RULE,
                region="us-central1",
                name="allow-web-ingress",
                criticality=ResourceCriticality.STANDARD,
                tags={"owner": "platform-team"},
                attributes=ResourceAttributes(publicly_accessible=True, owner_tag="platform-team"),
            ),
            # Cloud Storage bucket -- compliant.
            CloudResource(
                resource_id=f"{sid}-gcp-gcs-artifacts",
                managed_system_id=sid,
                cloud_provider=CloudProvider.GCP,
                environment=environment,
                resource_type=ResourceType.OBJECT_STORAGE_BUCKET,
                region="us-central1",
                name="app-artifacts-bucket",
                criticality=ResourceCriticality.STANDARD,
                tags={"owner": "platform-team", "data-classification": "internal"},
                attributes=ResourceAttributes(
                    encryption_at_rest_enabled=True, backup_enabled=True, owner_tag="platform-team"
                ),
            ),
            # Cloud Storage bucket -- violates POL-ENC-003 / POL-TAG-012 /
            # POL-OWN-011, and is in an unauthorized region for this demo baseline.
            CloudResource(
                resource_id=f"{sid}-gcp-gcs-logexport",
                managed_system_id=sid,
                cloud_provider=CloudProvider.GCP,
                environment=environment,
                resource_type=ResourceType.OBJECT_STORAGE_BUCKET,
                region="asia-east1",
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
            # Cloud SQL instance -- compliant, critical, HA.
            CloudResource(
                resource_id=f"{sid}-gcp-cloudsql-primary",
                managed_system_id=sid,
                cloud_provider=CloudProvider.GCP,
                environment=environment,
                resource_type=ResourceType.RELATIONAL_DATABASE,
                region="us-central1",
                name="primary-cloudsql-postgres",
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
            # Cloud Run service -- compliant.
            CloudResource(
                resource_id=f"{sid}-gcp-cloudrun-api",
                managed_system_id=sid,
                cloud_provider=CloudProvider.GCP,
                environment=environment,
                resource_type=ResourceType.CONTAINER_SERVICE,
                region="us-central1",
                name="api-service",
                criticality=ResourceCriticality.IMPORTANT,
                tags={"owner": "platform-team"},
                attributes=ResourceAttributes(
                    runtime_version="python3.12",
                    runtime_version_supported=True,
                    owner_tag="platform-team",
                ),
            ),
            # Secret Manager reference -- compliant.
            CloudResource(
                resource_id=f"{sid}-gcp-secret-db",
                managed_system_id=sid,
                cloud_provider=CloudProvider.GCP,
                environment=environment,
                resource_type=ResourceType.SECRETS_REFERENCE,
                region="us-central1",
                name="db-credentials-ref",
                criticality=ResourceCriticality.CRITICAL,
                tags={"owner": "data-team"},
                attributes=ResourceAttributes(secrets_in_plaintext_config=False, owner_tag="data-team"),
            ),
            # Cloud Audit Logs config -- violates POL-LOG-004.
            CloudResource(
                resource_id=f"{sid}-gcp-auditlogs",
                managed_system_id=sid,
                cloud_provider=CloudProvider.GCP,
                environment=environment,
                resource_type=ResourceType.AUDIT_LOG_CONFIG,
                region="us-central1",
                name="org-cloud-audit-logs",
                criticality=ResourceCriticality.IMPORTANT,
                tags={"owner": "security-team"},
                attributes=ResourceAttributes(audit_logging_enabled=False, owner_tag="security-team"),
            ),
            # Cloud Monitoring config -- violates POL-MON-005.
            CloudResource(
                resource_id=f"{sid}-gcp-monitoring",
                managed_system_id=sid,
                cloud_provider=CloudProvider.GCP,
                environment=environment,
                resource_type=ResourceType.MONITORING_CONFIG,
                region="us-central1",
                name="app-cloud-monitoring-alerts",
                criticality=ResourceCriticality.STANDARD,
                tags={"owner": "platform-team"},
                attributes=ResourceAttributes(monitoring_enabled=False, owner_tag="platform-team"),
            ),
        ]
