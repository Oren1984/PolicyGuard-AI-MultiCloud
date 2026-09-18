"""Shared domain-entity <-> API-schema conversion helpers, used across
multiple route modules. Kept in one place so every route serializes the
same entity the same way (mirrors the ChangeGuard sibling project's
`_converters.py` convention)."""

from __future__ import annotations

from src.api.schemas.audit_schemas import AuditEventResponse
from src.api.schemas.exception_schemas import ExceptionApprovalResponse, PolicyExceptionResponse
from src.api.schemas.finding_schemas import ComplianceFindingResponse, DriftFindingResponse
from src.api.schemas.policy_schemas import PolicyResponse
from src.api.schemas.system_schemas import (
    ArchitectureBaselineRequest,
    CloudResourceRequest,
    CloudResourceResponse,
    MaintenanceWindowRequest,
    ManagedSystemResponse,
    ResourceAttributesRequest,
)
from src.domain.entities.audit_event import AuditEvent
from src.domain.entities.cloud_resource import CloudResource, ResourceAttributes
from src.domain.entities.compliance_finding import ComplianceFinding
from src.domain.entities.drift_finding import DriftFinding
from src.domain.entities.managed_system import ManagedSystem
from src.domain.entities.policy import Policy
from src.domain.entities.policy_exception import ExceptionApproval, PolicyException
from src.domain.entities.state_snapshot import ArchitectureBaseline, MaintenanceWindow
from src.domain.enums.cloud_provider import CloudProvider
from src.domain.enums.environment import Environment
from src.domain.enums.policy_severity import PolicySeverity
from src.domain.enums.resource_criticality import ResourceCriticality
from src.domain.enums.resource_type import ResourceType


def severity_from_label(label: str) -> PolicySeverity:
    return PolicySeverity[label]


def criticality_from_literal(value: str) -> ResourceCriticality:
    return ResourceCriticality[value.upper()]


def criticality_to_literal(value: ResourceCriticality) -> str:
    return value.name.lower()


def managed_system_to_response(system: ManagedSystem) -> ManagedSystemResponse:
    return ManagedSystemResponse(
        system_id=system.system_id,
        name=system.name,
        cloud_provider=system.cloud_provider.value,
        environment=system.environment.value,
        owner_actor_id=system.owner_actor_id,
        criticality=criticality_to_literal(system.criticality),
        description=system.description,
        tags=dict(system.tags),
        created_at=system.created_at,
        is_production=system.is_production,
    )


def resource_request_to_domain(
    request: CloudResourceRequest,
    *,
    managed_system_id: str,
    cloud_provider: CloudProvider,
    environment: Environment,
) -> CloudResource:
    a = request.attributes
    return CloudResource(
        resource_id=request.resource_id,
        managed_system_id=managed_system_id,
        cloud_provider=cloud_provider,
        environment=environment,
        resource_type=ResourceType(request.resource_type),
        region=request.region,
        name=request.name,
        criticality=criticality_from_literal(request.criticality),
        tags=dict(request.tags),
        attributes=ResourceAttributes(**a.model_dump()),
    )


def resource_to_response(resource: CloudResource) -> CloudResourceResponse:
    return CloudResourceResponse(
        resource_id=resource.resource_id,
        managed_system_id=resource.managed_system_id,
        cloud_provider=resource.cloud_provider.value,
        environment=resource.environment.value,
        resource_type=resource.resource_type.value,
        region=resource.region,
        name=resource.name,
        criticality=criticality_to_literal(resource.criticality),
        tags=dict(resource.tags),
        attributes=ResourceAttributesRequest(**{
            k: getattr(resource.attributes, k) for k in ResourceAttributesRequest.model_fields
        }),
        observed_at=resource.observed_at,
    )


def baseline_request_to_domain(request: ArchitectureBaselineRequest) -> ArchitectureBaseline:
    mw = request.maintenance_window
    return ArchitectureBaseline(
        allowed_regions=tuple(request.allowed_regions),
        required_tag_keys=tuple(request.required_tag_keys),
        supported_runtime_versions=tuple(request.supported_runtime_versions),
        required_retention_days=request.required_retention_days,
        maintenance_window=MaintenanceWindow(starts_at=mw.starts_at, ends_at=mw.ends_at),
    )


def baseline_to_response(baseline: ArchitectureBaseline) -> ArchitectureBaselineRequest:
    return ArchitectureBaselineRequest(
        allowed_regions=list(baseline.allowed_regions),
        required_tag_keys=list(baseline.required_tag_keys),
        supported_runtime_versions=list(baseline.supported_runtime_versions),
        required_retention_days=baseline.required_retention_days,
        maintenance_window=MaintenanceWindowRequest(
            starts_at=baseline.maintenance_window.starts_at,
            ends_at=baseline.maintenance_window.ends_at,
        ),
    )


def policy_to_response(policy: Policy) -> PolicyResponse:
    return PolicyResponse(
        policy_id=policy.policy_id,
        title=policy.title,
        description=policy.description,
        category=policy.category.value,
        severity=policy.severity.label,
        required_evidence=list(policy.required_evidence),
        explanation_template=policy.explanation_template,
        remediation_guidance=policy.remediation_guidance,
        exception_eligible=policy.exception_eligible,
        version=policy.version,
        active=policy.active,
    )


def compliance_finding_to_response(finding: ComplianceFinding) -> ComplianceFindingResponse:
    return ComplianceFindingResponse(
        finding_id=finding.finding_id,
        managed_system_id=finding.managed_system_id,
        resource_id=finding.resource_id,
        policy_id=finding.policy_id,
        category=finding.category.value,
        severity=finding.severity.label,
        title=finding.title,
        explanation=finding.explanation,
        evidence=list(finding.evidence),
        remediation_guidance=finding.remediation_guidance,
        exception_eligible=finding.exception_eligible,
        correlation_id=finding.correlation_id,
        status=finding.status.value,
        detected_at=finding.detected_at,
    )


def drift_finding_to_response(finding: DriftFinding) -> DriftFindingResponse:
    return DriftFindingResponse(
        finding_id=finding.finding_id,
        managed_system_id=finding.managed_system_id,
        resource_id=finding.resource_id,
        drift_type=finding.drift_type.value,
        what_changed=finding.what_changed,
        previous_value=finding.previous_value,
        current_value=finding.current_value,
        expected_value=finding.expected_value,
        why_it_matters=finding.why_it_matters,
        severity=finding.severity.label,
        evidence=list(finding.evidence),
        remediation=finding.remediation,
        exception_eligible=finding.exception_eligible,
        correlation_id=finding.correlation_id,
        policy_id=finding.policy_id,
        status=finding.status.value,
        detected_at=finding.detected_at,
    )


def exception_approval_to_response(approval: ExceptionApproval) -> ExceptionApprovalResponse:
    return ExceptionApprovalResponse(
        approval_id=approval.approval_id,
        exception_id=approval.exception_id,
        decision=approval.decision,
        rationale=approval.rationale,
        decided_by=approval.decided_by,
        decided_role=approval.decided_role,
        decided_at=approval.decided_at,
    )


def exception_to_response(exception: PolicyException) -> PolicyExceptionResponse:
    return PolicyExceptionResponse(
        exception_id=exception.exception_id,
        policy_id=exception.policy_id,
        resource_id=exception.resource_id,
        finding_id=exception.finding_id,
        managed_system_id=exception.managed_system_id,
        business_justification=exception.business_justification,
        risk_statement=exception.risk_statement,
        compensating_controls=list(exception.compensating_controls),
        requested_expiration=exception.requested_expiration,
        requested_by=exception.requested_by,
        evidence=list(exception.evidence),
        correlation_id=exception.correlation_id,
        status=exception.status.value,
        approvals=[exception_approval_to_response(a) for a in exception.approvals],
        created_at=exception.created_at,
        activated_at=exception.activated_at,
        expires_at=exception.expires_at,
        revoked_at=exception.revoked_at,
        revoked_by=exception.revoked_by,
        revoked_reason=exception.revoked_reason,
    )


def audit_event_to_response(event: AuditEvent) -> AuditEventResponse:
    return AuditEventResponse(
        event_id=event.event_id,
        sequence=event.sequence,
        previous_hash=event.previous_hash,
        current_hash=event.current_hash,
        actor=event.actor,
        actor_role=event.actor_role,
        action=event.action,
        resource_type=event.resource_type,
        resource_id=event.resource_id,
        correlation_id=event.correlation_id,
        payload=dict(event.payload),
        outcome=event.outcome,
        timestamp=event.timestamp,
    )
