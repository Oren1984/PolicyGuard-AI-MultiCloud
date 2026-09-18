"""Bidirectional mapping between pure domain entities and SQLAlchemy ORM
rows. Keeping this in one place means the domain layer never has to know
SQLAlchemy exists, and every repository implementation shares one
serialization contract for nested value objects.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from datetime import datetime

from src.adapters.persistence.models import (
    ComplianceFindingORM,
    DesiredStateSnapshotORM,
    DriftFindingORM,
    GovernanceDecisionORM,
    ManagedSystemORM,
    ObservedStateSnapshotORM,
    PolicyExceptionORM,
    PolicyORM,
    RemediationPlanORM,
)
from src.domain.entities.cloud_resource import CloudResource, ResourceAttributes
from src.domain.entities.compliance_finding import ComplianceFinding
from src.domain.entities.drift_finding import DriftFinding
from src.domain.entities.governance_decision import GovernanceDecision
from src.domain.entities.managed_system import ManagedSystem
from src.domain.entities.policy import Policy, PolicyEvaluationFn
from src.domain.entities.policy_exception import ExceptionApproval, PolicyException
from src.domain.entities.remediation_plan import RemediationPlan
from src.domain.entities.state_snapshot import (
    ArchitectureBaseline,
    DesiredStateSnapshot,
    MaintenanceWindow,
    ObservedStateSnapshot,
)
from src.domain.enums.cloud_provider import CloudProvider
from src.domain.enums.decision_type import DecisionType
from src.domain.enums.drift_type import DriftType
from src.domain.enums.environment import Environment
from src.domain.enums.exception_status import ExceptionStatus
from src.domain.enums.finding_status import FindingStatus
from src.domain.enums.policy_category import PolicyCategory
from src.domain.enums.policy_severity import PolicySeverity
from src.domain.enums.remediation_status import RemediationStatus
from src.domain.enums.resource_criticality import ResourceCriticality
from src.domain.enums.resource_type import ResourceType

# --------------------------------------------------------------------------
# CloudResource / ResourceAttributes
# --------------------------------------------------------------------------


def resource_to_dict(resource: CloudResource) -> dict:
    return {
        "resource_id": resource.resource_id,
        "managed_system_id": resource.managed_system_id,
        "cloud_provider": resource.cloud_provider.value,
        "environment": resource.environment.value,
        "resource_type": resource.resource_type.value,
        "region": resource.region,
        "name": resource.name,
        "criticality": int(resource.criticality),
        "tags": dict(resource.tags),
        "attributes": dataclasses.asdict(resource.attributes),
        "observed_at": resource.observed_at.isoformat(),
    }


def dict_to_resource(data: dict) -> CloudResource:
    return CloudResource(
        resource_id=data["resource_id"],
        managed_system_id=data["managed_system_id"],
        cloud_provider=CloudProvider(data["cloud_provider"]),
        environment=Environment(data["environment"]),
        resource_type=ResourceType(data["resource_type"]),
        region=data["region"],
        name=data["name"],
        criticality=ResourceCriticality(data["criticality"]),
        tags=dict(data.get("tags", {})),
        attributes=ResourceAttributes(**data.get("attributes", {})),
        observed_at=datetime.fromisoformat(data["observed_at"]),
    )


# --------------------------------------------------------------------------
# ArchitectureBaseline
# --------------------------------------------------------------------------


def baseline_to_dict(baseline: ArchitectureBaseline) -> dict:
    return {
        "allowed_regions": list(baseline.allowed_regions),
        "required_tag_keys": list(baseline.required_tag_keys),
        "supported_runtime_versions": list(baseline.supported_runtime_versions),
        "required_retention_days": baseline.required_retention_days,
        "maintenance_window": {
            "starts_at": (
                baseline.maintenance_window.starts_at.isoformat()
                if baseline.maintenance_window.starts_at
                else None
            ),
            "ends_at": (
                baseline.maintenance_window.ends_at.isoformat()
                if baseline.maintenance_window.ends_at
                else None
            ),
        },
    }


def dict_to_baseline(data: dict) -> ArchitectureBaseline:
    mw = data.get("maintenance_window") or {}
    return ArchitectureBaseline(
        allowed_regions=tuple(data.get("allowed_regions", ())),
        required_tag_keys=tuple(data.get("required_tag_keys", ())),
        supported_runtime_versions=tuple(data.get("supported_runtime_versions", ())),
        required_retention_days=data.get("required_retention_days"),
        maintenance_window=MaintenanceWindow(
            starts_at=datetime.fromisoformat(mw["starts_at"]) if mw.get("starts_at") else None,
            ends_at=datetime.fromisoformat(mw["ends_at"]) if mw.get("ends_at") else None,
        ),
    )


# --------------------------------------------------------------------------
# ManagedSystem
# --------------------------------------------------------------------------


def managed_system_to_orm(system: ManagedSystem) -> ManagedSystemORM:
    return ManagedSystemORM(
        system_id=system.system_id,
        name=system.name,
        cloud_provider=system.cloud_provider.value,
        environment=system.environment.value,
        owner_actor_id=system.owner_actor_id,
        criticality=int(system.criticality),
        description=system.description,
        tags=dict(system.tags),
        created_at=system.created_at,
    )


def orm_to_managed_system(orm: ManagedSystemORM) -> ManagedSystem:
    return ManagedSystem(
        system_id=orm.system_id,
        name=orm.name,
        cloud_provider=CloudProvider(orm.cloud_provider),
        environment=Environment(orm.environment),
        owner_actor_id=orm.owner_actor_id,
        criticality=ResourceCriticality(orm.criticality),
        description=orm.description,
        tags=dict(orm.tags or {}),
        created_at=orm.created_at,
    )


# --------------------------------------------------------------------------
# Snapshots
# --------------------------------------------------------------------------


def desired_snapshot_to_orm(snapshot: DesiredStateSnapshot) -> DesiredStateSnapshotORM:
    return DesiredStateSnapshotORM(
        snapshot_id=snapshot.snapshot_id,
        managed_system_id=snapshot.managed_system_id,
        source=snapshot.source,
        resources=[resource_to_dict(r) for r in snapshot.resources],
        baseline=baseline_to_dict(snapshot.baseline),
        submitted_by=snapshot.submitted_by,
        captured_at=snapshot.captured_at,
    )


def orm_to_desired_snapshot(orm: DesiredStateSnapshotORM) -> DesiredStateSnapshot:
    return DesiredStateSnapshot(
        snapshot_id=orm.snapshot_id,
        managed_system_id=orm.managed_system_id,
        source=orm.source,
        resources=tuple(dict_to_resource(r) for r in (orm.resources or [])),
        baseline=dict_to_baseline(orm.baseline or {}),
        submitted_by=orm.submitted_by,
        captured_at=orm.captured_at,
    )


def observed_snapshot_to_orm(snapshot: ObservedStateSnapshot) -> ObservedStateSnapshotORM:
    return ObservedStateSnapshotORM(
        snapshot_id=snapshot.snapshot_id,
        managed_system_id=snapshot.managed_system_id,
        source=snapshot.source,
        resources=[resource_to_dict(r) for r in snapshot.resources],
        correlation_id=snapshot.correlation_id,
        captured_at=snapshot.captured_at,
    )


def orm_to_observed_snapshot(orm: ObservedStateSnapshotORM) -> ObservedStateSnapshot:
    return ObservedStateSnapshot(
        snapshot_id=orm.snapshot_id,
        managed_system_id=orm.managed_system_id,
        source=orm.source,
        resources=tuple(dict_to_resource(r) for r in (orm.resources or [])),
        captured_at=orm.captured_at,
        correlation_id=orm.correlation_id,
    )


# --------------------------------------------------------------------------
# Policy / PolicyPack
#
# `Policy.evaluate` is a pure Python callable and cannot be persisted; the
# caller (src/adapters/persistence/policy_repository_sqlalchemy.py) supplies
# it back via `evaluate` after looking it up in the code-defined registry.
# --------------------------------------------------------------------------


def policy_to_orm(policy: Policy) -> PolicyORM:
    return PolicyORM(
        policy_id=policy.policy_id,
        title=policy.title,
        description=policy.description,
        category=policy.category.value,
        severity=int(policy.severity),
        required_evidence=list(policy.required_evidence),
        explanation_template=policy.explanation_template,
        remediation_guidance=policy.remediation_guidance,
        exception_eligible=policy.exception_eligible,
        version=policy.version,
        active=policy.active,
    )


def orm_to_policy(orm: PolicyORM, *, evaluate: PolicyEvaluationFn) -> Policy:
    return Policy(
        policy_id=orm.policy_id,
        title=orm.title,
        description=orm.description,
        category=PolicyCategory(orm.category),
        severity=PolicySeverity(orm.severity),
        evaluate=evaluate,
        required_evidence=tuple(orm.required_evidence or ()),
        explanation_template=orm.explanation_template,
        remediation_guidance=orm.remediation_guidance,
        exception_eligible=orm.exception_eligible,
        version=orm.version,
        active=orm.active,
    )


# --------------------------------------------------------------------------
# ComplianceFinding / DriftFinding
# --------------------------------------------------------------------------


def compliance_finding_to_orm(finding: ComplianceFinding) -> ComplianceFindingORM:
    return ComplianceFindingORM(
        finding_id=finding.finding_id,
        managed_system_id=finding.managed_system_id,
        resource_id=finding.resource_id,
        policy_id=finding.policy_id,
        category=finding.category.value,
        severity=int(finding.severity),
        title=finding.title,
        explanation=finding.explanation,
        evidence=list(finding.evidence),
        remediation_guidance=finding.remediation_guidance,
        exception_eligible=finding.exception_eligible,
        correlation_id=finding.correlation_id,
        status=finding.status.value,
        detected_at=finding.detected_at,
    )


def orm_to_compliance_finding(orm: ComplianceFindingORM) -> ComplianceFinding:
    return ComplianceFinding(
        finding_id=orm.finding_id,
        managed_system_id=orm.managed_system_id,
        resource_id=orm.resource_id,
        policy_id=orm.policy_id,
        category=PolicyCategory(orm.category),
        severity=PolicySeverity(orm.severity),
        title=orm.title,
        explanation=orm.explanation,
        evidence=tuple(orm.evidence or ()),
        remediation_guidance=orm.remediation_guidance,
        exception_eligible=orm.exception_eligible,
        correlation_id=orm.correlation_id,
        status=FindingStatus(orm.status),
        detected_at=orm.detected_at,
    )


def drift_finding_to_orm(finding: DriftFinding) -> DriftFindingORM:
    return DriftFindingORM(
        finding_id=finding.finding_id,
        managed_system_id=finding.managed_system_id,
        resource_id=finding.resource_id,
        drift_type=finding.drift_type.value,
        what_changed=finding.what_changed,
        previous_value=finding.previous_value,
        current_value=finding.current_value,
        expected_value=finding.expected_value,
        why_it_matters=finding.why_it_matters,
        severity=int(finding.severity),
        evidence=list(finding.evidence),
        remediation=finding.remediation,
        exception_eligible=finding.exception_eligible,
        correlation_id=finding.correlation_id,
        policy_id=finding.policy_id,
        status=finding.status.value,
        detected_at=finding.detected_at,
    )


def orm_to_drift_finding(orm: DriftFindingORM) -> DriftFinding:
    return DriftFinding(
        finding_id=orm.finding_id,
        managed_system_id=orm.managed_system_id,
        resource_id=orm.resource_id,
        drift_type=DriftType(orm.drift_type),
        what_changed=orm.what_changed,
        previous_value=orm.previous_value,
        current_value=orm.current_value,
        expected_value=orm.expected_value,
        why_it_matters=orm.why_it_matters,
        severity=PolicySeverity(orm.severity),
        evidence=tuple(orm.evidence or ()),
        remediation=orm.remediation,
        exception_eligible=orm.exception_eligible,
        correlation_id=orm.correlation_id,
        policy_id=orm.policy_id,
        status=FindingStatus(orm.status),
        detected_at=orm.detected_at,
    )


# --------------------------------------------------------------------------
# GovernanceDecision
# --------------------------------------------------------------------------


def governance_decision_to_orm(decision: GovernanceDecision) -> GovernanceDecisionORM:
    return GovernanceDecisionORM(
        decision_id=decision.decision_id,
        managed_system_id=decision.managed_system_id,
        finding_ids=list(decision.finding_ids),
        decision=decision.decision.value,
        reasons=list(decision.reasons),
        policy_ids=list(decision.policy_ids),
        correlation_id=decision.correlation_id,
        decided_at=decision.decided_at,
    )


def orm_to_governance_decision(orm: GovernanceDecisionORM) -> GovernanceDecision:
    return GovernanceDecision(
        decision_id=orm.decision_id,
        managed_system_id=orm.managed_system_id,
        finding_ids=tuple(orm.finding_ids or ()),
        decision=DecisionType(orm.decision),
        reasons=tuple(orm.reasons or ()),
        policy_ids=tuple(orm.policy_ids or ()),
        correlation_id=orm.correlation_id,
        decided_at=orm.decided_at,
    )


# --------------------------------------------------------------------------
# PolicyException / ExceptionApproval
# --------------------------------------------------------------------------


def _approval_to_dict(approval: ExceptionApproval) -> dict:
    return {
        "approval_id": approval.approval_id,
        "exception_id": approval.exception_id,
        "decision": approval.decision,
        "rationale": approval.rationale,
        "decided_by": approval.decided_by,
        "decided_role": approval.decided_role,
        "decided_at": approval.decided_at.isoformat(),
    }


def _dict_to_approval(data: dict) -> ExceptionApproval:
    return ExceptionApproval(
        approval_id=data["approval_id"],
        exception_id=data["exception_id"],
        decision=data["decision"],
        rationale=data["rationale"],
        decided_by=data["decided_by"],
        decided_role=data["decided_role"],
        decided_at=datetime.fromisoformat(data["decided_at"]),
    )


def policy_exception_to_orm(exception: PolicyException) -> PolicyExceptionORM:
    return PolicyExceptionORM(
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
        approvals=[_approval_to_dict(a) for a in exception.approvals],
        created_at=exception.created_at,
        activated_at=exception.activated_at,
        expires_at=exception.expires_at,
        revoked_at=exception.revoked_at,
        revoked_by=exception.revoked_by,
        revoked_reason=exception.revoked_reason,
    )


def orm_to_policy_exception(orm: PolicyExceptionORM) -> PolicyException:
    return PolicyException(
        exception_id=orm.exception_id,
        policy_id=orm.policy_id,
        resource_id=orm.resource_id,
        finding_id=orm.finding_id,
        managed_system_id=orm.managed_system_id,
        business_justification=orm.business_justification,
        risk_statement=orm.risk_statement,
        compensating_controls=tuple(orm.compensating_controls or ()),
        requested_expiration=orm.requested_expiration,
        requested_by=orm.requested_by,
        evidence=tuple(orm.evidence or ()),
        correlation_id=orm.correlation_id,
        status=ExceptionStatus(orm.status),
        approvals=tuple(_dict_to_approval(a) for a in (orm.approvals or [])),
        created_at=orm.created_at,
        activated_at=orm.activated_at,
        expires_at=orm.expires_at,
        revoked_at=orm.revoked_at,
        revoked_by=orm.revoked_by,
        revoked_reason=orm.revoked_reason,
    )


# --------------------------------------------------------------------------
# RemediationPlan
# --------------------------------------------------------------------------


def remediation_plan_to_orm(plan: RemediationPlan) -> RemediationPlanORM:
    return RemediationPlanORM(
        plan_id=plan.plan_id,
        finding_id=plan.finding_id,
        managed_system_id=plan.managed_system_id,
        description=plan.description,
        status=plan.status.value,
        assigned_to=plan.assigned_to,
        correlation_id=plan.correlation_id,
        verification_evidence=list(plan.verification_evidence),
        due_by=plan.due_by,
        created_at=plan.created_at,
        updated_at=plan.updated_at,
    )


def orm_to_remediation_plan(orm: RemediationPlanORM) -> RemediationPlan:
    return RemediationPlan(
        plan_id=orm.plan_id,
        finding_id=orm.finding_id,
        managed_system_id=orm.managed_system_id,
        description=orm.description,
        status=RemediationStatus(orm.status),
        assigned_to=orm.assigned_to,
        correlation_id=orm.correlation_id,
        verification_evidence=tuple(orm.verification_evidence or ()),
        due_by=orm.due_by,
        created_at=orm.created_at,
        updated_at=orm.updated_at,
    )


PolicyEvaluateResolver = Callable[[str], PolicyEvaluationFn]
