"""Findings and decisions capability group (spec section 15): list/detail
findings, generate deterministic governance decisions, remediation
guidance/progress, and the AI-assisted explanation layer (spec sections 10,
11) over findings.

Two gaps in the Phase 1 application layer are filled directly here, thinly,
rather than by adding new files under `src/application/` (out of scope for
this phase -- see module docstrings on `kill_switch_gate.py` and
`providers.py` for the same reasoning applied elsewhere):

1. Nothing in Phase 1 creates a `RemediationPlan` (only
   `UpdateRemediationStatusUseCase` updates one that already exists) or
   transitions a finding's own `FindingStatus` (the finding-transition state
   machine exists in `src/domain/state_machine/finding_transitions.py` but
   no use case drives it). Both gaps are filled here as thin
   validate-then-persist-then-audit orchestration, mirroring exactly what
   e.g. `SubmitDesiredStateSnapshotUseCase` does internally -- no new
   business rules, just wiring already-built ports together.
"""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status

from src.api.dependencies.actor import get_actor
from src.api.dependencies.kill_switch_gate import require_mutation_allowed, require_normal_mode_for_evaluation
from src.api.dependencies.providers import AIAdvisoryOrchestrator, get_ai_advisory_orchestrator
from src.api.dependencies.repositories import (
    get_audit_repo,
    get_compliance_finding_repo,
    get_drift_finding_repo,
    get_remediation_repo,
)
from src.api.dependencies.use_cases import (
    get_generate_governance_decision_use_case,
    get_update_remediation_status_use_case,
)
from src.api.routes._converters import compliance_finding_to_response, drift_finding_to_response
from src.api.schemas.finding_schemas import (
    AIAdvisoryResponse,
    AISummaryRequest,
    ComplianceFindingResponse,
    DriftFindingResponse,
    FindingListResponse,
    FindingStatusUpdateRequest,
    GateResultResponse,
    GovernanceDecisionResponse,
    RemediationPlanCreateRequest,
    RemediationPlanResponse,
    RemediationStatusUpdateRequest,
)
from src.application.use_cases.generate_governance_decision import GenerateGovernanceDecisionUseCase
from src.application.use_cases.update_remediation_status import UpdateRemediationStatusUseCase
from src.domain.entities.actor import Actor
from src.domain.entities.remediation_plan import RemediationPlan
from src.domain.enums.finding_status import FindingStatus
from src.domain.enums.remediation_status import RemediationStatus
from src.domain.state_machine.finding_transitions import validate_transition
from src.observability.correlation import get_correlation_id
from src.observability.metrics import decisions_total
from src.ports.finding_repository import FindingNotFoundError

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])

FindingKind = Literal["compliance", "drift"]


def _get_finding_repo(kind: FindingKind, compliance_repo, drift_repo):
    return compliance_repo if kind == "compliance" else drift_repo


def _finding_to_response(kind: FindingKind, finding) -> ComplianceFindingResponse | DriftFindingResponse:
    if kind == "compliance":
        return compliance_finding_to_response(finding)
    return drift_finding_to_response(finding)


@router.get("/{kind}", response_model=FindingListResponse)
def list_findings(
    kind: FindingKind,
    managed_system_id: str | None = Query(default=None),
    status_filter: FindingStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    compliance_repo=Depends(get_compliance_finding_repo),
    drift_repo=Depends(get_drift_finding_repo),
) -> FindingListResponse:
    repo = _get_finding_repo(kind, compliance_repo, drift_repo)
    items, total = repo.list(
        managed_system_id=managed_system_id, status=status_filter, limit=limit, offset=offset
    )
    return FindingListResponse(
        items=[_finding_to_response(kind, f) for f in items], total=total, limit=limit, offset=offset
    )


@router.get("/{kind}/{finding_id}", response_model=ComplianceFindingResponse | DriftFindingResponse)
def get_finding(
    kind: FindingKind,
    finding_id: str,
    compliance_repo=Depends(get_compliance_finding_repo),
    drift_repo=Depends(get_drift_finding_repo),
) -> ComplianceFindingResponse | DriftFindingResponse:
    repo = _get_finding_repo(kind, compliance_repo, drift_repo)
    return _finding_to_response(kind, repo.get(finding_id))


@router.patch("/remediation-plans/{plan_id}/status", response_model=RemediationPlanResponse)
def update_remediation_status(
    plan_id: str,
    payload: RemediationStatusUpdateRequest,
    actor: Actor = Depends(get_actor),
    use_case: UpdateRemediationStatusUseCase = Depends(get_update_remediation_status_use_case),
    _mode=Depends(require_mutation_allowed),
) -> RemediationPlanResponse:
    updated = use_case.execute(
        plan_id,
        target_status=RemediationStatus(payload.target_status),
        verification_evidence=tuple(payload.verification_evidence),
        actor=actor,
        correlation_id=get_correlation_id(),
    )
    return _remediation_to_response(updated)


@router.patch("/{kind}/{finding_id}/status", response_model=ComplianceFindingResponse | DriftFindingResponse)
def update_finding_status(
    kind: FindingKind,
    finding_id: str,
    payload: FindingStatusUpdateRequest,
    actor: Actor = Depends(get_actor),
    compliance_repo=Depends(get_compliance_finding_repo),
    drift_repo=Depends(get_drift_finding_repo),
    audit_repo=Depends(get_audit_repo),
    _mode=Depends(require_mutation_allowed),
) -> ComplianceFindingResponse | DriftFindingResponse:
    repo = _get_finding_repo(kind, compliance_repo, drift_repo)
    finding = repo.get(finding_id)
    target = FindingStatus(payload.target_status)
    validate_transition(finding.status, target)  # fail closed: raises InvalidStateTransitionError -> 409
    updated = repo.update_status(finding_id, target)
    audit_repo.append(
        actor=actor.actor_id,
        actor_role=actor.role.value,
        action="FINDING_STATUS_UPDATED",
        resource_type=f"{kind}_finding",
        resource_id=finding_id,
        correlation_id=get_correlation_id(),
        payload={"from": finding.status.value, "to": target.value},
    )
    return _finding_to_response(kind, updated)


@router.post("/{kind}/{finding_id}/decision", response_model=GovernanceDecisionResponse)
def generate_decision(
    kind: FindingKind,
    finding_id: str,
    actor: Actor = Depends(get_actor),
    use_case: GenerateGovernanceDecisionUseCase = Depends(get_generate_governance_decision_use_case),
    _mode=Depends(require_normal_mode_for_evaluation),
) -> GovernanceDecisionResponse:
    decision = use_case.execute(
        finding_id=finding_id, finding_kind=kind, actor=actor, correlation_id=get_correlation_id()
    )
    decisions_total.labels(decision=decision.decision.value).inc()
    return GovernanceDecisionResponse(
        decision_id=decision.decision_id,
        managed_system_id=decision.managed_system_id,
        finding_ids=list(decision.finding_ids),
        decision=decision.decision.value,
        reasons=list(decision.reasons),
        policy_ids=list(decision.policy_ids),
        correlation_id=decision.correlation_id,
        decided_at=decision.decided_at,
    )


def _remediation_to_response(plan: RemediationPlan) -> RemediationPlanResponse:
    return RemediationPlanResponse(
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


@router.get("/{kind}/{finding_id}/remediation-plan", response_model=RemediationPlanResponse | None)
def get_remediation_plan(
    kind: FindingKind, finding_id: str, remediation_repo=Depends(get_remediation_repo)
) -> RemediationPlanResponse | None:
    plan = remediation_repo.get_for_finding(finding_id)
    return _remediation_to_response(plan) if plan is not None else None


@router.post(
    "/{kind}/{finding_id}/remediation-plan",
    response_model=RemediationPlanResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_remediation_plan(
    kind: FindingKind,
    finding_id: str,
    payload: RemediationPlanCreateRequest,
    actor: Actor = Depends(get_actor),
    compliance_repo=Depends(get_compliance_finding_repo),
    drift_repo=Depends(get_drift_finding_repo),
    remediation_repo=Depends(get_remediation_repo),
    audit_repo=Depends(get_audit_repo),
    _mode=Depends(require_mutation_allowed),
) -> RemediationPlanResponse:
    repo = _get_finding_repo(kind, compliance_repo, drift_repo)
    finding = repo.get(finding_id)  # raises FindingNotFoundError -> 404 if the finding doesn't exist
    correlation_id = get_correlation_id()
    plan = RemediationPlan(
        plan_id=uuid.uuid4().hex,
        finding_id=finding_id,
        managed_system_id=finding.managed_system_id,
        description=payload.description,
        status=RemediationStatus.NOT_STARTED,
        assigned_to=payload.assigned_to,
        correlation_id=correlation_id,
        due_by=payload.due_by,
    )
    created = remediation_repo.create(plan)
    audit_repo.append(
        actor=actor.actor_id,
        actor_role=actor.role.value,
        action="REMEDIATION_PLAN_CREATED",
        resource_type="remediation_plan",
        resource_id=created.plan_id,
        correlation_id=correlation_id,
        payload={"finding_id": finding_id, "finding_kind": kind},
    )
    return _remediation_to_response(created)


def _resolve_findings(refs, compliance_repo, drift_repo) -> list:
    findings = []
    for ref in refs:
        repo = _get_finding_repo(ref.kind, compliance_repo, drift_repo)
        try:
            findings.append(repo.get(ref.finding_id))
        except FindingNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
    return findings


def _advisory_response(result) -> AIAdvisoryResponse:
    return AIAdvisoryResponse(
        provider_name=result.content.provider_name,
        kind=result.content.kind,
        content=result.content.content,
        referenced_evidence=list(result.content.referenced_evidence),
        confidence=result.content.confidence,
        gate_results=[
            GateResultResponse(gate=r.gate.value, status=r.status.value, reason=r.reason, details=r.details)
            for r in result.gates.results
        ],
        fell_back=result.fell_back,
    )


@router.post("/ai/summary", response_model=AIAdvisoryResponse)
def ai_summarize_findings(
    payload: AISummaryRequest,
    actor: Actor = Depends(get_actor),
    compliance_repo=Depends(get_compliance_finding_repo),
    drift_repo=Depends(get_drift_finding_repo),
    orchestrator: AIAdvisoryOrchestrator = Depends(get_ai_advisory_orchestrator),
) -> AIAdvisoryResponse:
    findings = _resolve_findings(payload.findings, compliance_repo, drift_repo)
    result = orchestrator.summarize(findings, actor=actor, correlation_id=get_correlation_id())
    return _advisory_response(result)


@router.post("/ai/group", response_model=AIAdvisoryResponse)
def ai_group_related_violations(
    payload: AISummaryRequest,
    actor: Actor = Depends(get_actor),
    compliance_repo=Depends(get_compliance_finding_repo),
    drift_repo=Depends(get_drift_finding_repo),
    orchestrator: AIAdvisoryOrchestrator = Depends(get_ai_advisory_orchestrator),
) -> AIAdvisoryResponse:
    findings = _resolve_findings(payload.findings, compliance_repo, drift_repo)
    result = orchestrator.group(findings, actor=actor, correlation_id=get_correlation_id())
    return _advisory_response(result)


@router.post("/{kind}/{finding_id}/ai/impact", response_model=AIAdvisoryResponse)
def ai_explain_impact(
    kind: FindingKind,
    finding_id: str,
    actor: Actor = Depends(get_actor),
    compliance_repo=Depends(get_compliance_finding_repo),
    drift_repo=Depends(get_drift_finding_repo),
    orchestrator: AIAdvisoryOrchestrator = Depends(get_ai_advisory_orchestrator),
) -> AIAdvisoryResponse:
    finding = _get_finding_repo(kind, compliance_repo, drift_repo).get(finding_id)
    result = orchestrator.explain_impact(finding, actor=actor, correlation_id=get_correlation_id())
    return _advisory_response(result)


@router.post("/{kind}/{finding_id}/ai/remediation-outline", response_model=AIAdvisoryResponse)
def ai_remediation_outline(
    kind: FindingKind,
    finding_id: str,
    actor: Actor = Depends(get_actor),
    compliance_repo=Depends(get_compliance_finding_repo),
    drift_repo=Depends(get_drift_finding_repo),
    orchestrator: AIAdvisoryOrchestrator = Depends(get_ai_advisory_orchestrator),
) -> AIAdvisoryResponse:
    finding = _get_finding_repo(kind, compliance_repo, drift_repo).get(finding_id)
    result = orchestrator.remediation_outline(finding, actor=actor, correlation_id=get_correlation_id())
    return _advisory_response(result)
