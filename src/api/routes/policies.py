"""Policies capability group (spec section 15): create/list/version
policies, activate/deactivate, create/list policy packs, and evaluate a
snapshot against a policy pack."""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Query, status

from src.adapters.persistence.policy_registry import resolve_evaluate_fn
from src.api.dependencies.actor import get_actor
from src.api.dependencies.kill_switch_gate import require_mutation_allowed
from src.api.dependencies.repositories import (
    get_compliance_finding_repo,
    get_managed_system_repo,
    get_policy_pack_repo,
    get_policy_repo,
)
from src.api.dependencies.use_cases import get_evaluate_policy_pack_use_case
from src.api.routes._converters import policy_to_response, severity_from_label
from src.api.schemas.policy_schemas import (
    EvaluatePolicyPackRequest,
    PolicyCreateRequest,
    PolicyEvaluationResponse,
    PolicyListResponse,
    PolicyPackCreateRequest,
    PolicyPackListResponse,
    PolicyPackResponse,
    PolicyResponse,
)
from src.application.use_cases.evaluate_policy_pack import EvaluatePolicyPackUseCase
from src.domain.entities.actor import Actor
from src.domain.entities.policy import Policy, PolicyPack
from src.domain.enums.actor_role import POLICY_ADMIN_ROLES
from src.observability.correlation import get_correlation_id
from src.observability.metrics import evaluation_duration_seconds, evaluations_total, findings_total

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])


def _require_policy_admin(actor: Actor) -> None:
    """Spec section 31 ("Human-in-the-Loop Control"): policy activation or
    deactivation is a mandatory human action restricted to an authorized
    role. No dedicated application service exists for this narrower check
    (unlike the exception workflow's ExceptionAuthorizationService), so it
    is enforced directly here against the same POLICY_ADMIN_ROLES set the
    domain layer already defines -- still fails closed with 403, just
    without an intermediate service class for a single-role check."""
    if actor.role not in POLICY_ADMIN_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"role '{actor.role.value}' is not authorized to manage policies or policy packs",
        )


@router.post("", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
def create_policy(
    payload: PolicyCreateRequest,
    actor: Actor = Depends(get_actor),
    policy_repo=Depends(get_policy_repo),
    _mode=Depends(require_mutation_allowed),
) -> PolicyResponse:
    _require_policy_admin(actor)
    policy = Policy(
        policy_id=payload.policy_id,
        title=payload.title,
        description=payload.description,
        category=payload.category,
        severity=severity_from_label(payload.severity),
        evaluate=resolve_evaluate_fn(payload.policy_id),
        required_evidence=tuple(payload.required_evidence),
        explanation_template=payload.explanation_template,
        remediation_guidance=payload.remediation_guidance,
        exception_eligible=payload.exception_eligible,
        version=payload.version,
        active=payload.active,
    )
    created = policy_repo.create(policy)
    return policy_to_response(created)


@router.get("", response_model=PolicyListResponse)
def list_policies(
    active_only: bool = Query(default=False), policy_repo=Depends(get_policy_repo)
) -> PolicyListResponse:
    policies = policy_repo.list(active_only=active_only)
    return PolicyListResponse(items=[policy_to_response(p) for p in policies])


@router.get("/{policy_id}", response_model=PolicyResponse)
def get_policy(policy_id: str, policy_repo=Depends(get_policy_repo)) -> PolicyResponse:
    return policy_to_response(policy_repo.get(policy_id))


@router.post("/{policy_id}/activate", response_model=PolicyResponse)
def activate_policy(
    policy_id: str,
    actor: Actor = Depends(get_actor),
    policy_repo=Depends(get_policy_repo),
    _mode=Depends(require_mutation_allowed),
) -> PolicyResponse:
    _require_policy_admin(actor)
    return policy_to_response(policy_repo.set_active(policy_id, True))


@router.post("/{policy_id}/deactivate", response_model=PolicyResponse)
def deactivate_policy(
    policy_id: str,
    actor: Actor = Depends(get_actor),
    policy_repo=Depends(get_policy_repo),
    _mode=Depends(require_mutation_allowed),
) -> PolicyResponse:
    _require_policy_admin(actor)
    return policy_to_response(policy_repo.set_active(policy_id, False))


@router.post("/packs", response_model=PolicyPackResponse, status_code=status.HTTP_201_CREATED)
def create_policy_pack(
    payload: PolicyPackCreateRequest,
    actor: Actor = Depends(get_actor),
    policy_repo=Depends(get_policy_repo),
    policy_pack_repo=Depends(get_policy_pack_repo),
    _mode=Depends(require_mutation_allowed),
) -> PolicyPackResponse:
    _require_policy_admin(actor)
    policies = [policy_repo.get(pid) for pid in payload.policy_ids]
    pack = PolicyPack(
        pack_id=payload.pack_id,
        name=payload.name,
        version=payload.version,
        policies=tuple(policies),
        active=payload.active,
        description=payload.description,
    )
    created = policy_pack_repo.create(pack)
    return PolicyPackResponse(
        pack_id=created.pack_id,
        name=created.name,
        version=created.version,
        policies=[policy_to_response(p) for p in created.policies],
        active=created.active,
        description=created.description,
    )


@router.get("/packs", response_model=PolicyPackListResponse)
def list_policy_packs(
    active_only: bool = Query(default=False), policy_pack_repo=Depends(get_policy_pack_repo)
) -> PolicyPackListResponse:
    packs = policy_pack_repo.list(active_only=active_only)
    return PolicyPackListResponse(
        items=[
            PolicyPackResponse(
                pack_id=p.pack_id,
                name=p.name,
                version=p.version,
                policies=[policy_to_response(pol) for pol in p.policies],
                active=p.active,
                description=p.description,
            )
            for p in packs
        ]
    )


@router.get("/packs/{pack_id}", response_model=PolicyPackResponse)
def get_policy_pack(pack_id: str, policy_pack_repo=Depends(get_policy_pack_repo)) -> PolicyPackResponse:
    p = policy_pack_repo.get(pack_id)
    return PolicyPackResponse(
        pack_id=p.pack_id,
        name=p.name,
        version=p.version,
        policies=[policy_to_response(pol) for pol in p.policies],
        active=p.active,
        description=p.description,
    )


@router.post("/packs/{pack_id}/activate", response_model=PolicyPackResponse)
def activate_policy_pack(
    pack_id: str,
    actor: Actor = Depends(get_actor),
    policy_pack_repo=Depends(get_policy_pack_repo),
    _mode=Depends(require_mutation_allowed),
) -> PolicyPackResponse:
    _require_policy_admin(actor)
    p = policy_pack_repo.set_active(pack_id, True)
    return PolicyPackResponse(
        pack_id=p.pack_id, name=p.name, version=p.version,
        policies=[policy_to_response(pol) for pol in p.policies], active=p.active, description=p.description,
    )


@router.post("/packs/{pack_id}/deactivate", response_model=PolicyPackResponse)
def deactivate_policy_pack(
    pack_id: str,
    actor: Actor = Depends(get_actor),
    policy_pack_repo=Depends(get_policy_pack_repo),
    _mode=Depends(require_mutation_allowed),
) -> PolicyPackResponse:
    _require_policy_admin(actor)
    p = policy_pack_repo.set_active(pack_id, False)
    return PolicyPackResponse(
        pack_id=p.pack_id, name=p.name, version=p.version,
        policies=[policy_to_response(pol) for pol in p.policies], active=p.active, description=p.description,
    )


@router.post("/packs/{pack_id}/evaluate", response_model=PolicyEvaluationResponse)
def evaluate_policy_pack(
    pack_id: str,
    payload: EvaluatePolicyPackRequest,
    actor: Actor = Depends(get_actor),
    use_case: EvaluatePolicyPackUseCase = Depends(get_evaluate_policy_pack_use_case),
    managed_system_repo=Depends(get_managed_system_repo),
    compliance_finding_repo=Depends(get_compliance_finding_repo),
) -> PolicyEvaluationResponse:
    # No `require_normal_mode_for_evaluation` dependency here: this use case
    # already performs its own equivalent kill-switch check internally
    # (raises EvaluationBlockedError, mapped to HTTP 503 in src/main.py) --
    # see src/api/dependencies/kill_switch_gate.py's module docstring for
    # why this route relies on that instead of a duplicate gate.
    correlation_id = get_correlation_id()
    started = time.perf_counter()
    evaluation = use_case.execute(
        managed_system_id=payload.managed_system_id, policy_pack_id=pack_id, actor=actor,
        correlation_id=correlation_id,
    )
    evaluation_duration_seconds.labels(evaluation_type="policy_pack").observe(time.perf_counter() - started)
    evaluations_total.labels(evaluation_type="policy_pack").inc()

    provider = managed_system_repo.get(payload.managed_system_id).cloud_provider.value
    for finding_id in evaluation.finding_ids:
        finding = compliance_finding_repo.get(finding_id)
        findings_total.labels(severity=finding.severity.label, provider=provider, kind="compliance").inc()

    return PolicyEvaluationResponse(
        evaluation_id=evaluation.evaluation_id,
        managed_system_id=evaluation.managed_system_id,
        policy_pack_id=evaluation.policy_pack_id,
        observed_snapshot_id=evaluation.observed_snapshot_id,
        finding_ids=list(evaluation.finding_ids),
        resources_evaluated=evaluation.resources_evaluated,
        correlation_id=evaluation.correlation_id,
        evaluated_at=evaluation.evaluated_at,
    )
