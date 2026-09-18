"""Policy-exception workflow capability group (spec section 12/15).

Every mutating action here calls into `ExceptionAuthorizationService`
(already wired inside the Phase 1 use cases via DI) so separation-of-duties
is enforced below the API layer, not just by these handlers -- see that
service's docstring. `payload.requested_by` is never trusted as the actual
requester on its own: `RequestPolicyExceptionUseCase` compares it against
the authenticated `actor.actor_id` and rejects a mismatch as spoofing
(spec section 12, demo scenario 13).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from src.api.dependencies.actor import get_actor
from src.api.dependencies.kill_switch_gate import require_mutation_allowed, require_normal_mode_for_evaluation
from src.api.dependencies.repositories import get_exception_repo
from src.api.dependencies.use_cases import (
    get_decide_exception_use_case,
    get_expire_exceptions_use_case,
    get_request_exception_use_case,
    get_review_exception_use_case,
    get_revoke_exception_use_case,
)
from src.api.routes._converters import exception_to_response
from src.api.schemas.exception_schemas import (
    ExceptionDecisionRequest,
    ExceptionExpirySweepResponse,
    ExceptionRevokeRequest,
    PolicyExceptionListResponse,
    PolicyExceptionRequestRequest,
    PolicyExceptionResponse,
)
from src.application.use_cases.decide_exception import DecidePolicyExceptionUseCase
from src.application.use_cases.expire_exceptions import ExpireExceptionsUseCase
from src.application.use_cases.request_exception import RequestPolicyExceptionUseCase
from src.application.use_cases.review_exception import ReviewPolicyExceptionUseCase
from src.application.use_cases.revoke_exception import RevokePolicyExceptionUseCase
from src.domain.entities.actor import Actor
from src.domain.enums.exception_status import ExceptionStatus
from src.observability.correlation import get_correlation_id
from src.observability.metrics import exception_events_total

router = APIRouter(prefix="/api/v1/exceptions", tags=["exceptions"])


@router.post("", response_model=PolicyExceptionResponse, status_code=201)
def request_exception(
    payload: PolicyExceptionRequestRequest,
    actor: Actor = Depends(get_actor),
    use_case: RequestPolicyExceptionUseCase = Depends(get_request_exception_use_case),
    _mode=Depends(require_mutation_allowed),
) -> PolicyExceptionResponse:
    created = use_case.execute(
        policy_id=payload.policy_id,
        resource_id=payload.resource_id,
        finding_id=payload.finding_id,
        managed_system_id=payload.managed_system_id,
        business_justification=payload.business_justification,
        risk_statement=payload.risk_statement,
        compensating_controls=tuple(payload.compensating_controls),
        requested_expiration=payload.requested_expiration,
        evidence=tuple(payload.evidence),
        claimed_requester_id=payload.requested_by or actor.actor_id,
        actor=actor,
        correlation_id=get_correlation_id(),
    )
    exception_events_total.labels(event="requested").inc()
    return exception_to_response(created)


@router.get("", response_model=PolicyExceptionListResponse)
def list_exceptions(
    managed_system_id: str | None = Query(default=None),
    status_filter: ExceptionStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    exception_repo=Depends(get_exception_repo),
) -> PolicyExceptionListResponse:
    items, total = exception_repo.list(
        managed_system_id=managed_system_id, status=status_filter, limit=limit, offset=offset
    )
    return PolicyExceptionListResponse(
        items=[exception_to_response(e) for e in items], total=total, limit=limit, offset=offset
    )


@router.get("/{exception_id}", response_model=PolicyExceptionResponse)
def get_exception(exception_id: str, exception_repo=Depends(get_exception_repo)) -> PolicyExceptionResponse:
    return exception_to_response(exception_repo.get(exception_id))


@router.post("/{exception_id}/review", response_model=PolicyExceptionResponse)
def review_exception(
    exception_id: str,
    actor: Actor = Depends(get_actor),
    use_case: ReviewPolicyExceptionUseCase = Depends(get_review_exception_use_case),
    _mode=Depends(require_mutation_allowed),
) -> PolicyExceptionResponse:
    updated = use_case.execute(exception_id, actor=actor, correlation_id=get_correlation_id())
    exception_events_total.labels(event="under_review").inc()
    return exception_to_response(updated)


@router.post("/{exception_id}/decide", response_model=PolicyExceptionResponse)
def decide_exception(
    exception_id: str,
    payload: ExceptionDecisionRequest,
    actor: Actor = Depends(get_actor),
    use_case: DecidePolicyExceptionUseCase = Depends(get_decide_exception_use_case),
    _mode=Depends(require_normal_mode_for_evaluation),
) -> PolicyExceptionResponse:
    updated = use_case.execute(
        exception_id,
        approve=payload.approve,
        rationale=payload.rationale,
        actor=actor,
        correlation_id=get_correlation_id(),
    )
    exception_events_total.labels(event="approved" if payload.approve else "rejected").inc()
    return exception_to_response(updated)


@router.post("/{exception_id}/revoke", response_model=PolicyExceptionResponse)
def revoke_exception(
    exception_id: str,
    payload: ExceptionRevokeRequest,
    actor: Actor = Depends(get_actor),
    use_case: RevokePolicyExceptionUseCase = Depends(get_revoke_exception_use_case),
    _mode=Depends(require_mutation_allowed),
) -> PolicyExceptionResponse:
    updated = use_case.execute(
        exception_id, reason=payload.reason, actor=actor, correlation_id=get_correlation_id()
    )
    exception_events_total.labels(event="revoked").inc()
    return exception_to_response(updated)


@router.post("/expire-sweep", response_model=ExceptionExpirySweepResponse)
def expire_exceptions(
    actor: Actor = Depends(get_actor),
    use_case: ExpireExceptionsUseCase = Depends(get_expire_exceptions_use_case),
    _mode=Depends(require_mutation_allowed),
) -> ExceptionExpirySweepResponse:
    expired = use_case.execute(actor=actor, correlation_id=get_correlation_id())
    if expired:
        exception_events_total.labels(event="expired").inc(len(expired))
    return ExceptionExpirySweepResponse(expired=[exception_to_response(e) for e in expired])
