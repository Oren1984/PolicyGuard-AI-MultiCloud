"""Audit and operations capability group (spec section 14/15): query audit
events and verify the hash chain. Read-only -- always available, even under
EMERGENCY_STOP (spec section 13: "audit verification ... remain available")."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from src.api.dependencies.repositories import get_audit_repo
from src.api.dependencies.use_cases import get_verify_audit_chain_use_case
from src.api.routes._converters import audit_event_to_response
from src.api.schemas.audit_schemas import AuditEventListResponse, AuditVerificationResponse
from src.application.use_cases.audit_use_cases import VerifyAuditChainUseCase
from src.observability.metrics import audit_chain_valid

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("/events", response_model=AuditEventListResponse)
def list_audit_events(
    limit: int = Query(default=50, ge=1, le=500),
    resource_type: str | None = Query(default=None),
    resource_id: str | None = Query(default=None),
    audit_repo=Depends(get_audit_repo),
) -> AuditEventListResponse:
    if resource_type is not None and resource_id is not None:
        events = audit_repo.list_for_resource(resource_type, resource_id)
    else:
        events = audit_repo.list_recent(limit=limit)
    return AuditEventListResponse(items=[audit_event_to_response(e) for e in events])


@router.get("/verify", response_model=AuditVerificationResponse)
def verify_audit_chain(
    use_case: VerifyAuditChainUseCase = Depends(get_verify_audit_chain_use_case),
) -> AuditVerificationResponse:
    report = use_case.execute()
    audit_chain_valid.set(1 if report.result.is_valid else 0)
    return AuditVerificationResponse(
        is_valid=report.result.is_valid,
        total_records=report.result.total_records,
        first_invalid_sequence=report.result.first_invalid_sequence,
        reason=report.result.reason,
        verified_at=report.verified_at,
    )
