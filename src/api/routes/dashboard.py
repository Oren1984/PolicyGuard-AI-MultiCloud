"""Read-only, server-rendered governance dashboard (spec section 16). No SPA,
no client-side framework -- Jinja2 templates rendered from repository reads
only. Aggregations (severity/provider/category/drift-type breakdowns) are
computed here in Python over a bounded page of recent records rather than by
adding new repository query methods -- adequate for a lean demo dashboard,
not a production analytics view.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from src.adapters.persistence.kill_switch_repository_sqlalchemy import KillSwitchStateUnavailableError
from src.api.dependencies.repositories import (
    get_audit_repo,
    get_compliance_finding_repo,
    get_decision_repo,
    get_drift_finding_repo,
    get_exception_repo,
    get_kill_switch_repo,
    get_managed_system_repo,
    get_remediation_repo,
)
from src.config import Settings, get_settings
from src.domain.enums.exception_status import ExceptionStatus

router = APIRouter(tags=["dashboard"])

_TEMPLATES_DIR = Path(__file__).resolve().parents[3] / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

_EXPIRING_SOON_WINDOW_DAYS = 7


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    managed_system_repo=Depends(get_managed_system_repo),
    compliance_finding_repo=Depends(get_compliance_finding_repo),
    drift_finding_repo=Depends(get_drift_finding_repo),
    decision_repo=Depends(get_decision_repo),
    exception_repo=Depends(get_exception_repo),
    remediation_repo=Depends(get_remediation_repo),
    audit_repo=Depends(get_audit_repo),
    kill_switch_repo=Depends(get_kill_switch_repo),
    settings: Settings = Depends(get_settings),
) -> HTMLResponse:
    systems, system_total = managed_system_repo.list(limit=200)
    system_by_id = {s.system_id: s for s in systems}

    compliance_findings, compliance_total = compliance_finding_repo.list(limit=500)
    drift_findings, drift_total = drift_finding_repo.list(limit=500)

    severity_counts: dict[str, int] = {}
    provider_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    drift_type_counts: dict[str, int] = {}

    def _tally_provider_severity(finding) -> None:
        severity_counts[finding.severity.label] = severity_counts.get(finding.severity.label, 0) + 1
        system = system_by_id.get(finding.managed_system_id)
        provider_label = system.cloud_provider.value if system else "unknown"
        provider_counts[provider_label] = provider_counts.get(provider_label, 0) + 1

    for f in compliance_findings:
        _tally_provider_severity(f)
        category_counts[f.category.value] = category_counts.get(f.category.value, 0) + 1
    for f in drift_findings:
        _tally_provider_severity(f)
        drift_type_counts[f.drift_type.value] = drift_type_counts.get(f.drift_type.value, 0) + 1

    decisions, decision_total = decision_repo.list(limit=200)
    decision_counts: dict[str, int] = {}
    for d in decisions:
        decision_counts[d.decision.value] = decision_counts.get(d.decision.value, 0) + 1

    active_exceptions, active_exception_total = exception_repo.list(status=ExceptionStatus.ACTIVE, limit=100)
    now = datetime.now(UTC)
    soon = now + timedelta(days=_EXPIRING_SOON_WINDOW_DAYS)
    expiring_soon = [e for e in active_exceptions if e.expires_at and now <= e.expires_at <= soon]

    # Exceptions still awaiting a human decision -- the review queue. Not an
    # aggregation over findings/decisions (EXCEPTION_REVIEW_REQUIRED is a
    # theoretical DecisionType a finding-level decision never actually
    # reaches, since only APPROVED/ACTIVE/EXPIRED/REVOKED exceptions feed
    # into decision routing -- see ExceptionRepository.list_active_for_system's
    # own docstring); this reads the exception records directly instead,
    # which is what a human reviewer actually needs to see.
    requested_exceptions, requested_total = exception_repo.list(status=ExceptionStatus.REQUESTED, limit=100)
    under_review_exceptions, under_review_total = exception_repo.list(
        status=ExceptionStatus.UNDER_REVIEW, limit=100
    )
    pending_review_exceptions = list(requested_exceptions) + list(under_review_exceptions)
    pending_review_total = requested_total + under_review_total

    remediation_plans, _ = remediation_repo.list(limit=200)
    remediation_status_counts: dict[str, int] = {}
    for p in remediation_plans:
        remediation_status_counts[p.status.value] = remediation_status_counts.get(p.status.value, 0) + 1

    verification = audit_repo.verify_chain()
    recent_events = audit_repo.list_recent(limit=15)

    try:
        kill_switch_state = kill_switch_repo.get_state()
    except KillSwitchStateUnavailableError:
        kill_switch_state = None  # fail closed: dashboard renders this as EMERGENCY_STOP-equivalent

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "system_total": system_total,
            "systems": systems,
            "severity_counts": severity_counts,
            "provider_counts": provider_counts,
            "category_counts": category_counts,
            "drift_type_counts": drift_type_counts,
            "compliance_total": compliance_total,
            "drift_total": drift_total,
            "decision_counts": decision_counts,
            "active_exceptions": active_exceptions,
            "active_exception_total": active_exception_total,
            "expiring_soon": expiring_soon,
            "pending_review_exceptions": pending_review_exceptions,
            "pending_review_total": pending_review_total,
            "remediation_status_counts": remediation_status_counts,
            "verification": verification,
            "recent_events": recent_events,
            "kill_switch_state": kill_switch_state,
            "demo_mode": settings.demo_mode,
        },
    )
