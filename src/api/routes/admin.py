"""Administration capability group (spec section 15): get system mode,
update kill-switch state, retrieve system status.

The kill-switch endpoints deliberately never depend on
`require_mutation_allowed` / `require_normal_mode_for_evaluation` -- see
`src/api/dependencies/kill_switch_gate.py`'s module docstring: an operator
must always be able to change mode, including out of EMERGENCY_STOP.
`KillSwitchUseCase.set_mode` enforces its own independent role check
(`can_change_kill_switch`, mapped to HTTP 403 in `src/main.py`)."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from src.api.dependencies.actor import get_actor
from src.api.dependencies.repositories import (
    get_audit_repo,
    get_compliance_finding_repo,
    get_drift_finding_repo,
    get_exception_repo,
    get_managed_system_repo,
)
from src.api.dependencies.use_cases import get_kill_switch_use_case
from src.api.schemas.admin_schemas import (
    KillSwitchChangeRequest,
    KillSwitchStateResponse,
    SystemStatusResponse,
)
from src.application.use_cases.kill_switch import KillSwitchUseCase
from src.config import Settings, get_settings
from src.domain.entities.actor import Actor
from src.domain.enums.exception_status import ExceptionStatus
from src.domain.enums.finding_status import FindingStatus
from src.domain.enums.system_mode import SystemMode
from src.observability.correlation import get_correlation_id
from src.observability.metrics import audit_chain_valid

router = APIRouter(prefix="/api/v1/admin", tags=["administration"])


@router.get("/kill-switch", response_model=KillSwitchStateResponse)
def get_kill_switch_state(
    use_case: KillSwitchUseCase = Depends(get_kill_switch_use_case),
) -> KillSwitchStateResponse:
    state = use_case.get_mode()
    return KillSwitchStateResponse(
        mode=state.mode.value, changed_by=state.changed_by, reason=state.reason, changed_at=state.changed_at
    )


@router.post("/kill-switch", response_model=KillSwitchStateResponse)
def set_kill_switch_state(
    payload: KillSwitchChangeRequest,
    actor: Actor = Depends(get_actor),
    use_case: KillSwitchUseCase = Depends(get_kill_switch_use_case),
) -> KillSwitchStateResponse:
    state = use_case.set_mode(
        SystemMode(payload.mode), reason=payload.reason, actor=actor, correlation_id=get_correlation_id()
    )
    return KillSwitchStateResponse(
        mode=state.mode.value, changed_by=state.changed_by, reason=state.reason, changed_at=state.changed_at
    )


@router.get("/status", response_model=SystemStatusResponse)
def system_status(
    managed_system_repo=Depends(get_managed_system_repo),
    compliance_finding_repo=Depends(get_compliance_finding_repo),
    drift_finding_repo=Depends(get_drift_finding_repo),
    exception_repo=Depends(get_exception_repo),
    audit_repo=Depends(get_audit_repo),
    kill_switch_use_case: KillSwitchUseCase = Depends(get_kill_switch_use_case),
    settings: Settings = Depends(get_settings),
) -> SystemStatusResponse:
    _, system_total = managed_system_repo.list(limit=1)

    compliance_counts: dict[str, int] = {}
    for finding_status in FindingStatus:
        _, total = compliance_finding_repo.list(status=finding_status, limit=1)
        compliance_counts[finding_status.value] = total

    drift_counts: dict[str, int] = {}
    for finding_status in FindingStatus:
        _, total = drift_finding_repo.list(status=finding_status, limit=1)
        drift_counts[finding_status.value] = total

    exception_counts: dict[str, int] = {}
    for exception_status in ExceptionStatus:
        _, total = exception_repo.list(status=exception_status, limit=1)
        exception_counts[exception_status.value] = total

    verification = audit_repo.verify_chain()
    audit_chain_valid.set(1 if verification.is_valid else 0)

    kill_switch_state = kill_switch_use_case.get_mode()

    return SystemStatusResponse(
        status="ok",
        environment=settings.environment,
        ai_provider=settings.ai_provider,
        kill_switch_mode=kill_switch_state.mode.value,
        audit_chain_valid=verification.is_valid,
        managed_system_count=system_total,
        compliance_finding_counts_by_status=compliance_counts,
        drift_finding_counts_by_status=drift_counts,
        exception_counts_by_status=exception_counts,
    )
