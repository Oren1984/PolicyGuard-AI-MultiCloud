"""Kill-switch mode gating for mutating routes (spec section 13).

Deliberate Phase 3 addition beyond the five DI-wiring modules named in the
build brief (actor/db/providers/repositories/use_cases): the brief itself
asks for this gate to be implemented "as a dependency/middleware check
applied to mutating routes." A dependency is the natural FastAPI mechanism
for this -- it is selectively attachable per-route (unlike ASGI middleware,
which would need its own path-matching logic to distinguish mutating routes
from reads) and composes with the rest of the DI graph.

Two gate levels, matching the two behaviors spec section 13 actually
distinguishes:

- `require_mutation_allowed`: blocks only in EMERGENCY_STOP. Used on
  mutating routes that are not themselves "a new evaluation or approval"
  (e.g. registering a system, submitting a snapshot, requesting/revoking an
  exception, updating remediation status).
- `require_normal_mode_for_evaluation`: blocks in PAUSED or EMERGENCY_STOP.
  Used on routes that start a new evaluation or record an approval
  (evaluate-policy-pack, generate-governance-decision, decide-exception).

`EvaluatePolicyPackUseCase` and `DetectDriftUseCase` (Phase 1) already
perform their own equivalent check internally and raise
`EvaluationBlockedError` / `DriftDetectionBlockedError` -- routes that call
those two use cases rely on that existing check (mapped to HTTP 503 in
`src/main.py`) instead of duplicating it here, so there is exactly one
source of truth for those two code paths. Every other mutating route -- the
exception workflow, remediation, finding-status, and governance-decision
routes -- has no such built-in check in Phase 1's use cases, so this module
is what enforces it for them.

The kill-switch admin endpoint itself (`POST /api/v1/admin/kill-switch`)
deliberately never depends on either gate below: it must remain reachable
in every mode, including EMERGENCY_STOP, so an authorized operator can turn
the system back to NORMAL. Its own role check
(`can_change_kill_switch`, enforced inside `KillSwitchUseCase`) is
independent of system mode.
"""

from __future__ import annotations

from fastapi import Depends, HTTPException, status

from src.adapters.persistence.kill_switch_repository_sqlalchemy import (
    KillSwitchStateUnavailableError,
    SqlAlchemyKillSwitchRepository,
)
from src.api.dependencies.repositories import get_kill_switch_repo
from src.domain.enums.system_mode import SystemMode


def _read_mode_fail_closed(kill_switch_repo: SqlAlchemyKillSwitchRepository) -> SystemMode:
    """Fail closed per spec section 13: if the mode cannot be read reliably,
    treat it as EMERGENCY_STOP rather than defaulting to NORMAL."""
    try:
        return kill_switch_repo.get_state().mode
    except KillSwitchStateUnavailableError:
        return SystemMode.EMERGENCY_STOP


def require_mutation_allowed(
    kill_switch_repo: SqlAlchemyKillSwitchRepository = Depends(get_kill_switch_repo),
) -> SystemMode:
    mode = _read_mode_fail_closed(kill_switch_repo)
    if mode == SystemMode.EMERGENCY_STOP:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="all mutating workflow actions are blocked while the kill switch is EMERGENCY_STOP",
        )
    return mode


def require_normal_mode_for_evaluation(
    kill_switch_repo: SqlAlchemyKillSwitchRepository = Depends(get_kill_switch_repo),
) -> SystemMode:
    mode = _read_mode_fail_closed(kill_switch_repo)
    if mode != SystemMode.NORMAL:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"new evaluations and approvals are blocked while mode={mode.value}",
        )
    return mode
