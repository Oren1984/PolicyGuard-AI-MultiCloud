from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from src.domain.enums.actor_role import KILL_SWITCH_ROLES, ActorRole
from src.domain.enums.system_mode import SystemMode


@dataclass(frozen=True, slots=True)
class KillSwitchState:
    mode: SystemMode
    changed_by: str | None = None
    reason: str | None = None
    changed_at: datetime = field(default_factory=lambda: datetime.now(UTC))


def can_change_kill_switch(role: ActorRole) -> tuple[bool, str]:
    if role not in KILL_SWITCH_ROLES:
        return False, f"role '{role.value}' is not authorized to change kill-switch state"
    return True, ""


def blocks_new_evaluations(state: KillSwitchState) -> bool:
    """PAUSED and EMERGENCY_STOP both block new evaluations and approvals;
    existing data remains readable in both (spec section 13)."""
    return state.mode in (SystemMode.PAUSED, SystemMode.EMERGENCY_STOP)


def blocks_all_mutations(state: KillSwitchState) -> bool:
    """EMERGENCY_STOP blocks every mutating workflow action, including
    kill-switch reads that fail to resolve reliably must be treated the
    same way by the caller (fail closed)."""
    return state.mode == SystemMode.EMERGENCY_STOP
