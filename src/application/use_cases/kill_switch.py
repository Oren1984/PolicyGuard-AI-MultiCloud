from __future__ import annotations

from src.domain.entities.actor import Actor
from src.domain.enums.system_mode import SystemMode
from src.domain.policies.kill_switch_policy import KillSwitchState, can_change_kill_switch
from src.ports.audit_repository import AuditEventRepository
from src.ports.kill_switch_repository import KillSwitchRepository


class UnauthorizedKillSwitchChangeError(Exception):
    pass


class KillSwitchUseCase:
    """Changes system mode (spec section 13). Requires an authorized role
    and is always audit logged, including denied attempts elsewhere in the
    call chain — this use case itself only proceeds once authorized."""

    def __init__(self, kill_switch_repo: KillSwitchRepository, audit_repo: AuditEventRepository) -> None:
        self._kill_switch_repo = kill_switch_repo
        self._audit_repo = audit_repo

    def get_mode(self) -> KillSwitchState:
        return self._kill_switch_repo.get_state()

    def set_mode(
        self, mode: SystemMode, *, reason: str, actor: Actor, correlation_id: str
    ) -> KillSwitchState:
        allowed, error = can_change_kill_switch(actor.role)
        if not allowed:
            self._audit_repo.append(
                actor=actor.actor_id,
                actor_role=actor.role.value,
                action="KILL_SWITCH_CHANGE_DENIED",
                resource_type="kill_switch",
                resource_id="kill_switch",
                correlation_id=correlation_id,
                payload={"attempted_mode": mode.value, "reason": error},
                outcome="DENIED",
            )
            raise UnauthorizedKillSwitchChangeError(error)

        state = self._kill_switch_repo.set_state(
            KillSwitchState(mode=mode, changed_by=actor.actor_id, reason=reason)
        )
        self._audit_repo.append(
            actor=actor.actor_id,
            actor_role=actor.role.value,
            action="KILL_SWITCH_MODE_CHANGED",
            resource_type="kill_switch",
            resource_id="kill_switch",
            correlation_id=correlation_id,
            payload={"mode": mode.value, "reason": reason},
        )
        return state
