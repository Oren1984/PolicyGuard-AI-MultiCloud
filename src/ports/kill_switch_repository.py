from __future__ import annotations

from typing import Protocol

from src.domain.policies.kill_switch_policy import KillSwitchState


class KillSwitchRepository(Protocol):
    def get_state(self) -> KillSwitchState:
        """Must fail closed: if the mode cannot be determined reliably,
        implementations should raise rather than silently default to
        NORMAL. Callers should treat any such failure as EMERGENCY_STOP."""
        ...

    def set_state(self, state: KillSwitchState) -> KillSwitchState: ...
