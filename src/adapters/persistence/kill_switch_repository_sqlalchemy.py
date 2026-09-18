from __future__ import annotations

from sqlalchemy.orm import Session

from src.adapters.persistence.models import KillSwitchStateORM
from src.domain.enums.system_mode import SystemMode
from src.domain.policies.kill_switch_policy import KillSwitchState


class KillSwitchStateUnavailableError(Exception):
    """Raised when the persisted kill-switch state cannot be read reliably
    (e.g. no row has ever been initialized, or the read itself failed).
    Per src/ports/kill_switch_repository.py, callers must treat this the
    same as EMERGENCY_STOP -- never silently default to NORMAL."""


class SqlAlchemyKillSwitchRepository:
    """Single-row PostgreSQL-backed kill-switch state (spec section 13)."""

    _ROW_ID = 1

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_state(self) -> KillSwitchState:
        try:
            orm = self._session.get(KillSwitchStateORM, self._ROW_ID)
        except Exception as exc:
            raise KillSwitchStateUnavailableError(f"failed to read kill-switch state: {exc}") from exc
        if orm is None:
            raise KillSwitchStateUnavailableError(
                "no kill-switch state has ever been initialized; treat this as EMERGENCY_STOP"
            )
        return KillSwitchState(
            mode=SystemMode(orm.mode),
            changed_by=orm.changed_by,
            reason=orm.reason,
            changed_at=orm.changed_at,
        )

    def set_state(self, state: KillSwitchState) -> KillSwitchState:
        orm = self._session.get(KillSwitchStateORM, self._ROW_ID)
        if orm is None:
            orm = KillSwitchStateORM(id=self._ROW_ID)
            self._session.add(orm)
        orm.mode = state.mode.value
        orm.changed_by = state.changed_by
        orm.reason = state.reason
        orm.changed_at = state.changed_at
        self._session.commit()
        return state
