from __future__ import annotations

from enum import Enum


class InvalidStateTransitionError(Exception):
    """Shared, fail-closed transition error for every state machine in this
    package. Any transition not explicitly present in an ALLOWED_TRANSITIONS
    table raises this — there is no default-allow path."""

    def __init__(self, entity: str, current: Enum, target: Enum) -> None:
        self.entity = entity
        self.current = current
        self.target = target
        super().__init__(f"invalid {entity} transition: {current.value} -> {target.value}")
