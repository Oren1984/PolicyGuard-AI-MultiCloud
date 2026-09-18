from __future__ import annotations

from typing import Protocol

from src.domain.entities.managed_system import ManagedSystem


class ManagedSystemNotFoundError(Exception):
    pass


class ManagedSystemRepository(Protocol):
    def create(self, system: ManagedSystem) -> ManagedSystem: ...

    def get(self, system_id: str) -> ManagedSystem:
        """Raises ManagedSystemNotFoundError if absent."""
        ...

    def exists(self, system_id: str) -> bool: ...

    def list(self, *, limit: int = 50, offset: int = 0) -> tuple[list[ManagedSystem], int]: ...
