from __future__ import annotations

from typing import Protocol

from src.domain.entities.policy import Policy, PolicyPack


class PolicyNotFoundError(Exception):
    pass


class PolicyPackNotFoundError(Exception):
    pass


class PolicyRepository(Protocol):
    def create(self, policy: Policy) -> Policy: ...

    def get(self, policy_id: str) -> Policy:
        """Raises PolicyNotFoundError if absent."""
        ...

    def list(self, *, active_only: bool = False) -> list[Policy]: ...

    def set_active(self, policy_id: str, active: bool) -> Policy: ...


class PolicyPackRepository(Protocol):
    def create(self, pack: PolicyPack) -> PolicyPack: ...

    def get(self, pack_id: str) -> PolicyPack:
        """Raises PolicyPackNotFoundError if absent."""
        ...

    def list(self, *, active_only: bool = False) -> list[PolicyPack]: ...

    def set_active(self, pack_id: str, active: bool) -> PolicyPack: ...
