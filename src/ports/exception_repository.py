from __future__ import annotations

from datetime import datetime
from typing import Protocol

from src.domain.entities.policy_exception import PolicyException
from src.domain.enums.exception_status import ExceptionStatus


class PolicyExceptionNotFoundError(Exception):
    pass


class PolicyExceptionRepository(Protocol):
    def create(self, exception: PolicyException) -> PolicyException: ...

    def get(self, exception_id: str) -> PolicyException:
        """Raises PolicyExceptionNotFoundError if absent."""
        ...

    def update(self, exception: PolicyException) -> PolicyException: ...

    def list(
        self,
        *,
        managed_system_id: str | None = None,
        status: ExceptionStatus | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[PolicyException], int]: ...

    def list_active_for_system(self, managed_system_id: str) -> list[PolicyException]:
        """Exceptions relevant to policy/drift evaluation: those currently
        suppressing a violation (APPROVED/ACTIVE) or that recently stopped
        doing so (EXPIRED/REVOKED)."""
        ...

    def list_expiring_before(self, cutoff: datetime) -> list[PolicyException]: ...
