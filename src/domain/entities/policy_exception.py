from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from src.domain.enums.exception_status import ExceptionStatus


@dataclass(frozen=True, slots=True)
class ExceptionApproval:
    """One review decision recorded against a PolicyException."""

    approval_id: str
    exception_id: str
    decision: str  # "APPROVED" | "REJECTED"
    rationale: str
    decided_by: str
    decided_role: str
    decided_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class PolicyException:
    """A request to temporarily accept a policy violation as risk, with the
    full lifecycle and required fields from spec section 12.

    `requested_by` is always the authenticated actor id resolved at the API
    boundary — never a client-supplied field — enforced in
    src/application/services/exception_authorization.py.

    `(policy_id, resource_id)` -- not `finding_id` -- is the suppression key
    used by later re-evaluations: finding ids are regenerated on every
    evaluation run, so an exception must key off the stable policy+resource
    pair to keep suppressing (or, once EXPIRED/REVOKED, to stop suppressing)
    the same underlying violation across runs.
    """

    exception_id: str
    policy_id: str
    resource_id: str
    finding_id: str
    managed_system_id: str
    business_justification: str
    risk_statement: str
    compensating_controls: tuple[str, ...]
    requested_expiration: datetime
    requested_by: str
    evidence: tuple[str, ...]
    correlation_id: str
    status: ExceptionStatus = ExceptionStatus.REQUESTED
    approvals: tuple[ExceptionApproval, ...] = ()
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    activated_at: datetime | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    revoked_by: str | None = None
    revoked_reason: str | None = None

    @property
    def is_currently_active(self) -> bool:
        return self.status == ExceptionStatus.ACTIVE

    def with_status(self, status: ExceptionStatus, **extra) -> PolicyException:
        import dataclasses

        return dataclasses.replace(self, status=status, **extra)
