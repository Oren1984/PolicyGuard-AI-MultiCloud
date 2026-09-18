from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from src.domain.enums.actor_role import ActorRole


@dataclass(frozen=True, slots=True)
class Actor:
    """An authenticated actor. In this POC, identity is resolved from a
    header at the API boundary (documented boundary — see docs/SECURITY.md
    in a later phase) and passed down as this trusted value object; it must
    never be reconstructed from client-supplied body fields below the API
    layer."""

    actor_id: str
    display_name: str
    role: ActorRole


@dataclass(frozen=True, slots=True)
class CorrelationContext:
    """Threaded through every use case and audit event so a single workflow
    (e.g. one evaluation run) can be traced end to end."""

    correlation_id: str
    initiated_by: str
    initiated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
