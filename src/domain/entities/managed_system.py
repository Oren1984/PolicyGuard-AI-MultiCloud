from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from src.domain.enums.cloud_provider import CloudProvider
from src.domain.enums.environment import Environment
from src.domain.enums.resource_criticality import ResourceCriticality


@dataclass(frozen=True, slots=True)
class ManagedSystem:
    """A registered system under continuous governance: the unit that
    desired/observed snapshots, findings, decisions, and exceptions are
    scoped to."""

    system_id: str
    name: str
    cloud_provider: CloudProvider
    environment: Environment
    owner_actor_id: str
    criticality: ResourceCriticality = ResourceCriticality.STANDARD
    description: str = ""
    tags: dict[str, str] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def is_production(self) -> bool:
        return self.environment == Environment.PRODUCTION
