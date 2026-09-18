from __future__ import annotations

from typing import Protocol

from src.domain.entities.state_snapshot import ObservedStateSnapshot
from src.domain.enums.cloud_provider import CloudProvider
from src.domain.enums.environment import Environment


class CloudInventoryProviderError(Exception):
    """Raised when inventory cannot be fetched. Callers must fail closed —
    never fabricate an observed snapshot when the provider is unavailable."""


class CloudInventoryProvider(Protocol):
    """Boundary a later phase's AWS/GCP mock (and optionally real) adapters
    implement. Real cloud credentials are never required for this POC —
    the default and only phase-1-relevant implementations are deterministic
    offline mocks; any real-provider adapter must stay behind this same
    interface and remain disabled unless explicitly configured.

    Implementations are solely responsible for normalizing provider-
    specific representations into the provider-independent CloudResource /
    ResourceAttributes shape — the domain layer never sees raw AWS or GCP
    payloads.
    """

    provider: CloudProvider

    def fetch_observed_snapshot(
        self,
        *,
        managed_system_id: str,
        environment: Environment,
        correlation_id: str,
    ) -> ObservedStateSnapshot:
        """Return a fresh, normalized observed-state snapshot. Raises
        CloudInventoryProviderError on failure; must never return partial or
        fabricated data silently."""
        ...
