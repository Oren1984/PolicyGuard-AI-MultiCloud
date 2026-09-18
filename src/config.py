"""Centralized, pydantic-settings-based configuration for the API layer.

Every environment-variable read for the running application goes through
this module. `src/adapters/persistence/db.py` (Phase 2) has its own local
`DATABASE_URL` reader for adapter-level use outside the API process (e.g. a
future migration/demo script run directly against the adapter); the API
layer itself always resolves the database URL through `Settings.database_url`
below so there is exactly one source of truth for a running server process.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="POLICYGUARD_", env_file=".env", extra="ignore")

    environment: str = "local"
    log_level: str = "INFO"

    database_url: str = "postgresql+psycopg://policyguard:policyguard@localhost:5432/policyguard"

    ai_provider: Literal["mock", "external"] = "mock"
    ai_external_base_url: str | None = None
    ai_external_api_key: str | None = None

    confidence_approval_threshold: float = 0.70
    confidence_hard_floor: float = 0.35

    # Seeded once at startup if no kill-switch row exists yet (spec section
    # 13). Changing this after the first row is created has no further
    # effect -- use the admin kill-switch endpoint to change mode at runtime.
    kill_switch_default_mode: Literal["normal", "paused", "emergency_stop"] = "normal"

    max_payload_bytes: int = Field(default=1_000_000, description="Max inbound JSON payload size in bytes.")

    cors_allow_origins: list[str] = Field(default_factory=list)


@lru_cache
def get_settings() -> Settings:
    return Settings()
