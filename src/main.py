"""FastAPI application factory and entrypoint for PolicyGuard AI MultiCloud.

Wires together every router built for this phase, a correlation-ID +
payload-size-limit middleware, structured error handling that never leaks
stack traces or secrets (spec section 18), and a startup hook that seeds the
kill switch's single row on first run (mirrors the sibling ChangeGuard
project's `_seed_kill_switch_default`) so `GET /api/v1/admin/kill-switch`
and every kill-switch-gated route have a deterministic starting mode rather
than immediately hitting the fail-closed "unavailable" path on a fresh
database. Real Alembic migrations are Phase 4's responsibility -- this
module deliberately does not call `Base.metadata.create_all()` itself, so a
missing migration surfaces as a clear failure rather than being silently
papered over at every app boot.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from src.adapters.persistence.kill_switch_repository_sqlalchemy import KillSwitchStateUnavailableError
from src.adapters.security.redaction import redact_value
from src.api.routes import admin, audit, dashboard, exceptions, findings, health, policies, systems
from src.application.services.exception_authorization import ExceptionAuthorizationError
from src.application.use_cases.detect_drift import DriftDetectionBlockedError, DriftMissingSnapshotError
from src.application.use_cases.evaluate_policy_pack import EvaluationBlockedError
from src.application.use_cases.kill_switch import UnauthorizedKillSwitchChangeError
from src.config import get_settings
from src.domain.enums.system_mode import SystemMode
from src.domain.policies.kill_switch_policy import KillSwitchState
from src.domain.state_machine.errors import InvalidStateTransitionError
from src.observability.correlation import CORRELATION_HEADER, new_correlation_id, set_correlation_id
from src.observability.logging import configure_logging
from src.observability.metrics import http_errors_total
from src.ports.ai_provider import AIProviderError
from src.ports.audit_repository import AuditPersistenceError
from src.ports.cloud_inventory_provider import CloudInventoryProviderError
from src.ports.decision_repository import GovernanceDecisionNotFoundError
from src.ports.exception_repository import PolicyExceptionNotFoundError
from src.ports.finding_repository import FindingNotFoundError
from src.ports.managed_system_repository import ManagedSystemNotFoundError
from src.ports.policy_repository import PolicyNotFoundError, PolicyPackNotFoundError
from src.ports.remediation_repository import RemediationPlanNotFoundError
from src.ports.snapshot_repository import SnapshotNotFoundError

_STATIC_DIR = Path(__file__).resolve().parents[1] / "static"

_ERROR_STATUS_MAP: dict[type[Exception], int] = {
    ManagedSystemNotFoundError: status.HTTP_404_NOT_FOUND,
    SnapshotNotFoundError: status.HTTP_404_NOT_FOUND,
    PolicyNotFoundError: status.HTTP_404_NOT_FOUND,
    PolicyPackNotFoundError: status.HTTP_404_NOT_FOUND,
    FindingNotFoundError: status.HTTP_404_NOT_FOUND,
    GovernanceDecisionNotFoundError: status.HTTP_404_NOT_FOUND,
    PolicyExceptionNotFoundError: status.HTTP_404_NOT_FOUND,
    RemediationPlanNotFoundError: status.HTTP_404_NOT_FOUND,
    InvalidStateTransitionError: status.HTTP_409_CONFLICT,
    DriftMissingSnapshotError: status.HTTP_409_CONFLICT,
    ExceptionAuthorizationError: status.HTTP_403_FORBIDDEN,
    UnauthorizedKillSwitchChangeError: status.HTTP_403_FORBIDDEN,
    EvaluationBlockedError: status.HTTP_503_SERVICE_UNAVAILABLE,
    DriftDetectionBlockedError: status.HTTP_503_SERVICE_UNAVAILABLE,
    KillSwitchStateUnavailableError: status.HTTP_503_SERVICE_UNAVAILABLE,
    CloudInventoryProviderError: status.HTTP_503_SERVICE_UNAVAILABLE,
    AIProviderError: status.HTTP_503_SERVICE_UNAVAILABLE,
    AuditPersistenceError: status.HTTP_500_INTERNAL_SERVER_ERROR,
    ValueError: status.HTTP_422_UNPROCESSABLE_ENTITY,
}


def _seed_kill_switch_default(settings) -> None:
    from src.adapters.persistence.db import get_sessionmaker
    from src.adapters.persistence.kill_switch_repository_sqlalchemy import SqlAlchemyKillSwitchRepository
    from src.adapters.persistence.models import KillSwitchStateORM

    session = get_sessionmaker(settings.database_url)()
    try:
        if session.get(KillSwitchStateORM, 1) is None:
            SqlAlchemyKillSwitchRepository(session).set_state(
                KillSwitchState(mode=SystemMode(settings.kill_switch_default_mode), reason="startup default")
            )
    finally:
        session.close()


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        try:
            _seed_kill_switch_default(settings)
        except Exception:  # pragma: no cover - defensive: DB may be unreachable at import time
            # Fail open on *seeding* only (never on serving requests): if the
            # database isn't reachable yet at boot, every kill-switch-gated
            # route still fails closed per-request via
            # KillSwitchStateUnavailableError -> EMERGENCY_STOP-equivalent.
            pass
        yield

    app = FastAPI(
        title="PolicyGuard AI MultiCloud",
        description="Continuous Policy, Drift & Compliance Governance POC",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def correlation_and_size_guard(request: Request, call_next):
        correlation_id = request.headers.get(CORRELATION_HEADER) or new_correlation_id()
        set_correlation_id(correlation_id)

        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > settings.max_payload_bytes:
            return JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content={
                    "error": "payload_too_large",
                    "detail": f"payload exceeds the {settings.max_payload_bytes} byte limit",
                    "correlation_id": correlation_id,
                },
            )

        response: Response = await call_next(request)
        response.headers[CORRELATION_HEADER] = correlation_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    for exc_type, status_code in _ERROR_STATUS_MAP.items():

        def _make_handler(code: int):
            async def _handler(request: Request, exc: Exception) -> JSONResponse:
                http_errors_total.labels(status_code=str(code)).inc()
                return JSONResponse(
                    status_code=code,
                    content={
                        "error": type(exc).__name__,
                        # Never leak stack traces or secrets to clients (spec
                        # section 18) -- redact_value scrubs known
                        # secret/token/connection-string patterns even from
                        # an exception's own message.
                        "detail": redact_value(str(exc)),
                        "correlation_id": request.headers.get(CORRELATION_HEADER, ""),
                    },
                )

            return _handler

        app.add_exception_handler(exc_type, _make_handler(status_code))

    @app.exception_handler(Exception)
    async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        # Fail closed and never leak stack traces or internals to clients.
        http_errors_total.labels(status_code="500").inc()
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "internal_error",
                "detail": "an unexpected error occurred",
                "correlation_id": request.headers.get(CORRELATION_HEADER, ""),
            },
        )

    app.include_router(health.router)
    app.include_router(systems.router)
    app.include_router(policies.router)
    app.include_router(findings.router)
    app.include_router(exceptions.router)
    app.include_router(admin.router)
    app.include_router(audit.router)
    app.include_router(dashboard.router)

    if _STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    return app


app = create_app()
