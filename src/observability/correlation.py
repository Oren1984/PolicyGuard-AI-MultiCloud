"""Correlation-ID mechanism: a per-request context variable, propagated via
the `X-Correlation-ID` header and threaded into every audit event (spec
sections 14, 17)."""

from __future__ import annotations

import uuid
from contextvars import ContextVar

CORRELATION_HEADER = "X-Correlation-ID"

_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")


def new_correlation_id() -> str:
    return uuid.uuid4().hex


def set_correlation_id(value: str) -> None:
    _correlation_id.set(value)


def get_correlation_id() -> str:
    return _correlation_id.get()
