"""Structured JSON logging (spec section 17), correlation-tagged and
secret-redacted. Reuses Phase 2's `src/adapters/security/redaction.py`
rather than introducing a second redaction implementation under
`src/security/` -- see that module's docstring for the redaction contract
already applied to audit payloads; this filter applies the same
`redact_value` to free-text log messages so logs never leak what audit
payloads are already protected against.
"""

from __future__ import annotations

import logging
import sys

from pythonjsonlogger import jsonlogger

from src.adapters.security.redaction import redact_value
from src.observability.correlation import get_correlation_id


class _CorrelationAndRedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.correlation_id = get_correlation_id() or "-"
        if isinstance(record.msg, str):
            record.msg = redact_value(record.msg)
        return True


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    root.setLevel(level)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    formatter = jsonlogger.JsonFormatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(correlation_id)s %(message)s"
    )
    handler.setFormatter(formatter)
    handler.addFilter(_CorrelationAndRedactionFilter())
    root.addHandler(handler)

    # Keep third-party access logs at the same structured format but quieter.
    logging.getLogger("uvicorn.access").setLevel("WARNING")
