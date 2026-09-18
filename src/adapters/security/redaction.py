"""Secret/token/connection-string redaction for logs, error responses, and
audit payloads (spec sections 14, 18).

This is a best-effort, defense-in-depth layer -- not a substitute for never
putting secrets into these payloads in the first place. Every audit payload
and persisted error message constructed in src/adapters must pass through
`redact_mapping` (dict payloads) or `redact_value` (free-text strings)
before it is canonicalized, hashed, logged, or stored.
"""

from __future__ import annotations

import re
from typing import Any

_SENSITIVE_KEY_PATTERN = re.compile(
    r"(pass(word)?|secret|token|api[_-]?key|authorization|credential|private[_-]?key"
    r"|connection[_-]?string)",
    re.IGNORECASE,
)
_BEARER_PATTERN = re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE)
_AWS_KEY_PATTERN = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
# Redacts the password portion of a connection string such as
# postgresql://user:password@host:5432/db -- keeps the scheme/user/host
# visible (useful for diagnosing which DB was targeted) while removing the
# credential itself.
_CONNECTION_STRING_PATTERN = re.compile(r"([a-zA-Z][\w+]*://[^:/\s@]+):([^@/\s]+)@")

REDACTED = "***REDACTED***"


def redact_value(value: str) -> str:
    """Scrubs known secret/credential patterns out of a free-text string."""
    value = _BEARER_PATTERN.sub(f"Bearer {REDACTED}", value)
    value = _AWS_KEY_PATTERN.sub(REDACTED, value)
    value = _CONNECTION_STRING_PATTERN.sub(rf"\1:{REDACTED}@", value)
    return value


def redact_mapping(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively redacts values whose key looks sensitive, and scrubs known
    secret patterns out of remaining string values (including inside lists).
    Used on every audit payload before it is canonicalized/hashed/stored."""
    result: dict[str, Any] = {}
    for key, value in data.items():
        if _SENSITIVE_KEY_PATTERN.search(str(key)):
            result[key] = REDACTED
        elif isinstance(value, dict):
            result[key] = redact_mapping(value)
        elif isinstance(value, list):
            result[key] = [redact_mapping(v) if isinstance(v, dict) else _redact_scalar(v) for v in value]
        else:
            result[key] = _redact_scalar(value)
    return result


def _redact_scalar(value: Any) -> Any:
    if isinstance(value, str):
        return redact_value(value)
    return value
