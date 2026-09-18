"""Gate 4 of 5 (spec section 11): rejects destructive, credential-related,
fabricated-authority, or unauthorized instructions in AI advisory content."""

from __future__ import annotations

import re

from src.domain.entities.ai_advisory import AIAdvisoryContent
from src.domain.entities.gate_result import GateResult
from src.domain.enums.gate_name import GateName, GateStatus

# Categorical blocklist: any of these appearing in AI-generated text is an
# automatic hard failure, independent of confidence. Covers destructive
# actions and any attempt by the AI to claim authority it does not have
# (spec section 10: AI must not determine compliance, change severity,
# approve exceptions, close findings, modify resources, or override
# deterministic policies/decisions).
_FORBIDDEN_PATTERNS: tuple[str, ...] = (
    "terraform destroy",
    "drop database",
    "delete production",
    "rm -rf",
    "disable audit",
    "disable logging",
    "suppress logging",
    "disable security",
    "bypass review",
    "bypass approval",
    "auto-remediate",
    "automatically remediate",
    "modify the resource directly",
    "i approve this exception",
    "exception is approved",
    "this finding is closed",
    "mark this finding as compliant",
    "override the governance decision",
    "override the deterministic",
    "ignore the policy",
)

_CREDENTIAL_LIKE_PATTERN = re.compile(
    r"(AKIA[0-9A-Z]{16}|Bearer\s+[A-Za-z0-9\-._~+/]{10,}|password\s*[:=]\s*\S+)", re.IGNORECASE
)


class SafetyGate:
    """AssuranceGate implementation for GateName.SAFETY."""

    def evaluate(self, content: AIAdvisoryContent, *, grounding_context: dict) -> GateResult:
        haystack = content.content.lower()

        hits = [pattern for pattern in _FORBIDDEN_PATTERNS if pattern in haystack]
        if hits:
            return GateResult(
                gate=GateName.SAFETY,
                status=GateStatus.FAILED,
                reason="AI advisory content recommends a categorically unsafe or unauthorized action.",
                details={"matched_patterns": hits},
            )

        if _CREDENTIAL_LIKE_PATTERN.search(content.content):
            return GateResult(
                gate=GateName.SAFETY,
                status=GateStatus.FAILED,
                reason="AI advisory content appears to contain credential-like material.",
            )

        return GateResult(
            gate=GateName.SAFETY,
            status=GateStatus.PASSED,
            reason="No unsafe recommendations or credential-like content detected.",
        )
