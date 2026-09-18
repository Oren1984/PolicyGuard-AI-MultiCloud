"""Optional external AI provider adapter (spec section 10).

Disabled unless explicitly configured: construction raises AIProviderError
immediately if `AI_EXTERNAL_BASE_URL` and `AI_EXTERNAL_API_KEY` are not both
supplied (via constructor arguments or environment variables), so a
misconfiguration is caught at wiring time rather than at first use. No
default execution path, and no automated check in this repository, depends
on this adapter making a real network call.

Uses only the Python standard library (urllib) -- no extra HTTP client
dependency for what must stay an optional, rarely-exercised code path.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from src.domain.entities.ai_advisory import AIAdvisoryContent
from src.domain.entities.compliance_finding import ComplianceFinding
from src.domain.entities.drift_finding import DriftFinding
from src.ports.ai_provider import AIProviderError

Finding = ComplianceFinding | DriftFinding


class ExternalAIProvider:
    """Implements the AIProvider port by delegating to a remote HTTP
    endpoint. Kept intentionally minimal -- this is an optional, disabled-
    by-default POC boundary, not a production integration."""

    name = "external-ai"

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        base_url = base_url or os.environ.get("AI_EXTERNAL_BASE_URL")
        api_key = api_key or os.environ.get("AI_EXTERNAL_API_KEY")
        if not base_url or not api_key:
            raise AIProviderError(
                "ExternalAIProvider is not configured; set AI_EXTERNAL_BASE_URL and "
                "AI_EXTERNAL_API_KEY, or use MockAIProvider (the default, offline provider)."
            )
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout_seconds = timeout_seconds

    def summarize_findings(
        self, findings: list[Finding], *, correlation_id: str
    ) -> AIAdvisoryContent:
        return self._call(
            "summarize_findings", {"finding_ids": [f.finding_id for f in findings]}, correlation_id
        )

    def explain_impact(self, finding: Finding, *, correlation_id: str) -> AIAdvisoryContent:
        return self._call("explain_impact", {"finding_id": finding.finding_id}, correlation_id)

    def group_related_violations(
        self, findings: list[Finding], *, correlation_id: str
    ) -> AIAdvisoryContent:
        return self._call(
            "group_related_violations", {"finding_ids": [f.finding_id for f in findings]}, correlation_id
        )

    def generate_remediation_outline(
        self, finding: Finding, *, correlation_id: str
    ) -> AIAdvisoryContent:
        return self._call(
            "generate_remediation_outline", {"finding_id": finding.finding_id}, correlation_id
        )

    def _call(self, operation: str, body: dict, correlation_id: str) -> AIAdvisoryContent:
        request_body = {**body, "operation": operation, "correlation_id": correlation_id}
        req = urllib.request.Request(
            url=f"{self._base_url}/v1/policyguard/{operation}",
            data=json.dumps(request_body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout_seconds) as resp:
                raw = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise AIProviderError(f"external AI provider request failed: {exc}") from exc

        try:
            return AIAdvisoryContent(
                provider_name=self.name,
                kind=str(raw["kind"]),
                content=str(raw["content"]),
                referenced_evidence=tuple(raw.get("referenced_evidence", [])),
                confidence=float(raw.get("confidence", 0.0)),
                raw_response=raw,
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise AIProviderError(f"external AI provider returned an unparsable response: {exc}") from exc
