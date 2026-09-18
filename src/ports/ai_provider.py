from __future__ import annotations

from typing import Protocol

from src.domain.entities.ai_advisory import AIAdvisoryContent
from src.domain.entities.compliance_finding import ComplianceFinding
from src.domain.entities.drift_finding import DriftFinding


class AIProviderError(Exception):
    """Raised when a provider cannot produce a result at all (timeout,
    outage, malformed transport response). Callers must fail closed and
    fall back to a deterministic explanation on this."""


class AIProvider(Protocol):
    """Explicit abstraction boundary for any AI backend (mock or external).

    Per spec section 10, an AIProvider may ONLY summarize, explain, group,
    or outline — it is never given a method that determines compliance,
    sets severity, approves an exception, closes a finding, or otherwise
    controls a governance outcome. Every method below returns untrusted
    advisory content that must pass the five AI assurance gates (section
    11 — gate interfaces only in this phase) before it may be shown or
    stored as accepted advisory output.
    """

    name: str

    def summarize_findings(
        self, findings: list[ComplianceFinding | DriftFinding], *, correlation_id: str
    ) -> AIAdvisoryContent:
        """Summarize a set of findings in human-readable language."""
        ...

    def explain_impact(
        self, finding: ComplianceFinding | DriftFinding, *, correlation_id: str
    ) -> AIAdvisoryContent:
        """Explain the architectural/business impact of a single finding."""
        ...

    def group_related_violations(
        self, findings: list[ComplianceFinding | DriftFinding], *, correlation_id: str
    ) -> AIAdvisoryContent:
        """Group related violations (e.g. recurring drift patterns) together."""
        ...

    def generate_remediation_outline(
        self, finding: ComplianceFinding | DriftFinding, *, correlation_id: str
    ) -> AIAdvisoryContent:
        """Generate a human-readable remediation outline. Advisory only —
        never executed automatically and never a substitute for the
        deterministic `remediation_guidance` already carried by the finding."""
        ...
