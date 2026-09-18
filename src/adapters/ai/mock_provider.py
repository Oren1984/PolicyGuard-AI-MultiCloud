"""Deterministic, offline AI provider used by default (spec section 10). No
network access, no API keys. Every AIAdvisoryContent it returns is grounded
by construction: `referenced_evidence` is built only from fields already
present on the findings it was given (finding id, resource id, policy id,
and the finding's own evidence tuple), so Gate 2 (grounding) passes for any
ordinary input by design.

Per spec section 10, this provider only ever summarizes, explains, groups,
or outlines -- it has no method that could determine compliance, change
severity, approve an exception, close a finding, or otherwise influence the
governance decision router.
"""

from __future__ import annotations

from src.domain.entities.ai_advisory import AIAdvisoryContent
from src.domain.entities.compliance_finding import ComplianceFinding
from src.domain.entities.drift_finding import DriftFinding

Finding = ComplianceFinding | DriftFinding


def _severity_label(finding: Finding) -> str:
    return finding.severity.label


def _title_for(finding: Finding) -> str:
    if isinstance(finding, ComplianceFinding):
        return finding.title
    return finding.what_changed


def _remediation_for(finding: Finding) -> str:
    if isinstance(finding, ComplianceFinding):
        return finding.remediation_guidance
    return finding.remediation


def _evidence_for(finding: Finding) -> tuple[str, ...]:
    refs = [f"finding:{finding.finding_id}", f"resource:{finding.resource_id}"]
    if finding.policy_id:
        refs.append(f"policy:{finding.policy_id}")
    refs.extend(finding.evidence)
    return tuple(dict.fromkeys(refs))


class MockAIProvider:
    """The default local AI provider (AIProvider port). Fully deterministic
    given its inputs -- same findings in, same advisory content out."""

    def __init__(self, name: str = "mock-ai-v1") -> None:
        self.name = name

    def summarize_findings(
        self, findings: list[Finding], *, correlation_id: str
    ) -> AIAdvisoryContent:
        if not findings:
            content = "No findings were supplied to summarize."
            evidence: tuple[str, ...] = ()
        else:
            severity_counts: dict[str, int] = {}
            for f in findings:
                label = _severity_label(f)
                severity_counts[label] = severity_counts.get(label, 0) + 1
            severity_summary = ", ".join(
                f"{count} {label}" for label, count in sorted(severity_counts.items())
            )
            resource_ids = sorted({f.resource_id for f in findings})
            content = (
                f"{len(findings)} finding(s) reviewed ({severity_summary}). "
                f"Affected resources: {', '.join(resource_ids)}."
            )
            evidence = tuple(dict.fromkeys(ref for f in findings for ref in _evidence_for(f)))
        return AIAdvisoryContent(
            provider_name=self.name,
            kind="summary",
            content=content,
            referenced_evidence=evidence,
            confidence=0.9 if findings else 0.5,
            raw_response={"finding_count": len(findings), "correlation_id": correlation_id},
        )

    def explain_impact(self, finding: Finding, *, correlation_id: str) -> AIAdvisoryContent:
        content = (
            f"Impact: {_title_for(finding)} on resource {finding.resource_id} "
            f"(severity {_severity_label(finding)}). This may increase operational, security, or "
            "compliance risk for the affected system until it is remediated or an exception is granted."
        )
        return AIAdvisoryContent(
            provider_name=self.name,
            kind="impact_explanation",
            content=content,
            referenced_evidence=_evidence_for(finding),
            confidence=0.85,
            raw_response={"finding_id": finding.finding_id, "correlation_id": correlation_id},
        )

    def group_related_violations(
        self, findings: list[Finding], *, correlation_id: str
    ) -> AIAdvisoryContent:
        groups: dict[str, list[str]] = {}
        for f in findings:
            key = f.policy_id or "unassociated"
            groups.setdefault(key, []).append(f.finding_id)
        content = "; ".join(
            f"policy {policy_id}: {len(ids)} related finding(s)"
            for policy_id, ids in sorted(groups.items())
        ) or "No related violations to group."
        evidence = tuple(dict.fromkeys(ref for f in findings for ref in _evidence_for(f)))
        return AIAdvisoryContent(
            provider_name=self.name,
            kind="grouping",
            content=content,
            referenced_evidence=evidence,
            confidence=0.8 if findings else 0.5,
            raw_response={"group_count": len(groups), "correlation_id": correlation_id},
        )

    def generate_remediation_outline(
        self, finding: Finding, *, correlation_id: str
    ) -> AIAdvisoryContent:
        guidance = _remediation_for(finding)
        content = (
            f"Suggested remediation outline for {finding.resource_id}: {guidance} "
            "This outline is advisory only; it does not replace human review, approval, or execution, "
            "and does not itself remediate anything."
        )
        return AIAdvisoryContent(
            provider_name=self.name,
            kind="remediation_outline",
            content=content,
            referenced_evidence=_evidence_for(finding),
            confidence=0.85,
            raw_response={"finding_id": finding.finding_id, "correlation_id": correlation_id},
        )
