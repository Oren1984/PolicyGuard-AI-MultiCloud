"""DI wiring for Phase 2's cloud/AI/assurance adapters, plus a thin AI
advisory orchestrator that ties the AIProvider port and the
AssuranceGateRunner pipeline together for the API layer.

The orchestrator is deliberately kept here rather than as a new
`src/application/` use case: Phase 3's brief explicitly scopes this build to
`src/api/`, `src/security/`, `src/observability/`, `src/config.py`, and
`src/main.py` and forbids touching `src/application/`. Every AI-adjacent
capability it exposes is pure orchestration over already-built Phase 1/2
ports/adapters (AIProvider, AssuranceGateRunner) -- no new governance
business logic is introduced here, and the deterministic decision router
(`route_governance_decision`) is never given any of this class's output as
an input (spec section 9's structural AI-exclusion guarantee is untouched by
this module).
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends

from src.adapters.ai.external_provider import ExternalAIProvider
from src.adapters.ai.mock_provider import MockAIProvider
from src.adapters.assurance.confidence_gate import ConfidenceThresholds
from src.adapters.assurance.pipeline import AssuranceGateRunner, build_fallback_advisory
from src.adapters.cloud.mock_aws_provider import MockAWSInventoryProvider
from src.adapters.cloud.mock_gcp_provider import MockGCPInventoryProvider
from src.adapters.persistence.audit_repository_sqlalchemy import SqlAlchemyAuditEventRepository
from src.api.dependencies.repositories import get_audit_repo
from src.config import Settings, get_settings
from src.domain.entities.actor import Actor
from src.domain.entities.ai_advisory import AIAdvisoryContent
from src.domain.entities.compliance_finding import ComplianceFinding
from src.domain.entities.drift_finding import DriftFinding
from src.domain.entities.gate_result import GatePipelineResult, GateResult
from src.domain.enums.cloud_provider import CloudProvider
from src.domain.enums.gate_name import GateName, GateStatus
from src.observability.metrics import gate_failures_total
from src.ports.ai_provider import AIProvider, AIProviderError
from src.ports.cloud_inventory_provider import CloudInventoryProvider

Finding = ComplianceFinding | DriftFinding

# Cloud inventory providers are selected by the managed system's own
# CloudProvider, not injected per-request via a header/query param -- this
# keeps the choice tied to data already on record (spec section 6: adapters
# stay behind the CloudInventoryProvider port; routes never call a cloud SDK
# or a specific mock class directly).
_CLOUD_PROVIDERS: dict[CloudProvider, CloudInventoryProvider] = {
    CloudProvider.AWS: MockAWSInventoryProvider(),
    CloudProvider.GCP: MockGCPInventoryProvider(),
}


def get_cloud_inventory_provider(provider: CloudProvider) -> CloudInventoryProvider:
    return _CLOUD_PROVIDERS[provider]


def get_ai_provider(settings: Settings = Depends(get_settings)) -> AIProvider:
    if settings.ai_provider == "external":
        return ExternalAIProvider(
            base_url=settings.ai_external_base_url, api_key=settings.ai_external_api_key
        )
    return MockAIProvider()


@dataclass(frozen=True, slots=True)
class AIAdvisoryResult:
    content: AIAdvisoryContent
    gates: GatePipelineResult
    fell_back: bool


class AIAdvisoryOrchestrator:
    """Calls the AIProvider port, runs the AssuranceGateRunner pipeline
    (spec section 11) over its output, records every gate result to the
    audit trail (spec: "record every gate result in the audit trail"), and
    returns the (possibly fallback-substituted) content plus the pipeline
    result. AI output produced here is never passed to
    `route_governance_decision` -- see module docstring.
    """

    def __init__(self, ai_provider: AIProvider, gate_runner: AssuranceGateRunner, audit_repo) -> None:
        self._ai_provider = ai_provider
        self._gate_runner = gate_runner
        self._audit_repo = audit_repo

    def summarize(
        self, findings: list[Finding], *, actor: Actor, correlation_id: str
    ) -> AIAdvisoryResult:
        return self._run(
            kind="summary",
            call=lambda: self._ai_provider.summarize_findings(findings, correlation_id=correlation_id),
            grounding_context=self._grounding_context(findings),
            actor=actor,
            correlation_id=correlation_id,
            resource_id=",".join(f.finding_id for f in findings) or "none",
        )

    def group(self, findings: list[Finding], *, actor: Actor, correlation_id: str) -> AIAdvisoryResult:
        return self._run(
            kind="grouping",
            call=lambda: self._ai_provider.group_related_violations(findings, correlation_id=correlation_id),
            grounding_context=self._grounding_context(findings),
            actor=actor,
            correlation_id=correlation_id,
            resource_id=",".join(f.finding_id for f in findings) or "none",
        )

    def explain_impact(self, finding: Finding, *, actor: Actor, correlation_id: str) -> AIAdvisoryResult:
        return self._run(
            kind="impact_explanation",
            call=lambda: self._ai_provider.explain_impact(finding, correlation_id=correlation_id),
            grounding_context=self._grounding_context([finding]),
            actor=actor,
            correlation_id=correlation_id,
            resource_id=finding.finding_id,
        )

    def remediation_outline(
        self, finding: Finding, *, actor: Actor, correlation_id: str
    ) -> AIAdvisoryResult:
        return self._run(
            kind="remediation_outline",
            call=lambda: self._ai_provider.generate_remediation_outline(
                finding, correlation_id=correlation_id
            ),
            grounding_context=self._grounding_context([finding]),
            actor=actor,
            correlation_id=correlation_id,
            resource_id=finding.finding_id,
        )

    @staticmethod
    def _grounding_context(findings: list[Finding]) -> dict:
        known_evidence: set[str] = set()
        for f in findings:
            known_evidence.add(f"finding:{f.finding_id}")
            known_evidence.add(f"resource:{f.resource_id}")
            if f.policy_id:
                known_evidence.add(f"policy:{f.policy_id}")
            known_evidence.update(f.evidence)
        severities = [f.severity.label for f in findings]
        return {
            "known_evidence": known_evidence,
            "resource_id": findings[0].resource_id if findings else None,
            "deterministic_severity": severities[0] if len(severities) == 1 else None,
        }

    def _run(
        self, *, kind: str, call, grounding_context: dict, actor: Actor, correlation_id: str, resource_id: str
    ) -> AIAdvisoryResult:
        try:
            raw = call()
        except AIProviderError:
            # Fail closed: an unreachable/erroring AI provider must never
            # block the caller from getting a safe, deterministic
            # explanation (spec section 11: "fail closed and use a
            # deterministic fallback explanation").
            fallback = build_fallback_advisory(kind, grounding_context)
            gates = GatePipelineResult(
                results=(
                    GateResult(
                        gate=GateName.SAFETY,
                        status=GateStatus.FAILED,
                        reason="AI provider call failed; failing closed to a deterministic fallback.",
                    ),
                )
            )
            self._audit_gates(gates, actor=actor, correlation_id=correlation_id, resource_id=resource_id)
            return AIAdvisoryResult(content=fallback, gates=gates, fell_back=True)

        content, gates = self._gate_runner.run(raw, grounding_context=grounding_context)
        fell_back = gates.any_failed
        self._audit_gates(gates, actor=actor, correlation_id=correlation_id, resource_id=resource_id)
        return AIAdvisoryResult(content=content, gates=gates, fell_back=fell_back)

    def _audit_gates(
        self, gates: GatePipelineResult, *, actor: Actor, correlation_id: str, resource_id: str
    ) -> None:
        for result in gates.results:
            if result.status == GateStatus.FAILED:
                gate_failures_total.labels(gate=result.gate.value).inc()
        self._audit_repo.append(
            actor=actor.actor_id,
            actor_role=actor.role.value,
            action="AI_ASSURANCE_GATES_EVALUATED",
            resource_type="ai_advisory",
            resource_id=resource_id,
            correlation_id=correlation_id,
            payload={
                "gates": [
                    {"gate": r.gate.value, "status": r.status.value, "reason": r.reason}
                    for r in gates.results
                ],
                "any_failed": gates.any_failed,
            },
        )


def get_assurance_gate_runner(settings: Settings = Depends(get_settings)) -> AssuranceGateRunner:
    return AssuranceGateRunner(
        ConfidenceThresholds(
            approval_threshold=settings.confidence_approval_threshold,
            hard_floor=settings.confidence_hard_floor,
        )
    )


def get_ai_advisory_orchestrator(
    ai_provider: AIProvider = Depends(get_ai_provider),
    gate_runner: AssuranceGateRunner = Depends(get_assurance_gate_runner),
    audit_repo: SqlAlchemyAuditEventRepository = Depends(get_audit_repo),
) -> AIAdvisoryOrchestrator:
    return AIAdvisoryOrchestrator(ai_provider, gate_runner, audit_repo)
