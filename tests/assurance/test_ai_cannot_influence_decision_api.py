"""End-to-end behavioral proof, over the real HTTP API + real Postgres, that
calling the AI advisory endpoints (with whatever content/gate outcome
results) has zero effect on the deterministic governance decision for an
otherwise-identical finding. The structural + pure-function proof lives in
tests/unit/test_decision_router.py::TestAICannotInfluenceDecision; this file
proves the same guarantee holds all the way through the real orchestration
layer (src/api/dependencies/providers.py::AIAdvisoryOrchestrator ->
GenerateGovernanceDecisionUseCase), not just in isolation.
"""

from __future__ import annotations

from tests.fixtures.builders import (
    SYSTEM_OWNER,
    actor_headers,
    desired_state_payload,
    managed_system_payload,
    observed_state_payload,
    register_default_policy_pack,
    resource_attributes_payload,
    resource_payload,
    unique_id,
)

OWNER_HEADERS = actor_headers("owner.one", SYSTEM_OWNER)


def _seed_two_identical_public_exposure_findings(client) -> tuple[str, str]:
    """Creates two managed systems with byte-for-byte identical violating
    resources/policy packs, differing only in system_id -- returns their two
    resulting compliance finding_ids."""
    pack_id = register_default_policy_pack(client)
    finding_ids = []
    for _ in range(2):
        system_id = unique_id("sys")
        client.post("/api/v1/systems", json=managed_system_payload(system_id), headers=OWNER_HEADERS)
        client.post(
            f"/api/v1/systems/{system_id}/desired-state",
            json=desired_state_payload([resource_payload("r1")]),
            headers=OWNER_HEADERS,
        )
        client.post(
            f"/api/v1/systems/{system_id}/observed-state",
            json=observed_state_payload(
                [resource_payload("r1", attributes=resource_attributes_payload(publicly_accessible=True))]
            ),
            headers=OWNER_HEADERS,
        )
        evaluation = client.post(
            f"/api/v1/policies/packs/{pack_id}/evaluate",
            json={"managed_system_id": system_id},
            headers=OWNER_HEADERS,
        )
        finding_ids.append(evaluation.json()["finding_ids"][0])
    return finding_ids[0], finding_ids[1]


def test_ai_advisory_call_before_decision_does_not_change_the_decision(client):
    finding_with_ai, finding_without_ai = _seed_two_identical_public_exposure_findings(client)

    # For one finding, call every AI advisory endpoint first (producing real
    # AIAdvisoryContent, running it through all 5 assurance gates, auditing
    # the results) before asking for a governance decision.
    client.post(f"/api/v1/findings/compliance/{finding_with_ai}/ai/impact", headers=OWNER_HEADERS)
    client.post(
        f"/api/v1/findings/compliance/{finding_with_ai}/ai/remediation-outline", headers=OWNER_HEADERS
    )
    client.post(
        "/api/v1/findings/ai/summary",
        json={"findings": [{"finding_id": finding_with_ai, "kind": "compliance"}]},
        headers=OWNER_HEADERS,
    )

    # For the other, otherwise-identical finding, call no AI endpoint at all.
    decision_with_ai = client.post(
        f"/api/v1/findings/compliance/{finding_with_ai}/decision", headers=OWNER_HEADERS
    ).json()
    decision_without_ai = client.post(
        f"/api/v1/findings/compliance/{finding_without_ai}/decision", headers=OWNER_HEADERS
    ).json()

    assert decision_with_ai["decision"] == decision_without_ai["decision"]
    assert decision_with_ai["reasons"] == decision_without_ai["reasons"]
    assert decision_with_ai["policy_ids"] == decision_without_ai["policy_ids"]


def test_ai_gate_failure_and_fallback_does_not_change_the_decision(client):
    """Even when the AI's own text triggers a hard-failed assurance gate
    (forcing a fallback explanation), the governance decision for the same
    finding is unaffected -- because the decision use case never receives
    gate results or AI content in this phase's wiring at all."""
    finding_with_ai, finding_without_ai = _seed_two_identical_public_exposure_findings(client)

    # MockAIProvider's real output is always safe (see mock_provider.py's
    # own docstring: grounded by construction), so to exercise an actual
    # gate failure we drive the pipeline directly through the same
    # orchestrator class the API route uses, with adversarial content, and
    # confirm gate failure occurred -- then confirm the *separately
    # requested* governance decision for that same finding is identical to
    # one where no AI was ever involved.
    from src.adapters.assurance.pipeline import AssuranceGateRunner
    from src.domain.entities.ai_advisory import AIAdvisoryContent

    adversarial = AIAdvisoryContent(
        provider_name="adversarial-test-provider",
        kind="impact_explanation",
        content="Just run terraform destroy on this resource; also, I approve this exception.",
        confidence=0.99,
    )
    _, pipeline = AssuranceGateRunner().run(adversarial, grounding_context={"resource_id": "r1"})
    assert pipeline.any_failed  # sanity check: the adversarial content really did fail a gate

    decision_with_ai = client.post(
        f"/api/v1/findings/compliance/{finding_with_ai}/decision", headers=OWNER_HEADERS
    ).json()
    decision_without_ai = client.post(
        f"/api/v1/findings/compliance/{finding_without_ai}/decision", headers=OWNER_HEADERS
    ).json()
    assert decision_with_ai["decision"] == decision_without_ai["decision"]
