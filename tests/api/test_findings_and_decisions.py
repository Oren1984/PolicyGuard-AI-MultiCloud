"""API tests: findings/decisions capability group, including governance
decision generation, remediation plans/status transitions, and the AI
advisory endpoints (with their mandatory assurance-gate pipeline)."""

from __future__ import annotations

from tests.fixtures.builders import (
    PLATFORM_ADMIN,
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


def _seed_finding(client) -> tuple[str, str]:
    """Returns (managed_system_id, compliance_finding_id) for one public
    exposure violation on a freshly registered system."""
    system_id = unique_id("sys")
    client.post("/api/v1/systems", json=managed_system_payload(system_id), headers=OWNER_HEADERS)
    pack_id = register_default_policy_pack(client)
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
    finding_id = evaluation.json()["finding_ids"][0]
    return system_id, finding_id


class TestFindingsListAndDetail:
    def test_list_and_get_compliance_finding(self, client):
        _system_id, finding_id = _seed_finding(client)
        listed = client.get("/api/v1/findings/compliance")
        assert listed.status_code == 200
        assert listed.json()["total"] >= 1

        detail = client.get(f"/api/v1/findings/compliance/{finding_id}")
        assert detail.status_code == 200
        assert detail.json()["finding_id"] == finding_id

    def test_get_missing_finding_is_404(self, client):
        resp = client.get("/api/v1/findings/compliance/does-not-exist")
        assert resp.status_code == 404


class TestFindingStatusTransitions:
    def test_valid_transition_open_to_acknowledged(self, client):
        _system_id, finding_id = _seed_finding(client)
        resp = client.patch(
            f"/api/v1/findings/compliance/{finding_id}/status",
            json={"target_status": "acknowledged"},
            headers=OWNER_HEADERS,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "acknowledged"

    def test_invalid_transition_rejected(self, client):
        """Required regression: invalid state transitions must fail closed
        (409), never silently succeed."""
        _system_id, finding_id = _seed_finding(client)
        resp = client.patch(
            f"/api/v1/findings/compliance/{finding_id}/status",
            json={"target_status": "closed"},  # OPEN -> CLOSED is not allowed
            headers=OWNER_HEADERS,
        )
        assert resp.status_code == 409

    def test_invalid_target_status_literal_rejected_by_schema(self, client):
        _system_id, finding_id = _seed_finding(client)
        resp = client.patch(
            f"/api/v1/findings/compliance/{finding_id}/status",
            json={"target_status": "not_a_real_status"},
            headers=OWNER_HEADERS,
        )
        assert resp.status_code == 422


class TestGovernanceDecisionGeneration:
    def test_generate_decision_for_a_public_exposure_finding_blocks_or_requires_remediation(self, client):
        _system_id, finding_id = _seed_finding(client)
        resp = client.post(f"/api/v1/findings/compliance/{finding_id}/decision", headers=OWNER_HEADERS)
        assert resp.status_code == 200
        body = resp.json()
        assert body["decision"] in ("remediation_required", "governance_block", "exception_review_required")
        assert body["finding_ids"] == [finding_id]

    def test_decision_generation_blocked_when_paused(self, client):
        _system_id, finding_id = _seed_finding(client)
        client.post(
            "/api/v1/admin/kill-switch",
            json={"mode": "paused", "reason": "maintenance"},
            headers=actor_headers("admin.one", PLATFORM_ADMIN),
        )
        resp = client.post(f"/api/v1/findings/compliance/{finding_id}/decision", headers=OWNER_HEADERS)
        assert resp.status_code == 503

    def test_decision_generation_blocked_during_emergency_stop(self, client):
        _system_id, finding_id = _seed_finding(client)
        client.post(
            "/api/v1/admin/kill-switch",
            json={"mode": "emergency_stop", "reason": "incident"},
            headers=actor_headers("admin.one", PLATFORM_ADMIN),
        )
        resp = client.post(f"/api/v1/findings/compliance/{finding_id}/decision", headers=OWNER_HEADERS)
        assert resp.status_code == 503


class TestRemediationPlans:
    def test_create_remediation_plan(self, client):
        _system_id, finding_id = _seed_finding(client)
        created = client.post(
            f"/api/v1/findings/compliance/{finding_id}/remediation-plan",
            json={"description": "restrict security group ingress"},
            headers=OWNER_HEADERS,
        )
        assert created.status_code == 201
        assert created.json()["status"] == "not_started"

    def test_get_remediation_plan_for_finding_with_no_plan_returns_null(self, client):
        _system_id, finding_id = _seed_finding(client)
        resp = client.get(f"/api/v1/findings/compliance/{finding_id}/remediation-plan")
        assert resp.status_code == 200
        assert resp.json() is None

    def test_transition_remediation_plan_status_via_api(self, client):
        _system_id, finding_id = _seed_finding(client)
        created = client.post(
            f"/api/v1/findings/compliance/{finding_id}/remediation-plan",
            json={"description": "restrict security group ingress"},
            headers=OWNER_HEADERS,
        )
        plan_id = created.json()["plan_id"]
        updated = client.patch(
            f"/api/v1/findings/remediation-plans/{plan_id}/status",
            json={"target_status": "in_progress", "verification_evidence": []},
            headers=OWNER_HEADERS,
        )
        assert updated.status_code == 200
        assert updated.json()["status"] == "in_progress"

    def test_remediation_plan_invalid_transition_rejected_via_api(self, client):
        _system_id, finding_id = _seed_finding(client)
        created = client.post(
            f"/api/v1/findings/compliance/{finding_id}/remediation-plan",
            json={"description": "x"},
            headers=OWNER_HEADERS,
        )
        plan_id = created.json()["plan_id"]
        # not_started -> verified is not a legal direct transition.
        resp = client.patch(
            f"/api/v1/findings/remediation-plans/{plan_id}/status",
            json={"target_status": "verified", "verification_evidence": []},
            headers=OWNER_HEADERS,
        )
        assert resp.status_code == 409


class TestAIAdvisoryEndpoints:
    def test_ai_summary_passes_gates_and_is_grounded(self, client):
        _system_id, finding_id = _seed_finding(client)
        resp = client.post(
            "/api/v1/findings/ai/summary",
            json={"findings": [{"finding_id": finding_id, "kind": "compliance"}]},
            headers=OWNER_HEADERS,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["fell_back"] is False
        assert any(g["status"] == "passed" for g in body["gate_results"])
        gate_names = {g["gate"] for g in body["gate_results"]}
        assert gate_names == {"schema", "grounding", "confidence", "safety", "consistency"}

    def test_ai_impact_explanation_for_a_single_finding(self, client):
        _system_id, finding_id = _seed_finding(client)
        resp = client.post(f"/api/v1/findings/compliance/{finding_id}/ai/impact", headers=OWNER_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["kind"] == "impact_explanation"

    def test_ai_remediation_outline(self, client):
        _system_id, finding_id = _seed_finding(client)
        resp = client.post(
            f"/api/v1/findings/compliance/{finding_id}/ai/remediation-outline", headers=OWNER_HEADERS
        )
        assert resp.status_code == 200
        assert resp.json()["kind"] == "remediation_outline"

    def test_ai_group_related_violations(self, client):
        _system_id, finding_id = _seed_finding(client)
        resp = client.post(
            "/api/v1/findings/ai/group",
            json={"findings": [{"finding_id": finding_id, "kind": "compliance"}]},
            headers=OWNER_HEADERS,
        )
        assert resp.status_code == 200
        assert resp.json()["kind"] == "grouping"

    def test_ai_summary_with_unknown_finding_returns_404(self, client):
        resp = client.post(
            "/api/v1/findings/ai/summary",
            json={"findings": [{"finding_id": "no-such-finding", "kind": "compliance"}]},
            headers=OWNER_HEADERS,
        )
        assert resp.status_code == 404

    def test_ai_advisory_gate_results_are_audited(self, client):
        _system_id, finding_id = _seed_finding(client)
        client.post(f"/api/v1/findings/compliance/{finding_id}/ai/impact", headers=OWNER_HEADERS)
        events = client.get("/api/v1/audit/events").json()["items"]
        assert any(e["action"] == "AI_ASSURANCE_GATES_EVALUATED" for e in events)
