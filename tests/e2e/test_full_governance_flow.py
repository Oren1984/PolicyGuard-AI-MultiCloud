"""End-to-end test: the complete governance workflow in one continuous run,
against a real (TestClient-driven) FastAPI app + real Postgres -- register a
system, fetch mock cloud inventory, submit desired state, build a real
policy pack, evaluate it, detect drift, generate governance decisions,
produce an AI explanation through the assurance-gate pipeline, run the full
exception lifecycle (including a rejected self-approval and a rejected
spoofed-identity attempt), exercise all three kill-switch modes, verify the
audit chain, and render the dashboard. This is the same shape of workflow
Phase 3 verified manually; here it is captured as a permanent, repeatable
automated test.
"""

from __future__ import annotations

from tests.fixtures.builders import (
    COMPLIANCE_APPROVER,
    PLATFORM_ADMIN,
    SECURITY_REVIEWER,
    SYSTEM_OWNER,
    actor_headers,
    desired_state_payload,
    exception_request_payload,
    managed_system_payload,
    observed_state_payload,
    register_default_policy_pack,
    resource_attributes_payload,
    resource_payload,
    unique_id,
)

OWNER = actor_headers("owner.one", SYSTEM_OWNER)
REVIEWER = actor_headers("reviewer.one", SECURITY_REVIEWER)
APPROVER = actor_headers("approver.one", COMPLIANCE_APPROVER)
ADMIN = actor_headers("admin.one", PLATFORM_ADMIN)


def test_full_governance_lifecycle(client):
    # 1. Register an AWS production system.
    system_id = unique_id("e2e-sys")
    register = client.post(
        "/api/v1/systems", json=managed_system_payload(system_id, cloud_provider="aws"), headers=OWNER
    )
    assert register.status_code == 201

    # 2. Fetch a real mock-AWS observed inventory snapshot.
    fetched = client.post(f"/api/v1/systems/{system_id}/observed-state/fetch", headers=OWNER)
    assert fetched.status_code == 201
    assert len(fetched.json()["resources"]) > 0

    # 3. Submit a desired-state baseline (deliberately compliant for one
    #    resource so we control exactly one known violation).
    desired = desired_state_payload([resource_payload("r1")], allowed_regions=["us-east-1"])
    submitted_desired = client.post(f"/api/v1/systems/{system_id}/desired-state", json=desired, headers=OWNER)
    assert submitted_desired.status_code == 201

    # 4. Submit an observed state with one deliberate public-exposure violation.
    observed = observed_state_payload(
        [resource_payload("r1", attributes=resource_attributes_payload(publicly_accessible=True))]
    )
    submitted_observed = client.post(
        f"/api/v1/systems/{system_id}/observed-state", json=observed, headers=OWNER
    )
    assert submitted_observed.status_code == 201

    # 5. Build and evaluate the real default policy pack.
    pack_id = register_default_policy_pack(client)
    evaluation = client.post(
        f"/api/v1/policies/packs/{pack_id}/evaluate", json={"managed_system_id": system_id}, headers=OWNER
    )
    assert evaluation.status_code == 200
    finding_ids = evaluation.json()["finding_ids"]
    assert finding_ids

    # 6. Detect drift too (independent evidence path).
    drift = client.post(f"/api/v1/systems/{system_id}/drift-detection", headers=OWNER)
    assert drift.status_code == 200

    # 7. Generate a governance decision for the public-exposure finding.
    findings = [client.get(f"/api/v1/findings/compliance/{fid}").json() for fid in finding_ids]
    public_exposure_finding = next(f for f in findings if f["policy_id"] == "POL-NET-001")
    decision = client.post(
        f"/api/v1/findings/compliance/{public_exposure_finding['finding_id']}/decision", headers=OWNER
    )
    assert decision.status_code == 200
    assert decision.json()["decision"] in ("remediation_required", "governance_block")

    # 8. AI explanation through the full assurance-gate pipeline.
    advisory = client.post(
        f"/api/v1/findings/compliance/{public_exposure_finding['finding_id']}/ai/impact", headers=OWNER
    )
    assert advisory.status_code == 200
    assert len(advisory.json()["gate_results"]) == 5

    # 9. Exception workflow: request, rejected self-approval, rejected
    #    spoofed identity, then a legitimate approval by a different actor.
    exc_payload = exception_request_payload(
        policy_id="POL-NET-001",
        resource_id="r1",
        finding_id=public_exposure_finding["finding_id"],
        managed_system_id=system_id,
    )
    exc_created = client.post("/api/v1/exceptions", json=exc_payload, headers=OWNER)
    assert exc_created.status_code == 201
    exception_id = exc_created.json()["exception_id"]

    spoofed_payload = exception_request_payload(
        policy_id="POL-NET-001",
        resource_id="r1",
        finding_id=public_exposure_finding["finding_id"],
        managed_system_id=system_id,
        requested_by="someone.else",
    )
    spoofed = client.post("/api/v1/exceptions", json=spoofed_payload, headers=OWNER)
    assert spoofed.status_code == 403

    client.post(f"/api/v1/exceptions/{exception_id}/review", headers=REVIEWER)
    self_approve = client.post(
        f"/api/v1/exceptions/{exception_id}/decide",
        json={"approve": True, "rationale": "self approve"},
        headers=actor_headers("owner.one", COMPLIANCE_APPROVER),  # same actor id as requester
    )
    assert self_approve.status_code == 403

    approved = client.post(
        f"/api/v1/exceptions/{exception_id}/decide",
        json={"approve": True, "rationale": "compensating control verified"},
        headers=APPROVER,
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "active"

    # 10. Kill switch: PAUSED blocks new evaluations, EMERGENCY_STOP blocks
    #     all mutations, both leave health/audit available, then recover.
    client.post("/api/v1/admin/kill-switch", json={"mode": "paused", "reason": "maintenance"}, headers=ADMIN)
    paused_eval = client.post(
        f"/api/v1/policies/packs/{pack_id}/evaluate", json={"managed_system_id": system_id}, headers=OWNER
    )
    assert paused_eval.status_code == 503
    assert client.get("/health").status_code == 200

    client.post(
        "/api/v1/admin/kill-switch", json={"mode": "emergency_stop", "reason": "incident"}, headers=ADMIN
    )
    blocked_mutation = client.post("/api/v1/systems", json=managed_system_payload(), headers=OWNER)
    assert blocked_mutation.status_code == 503
    assert client.get("/api/v1/audit/verify").status_code == 200

    recovered = client.post(
        "/api/v1/admin/kill-switch", json={"mode": "normal", "reason": "resolved"}, headers=ADMIN
    )
    assert recovered.status_code == 200
    assert recovered.json()["mode"] == "normal"

    # 11. Audit-chain verification and dashboard render.
    verification = client.get("/api/v1/audit/verify")
    assert verification.status_code == 200
    assert verification.json()["is_valid"] is True
    assert verification.json()["total_records"] > 0

    dashboard = client.get("/dashboard")
    assert dashboard.status_code == 200
    assert system_id in dashboard.text
