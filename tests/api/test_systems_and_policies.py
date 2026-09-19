"""API tests: systems/inventory and policies capability groups (spec section
15), including the mock cloud inventory fetch and cross-cloud normalization
(spec section 19 scenario 18: cross-cloud findings normalized into the same
domain model)."""

from __future__ import annotations

from tests.fixtures.builders import (
    COMPLIANCE_APPROVER,
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


class TestManagedSystems:
    def test_register_and_get_system(self, client):
        payload = managed_system_payload()
        resp = client.post("/api/v1/systems", json=payload, headers=OWNER_HEADERS)
        assert resp.status_code == 201
        body = resp.json()
        assert body["system_id"] == payload["system_id"]
        assert body["is_production"] is True

        fetched = client.get(f"/api/v1/systems/{payload['system_id']}")
        assert fetched.status_code == 200

    def test_register_requires_actor_headers(self, client):
        resp = client.post("/api/v1/systems", json=managed_system_payload())
        assert resp.status_code == 401

    def test_list_systems(self, client):
        client.post("/api/v1/systems", json=managed_system_payload(), headers=OWNER_HEADERS)
        client.post("/api/v1/systems", json=managed_system_payload(), headers=OWNER_HEADERS)
        resp = client.get("/api/v1/systems")
        assert resp.status_code == 200
        assert resp.json()["total"] >= 2

    def test_get_missing_system_is_404(self, client):
        resp = client.get("/api/v1/systems/does-not-exist")
        assert resp.status_code == 404

    def test_unknown_field_rejected_by_strict_schema(self, client):
        payload = dict(managed_system_payload(), unexpected_field="nope")
        resp = client.post("/api/v1/systems", json=payload, headers=OWNER_HEADERS)
        assert resp.status_code == 422

    def test_registration_blocked_during_emergency_stop(self, client):
        client.post(
            "/api/v1/admin/kill-switch",
            json={"mode": "emergency_stop", "reason": "incident"},
            headers=actor_headers("admin.one", PLATFORM_ADMIN),
        )
        resp = client.post("/api/v1/systems", json=managed_system_payload(), headers=OWNER_HEADERS)
        assert resp.status_code == 503


class TestSnapshotsAndCloudInventory:
    def test_submit_desired_and_observed_state(self, client):
        system_id = unique_id("sys")
        client.post("/api/v1/systems", json=managed_system_payload(system_id), headers=OWNER_HEADERS)

        desired = desired_state_payload([resource_payload("r1")])
        resp = client.post(f"/api/v1/systems/{system_id}/desired-state", json=desired, headers=OWNER_HEADERS)
        assert resp.status_code == 201

        observed = observed_state_payload([resource_payload("r1")])
        resp = client.post(
            f"/api/v1/systems/{system_id}/observed-state", json=observed, headers=OWNER_HEADERS
        )
        assert resp.status_code == 201

        comparison = client.get(f"/api/v1/systems/{system_id}/snapshot-comparison")
        assert comparison.status_code == 200
        body = comparison.json()
        assert body["desired"] is not None
        assert body["observed"] is not None

    def test_fetch_observed_state_from_mock_aws_provider(self, client):
        system_id = unique_id("sys")
        client.post(
            "/api/v1/systems",
            json=managed_system_payload(system_id, cloud_provider="aws"),
            headers=OWNER_HEADERS,
        )
        resp = client.post(f"/api/v1/systems/{system_id}/observed-state/fetch", headers=OWNER_HEADERS)
        assert resp.status_code == 201
        resources = resp.json()["resources"]
        assert len(resources) > 0
        assert all(r["cloud_provider"] == "aws" for r in resources)

    def test_fetch_observed_state_from_mock_gcp_provider_normalizes_to_same_model(self, client):
        """Spec section 19 scenario 18: cross-cloud findings normalized into
        the same domain model -- both providers return CloudResource-shaped
        JSON with identical field names, differing only in `cloud_provider`."""
        aws_system = unique_id("sys")
        gcp_system = unique_id("sys")
        client.post(
            "/api/v1/systems",
            json=managed_system_payload(aws_system, cloud_provider="aws"),
            headers=OWNER_HEADERS,
        )
        client.post(
            "/api/v1/systems",
            json=managed_system_payload(gcp_system, cloud_provider="gcp"),
            headers=OWNER_HEADERS,
        )
        aws_resp = client.post(f"/api/v1/systems/{aws_system}/observed-state/fetch", headers=OWNER_HEADERS)
        gcp_resp = client.post(f"/api/v1/systems/{gcp_system}/observed-state/fetch", headers=OWNER_HEADERS)
        assert aws_resp.status_code == 201
        assert gcp_resp.status_code == 201
        aws_resource = aws_resp.json()["resources"][0]
        gcp_resource = gcp_resp.json()["resources"][0]
        # Same normalized schema (same keys) across both providers.
        assert set(aws_resource.keys()) == set(gcp_resource.keys())
        assert aws_resource["cloud_provider"] == "aws"
        assert gcp_resource["cloud_provider"] == "gcp"

    def test_drift_detection_finds_public_exposure_change(self, client):
        system_id = unique_id("sys")
        client.post("/api/v1/systems", json=managed_system_payload(system_id), headers=OWNER_HEADERS)
        desired = desired_state_payload(
            [resource_payload("r1", attributes=resource_attributes_payload(publicly_accessible=False))]
        )
        client.post(f"/api/v1/systems/{system_id}/desired-state", json=desired, headers=OWNER_HEADERS)
        observed = observed_state_payload(
            [resource_payload("r1", attributes=resource_attributes_payload(publicly_accessible=True))]
        )
        client.post(f"/api/v1/systems/{system_id}/observed-state", json=observed, headers=OWNER_HEADERS)

        resp = client.post(f"/api/v1/systems/{system_id}/drift-detection", headers=OWNER_HEADERS)
        assert resp.status_code == 200
        findings = resp.json()["findings"]
        assert any(f["policy_id"] == "POL-NET-001" for f in findings)

    def test_drift_detection_requires_both_snapshots(self, client):
        system_id = unique_id("sys")
        client.post("/api/v1/systems", json=managed_system_payload(system_id), headers=OWNER_HEADERS)
        resp = client.post(f"/api/v1/systems/{system_id}/drift-detection", headers=OWNER_HEADERS)
        assert resp.status_code == 409

    def test_drift_detection_blocked_when_paused(self, client):
        system_id = unique_id("sys")
        client.post("/api/v1/systems", json=managed_system_payload(system_id), headers=OWNER_HEADERS)
        client.post(
            f"/api/v1/systems/{system_id}/desired-state",
            json=desired_state_payload([resource_payload("r1")]),
            headers=OWNER_HEADERS,
        )
        client.post(
            f"/api/v1/systems/{system_id}/observed-state",
            json=observed_state_payload([resource_payload("r1")]),
            headers=OWNER_HEADERS,
        )
        client.post(
            "/api/v1/admin/kill-switch",
            json={"mode": "paused", "reason": "maintenance"},
            headers=actor_headers("admin.one", PLATFORM_ADMIN),
        )
        resp = client.post(f"/api/v1/systems/{system_id}/drift-detection", headers=OWNER_HEADERS)
        assert resp.status_code == 503


class TestPoliciesAndPacks:
    def test_only_policy_admin_roles_can_create_policies(self, client):
        payload = {
            "policy_id": "POL-CUSTOM-001",
            "title": "Custom",
            "description": "custom policy",
            "category": "public_network_exposure",
            "severity": "HIGH",
            "required_evidence": [],
            "explanation_template": "x",
            "remediation_guidance": "y",
        }
        forbidden = client.post("/api/v1/policies", json=payload, headers=OWNER_HEADERS)
        assert forbidden.status_code == 403

        allowed = client.post(
            "/api/v1/policies", json=payload, headers=actor_headers("admin.one", PLATFORM_ADMIN)
        )
        assert allowed.status_code == 201

    def test_register_default_pack_via_helper_and_evaluate_against_snapshot(self, client):
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
        resp = client.post(
            f"/api/v1/policies/packs/{pack_id}/evaluate",
            json={"managed_system_id": system_id},
            headers=OWNER_HEADERS,
        )
        assert resp.status_code == 200
        assert resp.json()["resources_evaluated"] == 1
        assert len(resp.json()["finding_ids"]) >= 1

    def test_activate_and_deactivate_policy(self, client):
        admin_headers = actor_headers("admin.one", COMPLIANCE_APPROVER)
        payload = {
            "policy_id": "POL-CUSTOM-002",
            "title": "Custom 2",
            "description": "custom policy",
            "category": "missing_backup",
            "severity": "MEDIUM",
            "required_evidence": [],
            "explanation_template": "x",
            "remediation_guidance": "y",
            "active": True,
        }
        client.post("/api/v1/policies", json=payload, headers=admin_headers)
        deactivated = client.post("/api/v1/policies/POL-CUSTOM-002/deactivate", headers=admin_headers)
        assert deactivated.status_code == 200
        assert deactivated.json()["active"] is False
        reactivated = client.post("/api/v1/policies/POL-CUSTOM-002/activate", headers=admin_headers)
        assert reactivated.json()["active"] is True
