"""API tests: the full policy-exception workflow (spec section 12), over
real HTTP + real Postgres. Includes the required self-approval and spoofed-
identity regressions at the API boundary (unit/application-layer versions of
the same regressions live in tests/unit/test_separation_of_duties.py and
tests/application/test_use_cases.py -- this file proves the boundary itself
enforces them end to end)."""

from __future__ import annotations

from tests.fixtures.builders import (
    COMPLIANCE_APPROVER,
    PLATFORM_ADMIN,
    SECURITY_REVIEWER,
    SYSTEM_OWNER,
    actor_headers,
    exception_request_payload,
    managed_system_payload,
    unique_id,
)

OWNER_HEADERS = actor_headers("dev.one", SYSTEM_OWNER)


def _register_system(client) -> str:
    system_id = unique_id("sys")
    client.post("/api/v1/systems", json=managed_system_payload(system_id), headers=OWNER_HEADERS)
    return system_id


class TestRequestException:
    def test_request_exception_succeeds(self, client):
        system_id = _register_system(client)
        payload = exception_request_payload(
            policy_id="POL-NET-001", resource_id="r1", finding_id="f1", managed_system_id=system_id
        )
        resp = client.post("/api/v1/exceptions", json=payload, headers=OWNER_HEADERS)
        assert resp.status_code == 201
        body = resp.json()
        assert body["status"] == "requested"
        assert body["requested_by"] == "dev.one"

    def test_spoofed_requester_identity_is_rejected(self, client):
        """Required regression: a client-supplied `requested_by` that
        differs from the authenticated actor must be rejected."""
        system_id = _register_system(client)
        payload = exception_request_payload(
            policy_id="POL-NET-001",
            resource_id="r1",
            finding_id="f1",
            managed_system_id=system_id,
            requested_by="someone.else",  # spoofed -- authenticated actor is "dev.one"
        )
        resp = client.post("/api/v1/exceptions", json=payload, headers=OWNER_HEADERS)
        assert resp.status_code == 403

        listed = client.get("/api/v1/exceptions").json()
        assert listed["total"] == 0  # nothing was persisted

    def test_matching_requested_by_field_is_allowed(self, client):
        system_id = _register_system(client)
        payload = exception_request_payload(
            policy_id="POL-NET-001",
            resource_id="r1",
            finding_id="f1",
            managed_system_id=system_id,
            requested_by="dev.one",  # matches the authenticated actor
        )
        resp = client.post("/api/v1/exceptions", json=payload, headers=OWNER_HEADERS)
        assert resp.status_code == 201

    def test_missing_evidence_field_still_accepted_but_empty_is_recorded_honestly(self, client):
        """Missing/malformed evidence regression: evidence is optional at
        submission, but must never be silently fabricated -- an empty list
        stays an empty list."""
        system_id = _register_system(client)
        payload = exception_request_payload(
            policy_id="POL-NET-001",
            resource_id="r1",
            finding_id="f1",
            managed_system_id=system_id,
            evidence=[],
        )
        resp = client.post("/api/v1/exceptions", json=payload, headers=OWNER_HEADERS)
        assert resp.status_code == 201
        assert resp.json()["evidence"] == []

    def test_malformed_evidence_type_rejected_by_strict_schema(self, client):
        system_id = _register_system(client)
        payload = exception_request_payload(
            policy_id="POL-NET-001", resource_id="r1", finding_id="f1", managed_system_id=system_id
        )
        payload["evidence"] = "not-a-list"  # malformed: schema requires list[str]
        resp = client.post("/api/v1/exceptions", json=payload, headers=OWNER_HEADERS)
        assert resp.status_code == 422

    def test_missing_required_field_rejected(self, client):
        system_id = _register_system(client)
        payload = exception_request_payload(
            policy_id="POL-NET-001", resource_id="r1", finding_id="f1", managed_system_id=system_id
        )
        del payload["business_justification"]
        resp = client.post("/api/v1/exceptions", json=payload, headers=OWNER_HEADERS)
        assert resp.status_code == 422

    def test_request_blocked_during_emergency_stop(self, client):
        client.post(
            "/api/v1/admin/kill-switch",
            json={"mode": "emergency_stop", "reason": "incident"},
            headers=actor_headers("admin.one", PLATFORM_ADMIN),
        )
        system_id = _register_system(client)
        payload = exception_request_payload(
            policy_id="POL-NET-001", resource_id="r1", finding_id="f1", managed_system_id=system_id
        )
        resp = client.post("/api/v1/exceptions", json=payload, headers=OWNER_HEADERS)
        assert resp.status_code == 503


def _request_exception(client, *, system_id: str, requester_headers: dict) -> str:
    payload = exception_request_payload(
        policy_id="POL-NET-001", resource_id="r1", finding_id="f1", managed_system_id=system_id
    )
    resp = client.post("/api/v1/exceptions", json=payload, headers=requester_headers)
    return resp.json()["exception_id"]


class TestReviewAndDecide:
    def test_review_then_approve_activates_exception(self, client):
        system_id = _register_system(client)
        exception_id = _request_exception(client, system_id=system_id, requester_headers=OWNER_HEADERS)
        reviewer_headers = actor_headers("reviewer.one", SECURITY_REVIEWER)

        reviewed = client.post(f"/api/v1/exceptions/{exception_id}/review", headers=reviewer_headers)
        assert reviewed.status_code == 200
        assert reviewed.json()["status"] == "under_review"

        approved = client.post(
            f"/api/v1/exceptions/{exception_id}/decide",
            json={"approve": True, "rationale": "compensating control verified"},
            headers=reviewer_headers,
        )
        assert approved.status_code == 200
        assert approved.json()["status"] == "active"
        assert approved.json()["expires_at"] is not None

    def test_requester_cannot_review_their_own_exception(self, client):
        system_id = _register_system(client)
        exception_id = _request_exception(client, system_id=system_id, requester_headers=OWNER_HEADERS)
        self_reviewer_headers = actor_headers("dev.one", SECURITY_REVIEWER)  # same id, elevated role
        resp = client.post(f"/api/v1/exceptions/{exception_id}/review", headers=self_reviewer_headers)
        assert resp.status_code == 403

    def test_requester_cannot_approve_their_own_exception(self, client):
        """Required regression: requester self-approval must be rejected,
        even when the requester also happens to hold an authorized role."""
        system_id = _register_system(client)
        exception_id = _request_exception(client, system_id=system_id, requester_headers=OWNER_HEADERS)
        client.post(
            f"/api/v1/exceptions/{exception_id}/review",
            headers=actor_headers("reviewer.one", SECURITY_REVIEWER),
        )
        self_approve_headers = actor_headers("dev.one", COMPLIANCE_APPROVER)
        resp = client.post(
            f"/api/v1/exceptions/{exception_id}/decide",
            json={"approve": True, "rationale": "self-approving (should be rejected)"},
            headers=self_approve_headers,
        )
        assert resp.status_code == 403
        assert client.get(f"/api/v1/exceptions/{exception_id}").json()["status"] == "under_review"

    def test_rejection_is_terminal(self, client):
        system_id = _register_system(client)
        exception_id = _request_exception(client, system_id=system_id, requester_headers=OWNER_HEADERS)
        reviewer_headers = actor_headers("reviewer.one", SECURITY_REVIEWER)
        client.post(f"/api/v1/exceptions/{exception_id}/review", headers=reviewer_headers)
        rejected = client.post(
            f"/api/v1/exceptions/{exception_id}/decide",
            json={"approve": False, "rationale": "insufficient compensating controls"},
            headers=reviewer_headers,
        )
        assert rejected.status_code == 200
        assert rejected.json()["status"] == "rejected"

        # A rejected exception cannot be decided again (terminal state).
        redecide = client.post(
            f"/api/v1/exceptions/{exception_id}/decide",
            json={"approve": True, "rationale": "trying again"},
            headers=reviewer_headers,
        )
        assert redecide.status_code == 409

    def test_decide_blocked_when_paused(self, client):
        system_id = _register_system(client)
        exception_id = _request_exception(client, system_id=system_id, requester_headers=OWNER_HEADERS)
        reviewer_headers = actor_headers("reviewer.one", SECURITY_REVIEWER)
        client.post(f"/api/v1/exceptions/{exception_id}/review", headers=reviewer_headers)
        client.post(
            "/api/v1/admin/kill-switch",
            json={"mode": "paused", "reason": "maintenance"},
            headers=actor_headers("admin.one", PLATFORM_ADMIN),
        )
        resp = client.post(
            f"/api/v1/exceptions/{exception_id}/decide",
            json={"approve": True, "rationale": "x"},
            headers=reviewer_headers,
        )
        assert resp.status_code == 503


class TestRevokeAndExpire:
    def test_authorized_role_can_revoke_active_exception(self, client):
        system_id = _register_system(client)
        exception_id = _request_exception(client, system_id=system_id, requester_headers=OWNER_HEADERS)
        reviewer_headers = actor_headers("reviewer.one", SECURITY_REVIEWER)
        client.post(f"/api/v1/exceptions/{exception_id}/review", headers=reviewer_headers)
        client.post(
            f"/api/v1/exceptions/{exception_id}/decide",
            json={"approve": True, "rationale": "approved"},
            headers=reviewer_headers,
        )
        revoked = client.post(
            f"/api/v1/exceptions/{exception_id}/revoke",
            json={"reason": "risk profile changed"},
            headers=reviewer_headers,
        )
        assert revoked.status_code == 200
        assert revoked.json()["status"] == "revoked"

    def test_unauthorized_role_cannot_revoke(self, client):
        system_id = _register_system(client)
        exception_id = _request_exception(client, system_id=system_id, requester_headers=OWNER_HEADERS)
        reviewer_headers = actor_headers("reviewer.one", SECURITY_REVIEWER)
        client.post(f"/api/v1/exceptions/{exception_id}/review", headers=reviewer_headers)
        client.post(
            f"/api/v1/exceptions/{exception_id}/decide",
            json={"approve": True, "rationale": "approved"},
            headers=reviewer_headers,
        )
        resp = client.post(
            f"/api/v1/exceptions/{exception_id}/revoke",
            json={"reason": "trying to revoke without authorization"},
            headers=OWNER_HEADERS,
        )
        assert resp.status_code == 403

    def test_expired_exception_reuse_is_rejected_by_the_state_machine(self, client):
        """Required regression: an EXPIRED exception can never be
        reactivated -- the expire-sweep endpoint plus an attempted re-decide
        on an already-expired exception must fail closed."""
        import time

        system_id = _register_system(client)
        payload = exception_request_payload(
            policy_id="POL-NET-001",
            resource_id="r1",
            finding_id="f1",
            managed_system_id=system_id,
            expires_in_days=0,
        )
        # Force an already-past expiration to make the sweep pick it up.
        from datetime import UTC, datetime, timedelta

        payload["requested_expiration"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
        created = client.post("/api/v1/exceptions", json=payload, headers=OWNER_HEADERS)
        exception_id = created.json()["exception_id"]

        reviewer_headers = actor_headers("reviewer.one", SECURITY_REVIEWER)
        client.post(f"/api/v1/exceptions/{exception_id}/review", headers=reviewer_headers)
        client.post(
            f"/api/v1/exceptions/{exception_id}/decide",
            json={"approve": True, "rationale": "approved with immediate expiration for this test"},
            headers=reviewer_headers,
        )
        time.sleep(0.05)

        swept = client.post(
            "/api/v1/exceptions/expire-sweep", headers=actor_headers("sweeper", PLATFORM_ADMIN)
        )
        assert swept.status_code == 200
        expired_ids = {e["exception_id"] for e in swept.json()["expired"]}
        assert exception_id in expired_ids
        assert client.get(f"/api/v1/exceptions/{exception_id}").json()["status"] == "expired"

        # Attempting to "reuse" (re-decide) the now-expired exception must fail closed.
        reuse_attempt = client.post(
            f"/api/v1/exceptions/{exception_id}/decide",
            json={"approve": True, "rationale": "trying to reuse an expired exception"},
            headers=reviewer_headers,
        )
        assert reuse_attempt.status_code == 409

    def test_expired_exception_no_longer_suppresses_a_reevaluated_finding(self, client):
        """Full-loop regression: after expiry, re-evaluating the policy
        pack must surface the underlying violation again (not silently keep
        it suppressed) via the dedicated POL-EXC-020 policy."""
        from datetime import UTC, datetime, timedelta

        from tests.fixtures.builders import (
            desired_state_payload,
            observed_state_payload,
            register_default_policy_pack,
            resource_attributes_payload,
            resource_payload,
        )

        system_id = _register_system(client)
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

        payload = exception_request_payload(
            policy_id="POL-NET-001", resource_id="r1", finding_id="f1", managed_system_id=system_id
        )
        payload["requested_expiration"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
        created = client.post("/api/v1/exceptions", json=payload, headers=OWNER_HEADERS)
        exception_id = created.json()["exception_id"]
        reviewer_headers = actor_headers("reviewer.one", SECURITY_REVIEWER)
        client.post(f"/api/v1/exceptions/{exception_id}/review", headers=reviewer_headers)
        client.post(
            f"/api/v1/exceptions/{exception_id}/decide",
            json={"approve": True, "rationale": "approved briefly for this test"},
            headers=reviewer_headers,
        )
        client.post("/api/v1/exceptions/expire-sweep", headers=actor_headers("sweeper", PLATFORM_ADMIN))

        evaluation = client.post(
            f"/api/v1/policies/packs/{pack_id}/evaluate",
            json={"managed_system_id": system_id},
            headers=OWNER_HEADERS,
        )
        finding_ids = evaluation.json()["finding_ids"]
        findings = [client.get(f"/api/v1/findings/compliance/{fid}").json() for fid in finding_ids]
        # POL-NET-001 (the original violation) is still surfaced, and
        # POL-EXC-020 (expired-exception-on-record) additionally fires.
        assert any(f["policy_id"] == "POL-NET-001" for f in findings)
        assert any(f["policy_id"] == "POL-EXC-020" for f in findings)


class TestListExceptions:
    def test_list_filters_by_status(self, client):
        system_id = _register_system(client)
        _request_exception(client, system_id=system_id, requester_headers=OWNER_HEADERS)
        resp = client.get("/api/v1/exceptions", params={"status": "requested"})
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1

    def test_get_missing_exception_404(self, client):
        resp = client.get("/api/v1/exceptions/does-not-exist")
        assert resp.status_code == 404
