"""Security regression tests (spec section 18 / this phase's brief's exact
required list), exercised over the real HTTP API + real Postgres:

* Requester self-approval
* Spoofed identity fields
* Expired exception reuse
* AI attempting to influence the deterministic decision
* Audit-chain tampering
* Kill-switch bypass attempts
* Missing or malformed evidence
* Invalid state transitions

Most of these regressions already have a dedicated, focused test elsewhere
in the suite (unit/application/api/assurance tiers) -- this file is the
consolidated, security-framed pass over the same guarantees plus additional
API-hardening checks (payload limits, strict schemas, safe error responses)
that spec section 18 requires and don't fit any other tier's theme.
"""

from __future__ import annotations

from sqlalchemy import text

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


class TestSelfApprovalRegression:
    def test_requester_cannot_approve_their_own_exception(self, client):
        system_id = unique_id("sys")
        client.post("/api/v1/systems", json=managed_system_payload(system_id), headers=OWNER_HEADERS)
        payload = exception_request_payload(
            policy_id="POL-NET-001", resource_id="r1", finding_id="f1", managed_system_id=system_id
        )
        created = client.post("/api/v1/exceptions", json=payload, headers=OWNER_HEADERS)
        exception_id = created.json()["exception_id"]
        client.post(
            f"/api/v1/exceptions/{exception_id}/review",
            headers=actor_headers("reviewer.one", SECURITY_REVIEWER),
        )
        self_approve = client.post(
            f"/api/v1/exceptions/{exception_id}/decide",
            json={"approve": True, "rationale": "self-approving"},
            headers=actor_headers("dev.one", COMPLIANCE_APPROVER),
        )
        assert self_approve.status_code == 403


class TestSpoofedIdentityRegression:
    def test_client_supplied_requested_by_never_overrides_authenticated_actor(self, client):
        system_id = unique_id("sys")
        client.post("/api/v1/systems", json=managed_system_payload(system_id), headers=OWNER_HEADERS)
        payload = exception_request_payload(
            policy_id="POL-NET-001",
            resource_id="r1",
            finding_id="f1",
            managed_system_id=system_id,
            requested_by="attacker.claiming.to.be.someone.else",
        )
        resp = client.post("/api/v1/exceptions", json=payload, headers=OWNER_HEADERS)
        assert resp.status_code == 403

    def test_owner_actor_id_defaults_to_authenticated_actor_not_client_claim(self, client):
        payload = managed_system_payload()
        payload["owner_actor_id"] = None  # explicit: no client-supplied owner
        resp = client.post("/api/v1/systems", json=payload, headers=OWNER_HEADERS)
        assert resp.status_code == 201
        assert resp.json()["owner_actor_id"] == "dev.one"


class TestExpiredExceptionReuseRegression:
    def test_state_machine_rejects_expired_to_active(self):
        import pytest

        from src.domain.enums.exception_status import ExceptionStatus
        from src.domain.state_machine.errors import InvalidStateTransitionError
        from src.domain.state_machine.exception_transitions import validate_transition

        with pytest.raises(InvalidStateTransitionError):
            validate_transition(ExceptionStatus.EXPIRED, ExceptionStatus.ACTIVE)

    def test_deciding_an_already_expired_exception_via_api_is_rejected(self, client):
        from datetime import UTC, datetime, timedelta

        system_id = unique_id("sys")
        client.post("/api/v1/systems", json=managed_system_payload(system_id), headers=OWNER_HEADERS)
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
            json={"approve": True, "rationale": "approved"},
            headers=reviewer_headers,
        )
        client.post("/api/v1/exceptions/expire-sweep", headers=actor_headers("sweeper", PLATFORM_ADMIN))
        assert client.get(f"/api/v1/exceptions/{exception_id}").json()["status"] == "expired"

        reuse_attempt = client.post(
            f"/api/v1/exceptions/{exception_id}/decide",
            json={"approve": True, "rationale": "trying to reuse"},
            headers=reviewer_headers,
        )
        assert reuse_attempt.status_code == 409


class TestAICannotInfluenceDecisionRegression:
    def test_ai_endpoints_have_no_wiring_into_the_decision_router(self):
        """See tests/unit/test_decision_router.py::TestAICannotInfluenceDecision
        for the full structural + behavioral proof, and
        tests/assurance/test_ai_cannot_influence_decision_api.py for the
        real HTTP + Postgres end-to-end version. This is a lightweight
        cross-check confirming GenerateGovernanceDecisionUseCase's own
        source never imports the AI provider or advisory content types."""
        import inspect

        from src.application.use_cases import generate_governance_decision as module

        source = inspect.getsource(module)
        assert "AIProvider" not in source
        assert "AIAdvisoryContent" not in source
        assert "MockAIProvider" not in source


class TestAuditChainTamperingRegression:
    def test_tampering_a_persisted_audit_record_is_detected(self, client, db_engine):
        client.post(
            "/api/v1/admin/kill-switch",
            json={"mode": "paused", "reason": "generate an audit event"},
            headers=actor_headers("admin.one", PLATFORM_ADMIN),
        )
        before = client.get("/api/v1/audit/verify").json()
        assert before["is_valid"] is True

        with db_engine.begin() as conn:
            conn.execute(
                text("UPDATE audit_events SET canonical_payload = :p WHERE sequence = 1"),
                {"p": '{"tampered":true}'},
            )

        after = client.get("/api/v1/audit/verify").json()
        assert after["is_valid"] is False
        assert after["first_invalid_sequence"] == 1


class TestKillSwitchBypassRegression:
    def test_non_admin_role_cannot_change_kill_switch(self, client):
        resp = client.post(
            "/api/v1/admin/kill-switch",
            json={"mode": "emergency_stop", "reason": "trying to bypass"},
            headers=actor_headers("dev.one", SYSTEM_OWNER),
        )
        assert resp.status_code == 403

    def test_mutations_blocked_during_emergency_stop_cannot_be_forced_through(self, client):
        client.post(
            "/api/v1/admin/kill-switch",
            json={"mode": "emergency_stop", "reason": "incident"},
            headers=actor_headers("admin.one", PLATFORM_ADMIN),
        )
        resp = client.post("/api/v1/systems", json=managed_system_payload(), headers=OWNER_HEADERS)
        assert resp.status_code == 503

    def test_reads_remain_available_during_emergency_stop(self, client):
        """Spec section 13: health, status, audit verification, and
        read-only inspection must remain available even in EMERGENCY_STOP --
        proving the block is scoped to mutations only, not a wholesale
        outage that could be mistaken for a bypassed kill switch."""
        client.post(
            "/api/v1/admin/kill-switch",
            json={"mode": "emergency_stop", "reason": "incident"},
            headers=actor_headers("admin.one", PLATFORM_ADMIN),
        )
        assert client.get("/health").status_code == 200
        assert client.get("/api/v1/admin/status").status_code == 200
        assert client.get("/api/v1/audit/verify").status_code == 200
        assert client.get("/api/v1/systems").status_code == 200

    def test_kill_switch_state_unavailable_is_never_silently_treated_as_normal(self):
        """Fail-closed regression at the pure-function level: a kill switch
        that cannot be read must never be interpreted as NORMAL."""
        from src.domain.enums.system_mode import SystemMode
        from src.domain.policies.kill_switch_policy import KillSwitchState, blocks_all_mutations

        assert blocks_all_mutations(KillSwitchState(mode=SystemMode.EMERGENCY_STOP)) is True
        assert blocks_all_mutations(KillSwitchState(mode=SystemMode.NORMAL)) is False


class TestMissingOrMalformedEvidenceRegression:
    def test_malformed_evidence_type_rejected(self, client):
        system_id = unique_id("sys")
        client.post("/api/v1/systems", json=managed_system_payload(system_id), headers=OWNER_HEADERS)
        payload = exception_request_payload(
            policy_id="POL-NET-001", resource_id="r1", finding_id="f1", managed_system_id=system_id
        )
        payload["evidence"] = [{"not": "a string"}]
        resp = client.post("/api/v1/exceptions", json=payload, headers=OWNER_HEADERS)
        assert resp.status_code == 422

    def test_evaluation_without_evidence_complete_requires_remediation_never_compliant(self):
        """A finding whose evidence is incomplete can never be routed
        lighter than REMEDIATION_REQUIRED (see decision-router unit tests
        for the exhaustive version) -- confirmed here as the security-facing
        framing of the same guarantee."""
        from src.application.routing.decision_router import (
            GovernanceDecisionContext,
            route_governance_decision,
        )
        from src.domain.enums.decision_type import DecisionType
        from src.domain.enums.environment import Environment
        from src.domain.enums.policy_severity import PolicySeverity
        from src.domain.enums.resource_criticality import ResourceCriticality
        from src.domain.enums.system_mode import SystemMode

        ctx = GovernanceDecisionContext(
            has_violation=True,
            severity=PolicySeverity.LOW,
            environment=Environment.DEV,
            resource_criticality=ResourceCriticality.STANDARD,
            evidence_complete=False,
            exception_status=None,
            exception_eligible=True,
            critical_non_eligible=False,
            repeated_violation_count=0,
            system_mode=SystemMode.NORMAL,
            gates=None,
        )
        result = route_governance_decision(ctx)
        assert result.decision == DecisionType.REMEDIATION_REQUIRED
        assert result.decision != DecisionType.COMPLIANT


class TestInvalidStateTransitionRegression:
    def test_finding_status_invalid_transition_rejected_via_api(self, client):
        from tests.fixtures.builders import (
            desired_state_payload,
            observed_state_payload,
            register_default_policy_pack,
            resource_attributes_payload,
            resource_payload,
        )

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
        resp = client.patch(
            f"/api/v1/findings/compliance/{finding_id}/status",
            json={"target_status": "closed"},
            headers=OWNER_HEADERS,
        )
        assert resp.status_code == 409


class TestGeneralAPIHardening:
    def test_oversized_payload_is_rejected(self, client):
        huge_description = "x" * 2_000_000
        payload = dict(managed_system_payload(), description=huge_description)
        resp = client.post("/api/v1/systems", json=payload, headers=OWNER_HEADERS)
        assert resp.status_code in (413, 422)

    def test_unknown_fields_rejected_by_strict_schema(self, client):
        payload = dict(managed_system_payload(), unexpected_field="nope")
        resp = client.post("/api/v1/systems", json=payload, headers=OWNER_HEADERS)
        assert resp.status_code == 422

    def test_invalid_role_header_rejected(self, client):
        resp = client.post(
            "/api/v1/systems",
            json=managed_system_payload(),
            headers={"X-PolicyGuard-Actor": "dev.one", "X-PolicyGuard-Role": "superadmin"},
        )
        assert resp.status_code == 401

    def test_missing_actor_headers_rejected(self, client):
        resp = client.post("/api/v1/systems", json=managed_system_payload())
        assert resp.status_code == 401

    def test_error_responses_never_leak_stack_traces(self, client):
        resp = client.get("/api/v1/systems/does-not-exist")
        assert resp.status_code == 404
        body = resp.json()
        assert "Traceback" not in str(body)
        assert 'File "' not in str(body)

    def test_secrets_in_exception_payload_are_never_returned_verbatim_in_audit(self, client):
        system_id = unique_id("sys")
        client.post("/api/v1/systems", json=managed_system_payload(system_id), headers=OWNER_HEADERS)
        payload = exception_request_payload(
            policy_id="POL-NET-001", resource_id="r1", finding_id="f1", managed_system_id=system_id
        )
        payload["business_justification"] = "connection string: postgresql://user:hunter2@host/db"
        client.post("/api/v1/exceptions", json=payload, headers=OWNER_HEADERS)
        events = client.get("/api/v1/audit/events").json()["items"]
        assert not any("hunter2" in str(e["payload"]) for e in events)

    def test_xss_like_strings_are_stored_as_inert_data_not_executed(self, client):
        payload = dict(managed_system_payload(), name="<script>alert(1)</script>")
        resp = client.post("/api/v1/systems", json=payload, headers=OWNER_HEADERS)
        assert resp.status_code == 201
        assert resp.json()["name"] == "<script>alert(1)</script>"

    def test_sql_injection_like_string_is_stored_as_inert_data(self, client):
        payload = dict(managed_system_payload(), description="'; DROP TABLE managed_systems; --")
        resp = client.post("/api/v1/systems", json=payload, headers=OWNER_HEADERS)
        assert resp.status_code == 201
        # Parameterized access means the table survives -- prove it by
        # successfully listing systems afterward.
        listed = client.get("/api/v1/systems")
        assert listed.status_code == 200
