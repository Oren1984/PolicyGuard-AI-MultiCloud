"""API tests: health/readiness/metrics/docs endpoints and admin (kill-switch
+ system status) capability group."""

from __future__ import annotations

from tests.fixtures.builders import PLATFORM_ADMIN, SYSTEM_OWNER, actor_headers


class TestHealthReadinessMetrics:
    def test_health_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_ready_ok_against_real_database(self, client):
        resp = client.get("/ready")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ready"}

    def test_metrics_exposes_prometheus_text(self, client):
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "policyguard_" in resp.text

    def test_openapi_schema_served(self, client):
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        assert resp.json()["info"]["title"] == "PolicyGuard AI MultiCloud"

    def test_docs_served(self, client):
        resp = client.get("/docs")
        assert resp.status_code == 200


class TestKillSwitchAdminEndpoints:
    def test_default_mode_is_normal_after_fresh_startup(self, client):
        resp = client.get("/api/v1/admin/kill-switch")
        assert resp.status_code == 200
        assert resp.json()["mode"] == "normal"

    def test_authorized_admin_can_change_mode(self, client):
        resp = client.post(
            "/api/v1/admin/kill-switch",
            json={"mode": "paused", "reason": "scheduled maintenance"},
            headers=actor_headers("admin.one", PLATFORM_ADMIN),
        )
        assert resp.status_code == 200
        assert resp.json()["mode"] == "paused"

    def test_unauthorized_role_cannot_change_mode(self, client):
        """Required regression: kill-switch bypass attempts must be
        rejected with 403 for a non-authorized role."""
        resp = client.post(
            "/api/v1/admin/kill-switch",
            json={"mode": "emergency_stop", "reason": "trying to bypass"},
            headers=actor_headers("dev.one", SYSTEM_OWNER),
        )
        assert resp.status_code == 403

    def test_kill_switch_endpoint_requires_actor_headers(self, client):
        resp = client.post("/api/v1/admin/kill-switch", json={"mode": "paused", "reason": "no headers"})
        assert resp.status_code == 401

    def test_invalid_mode_value_is_rejected_by_strict_schema(self, client):
        resp = client.post(
            "/api/v1/admin/kill-switch",
            json={"mode": "not_a_real_mode", "reason": "x"},
            headers=actor_headers("admin.one", PLATFORM_ADMIN),
        )
        assert resp.status_code == 422

    def test_kill_switch_endpoint_reachable_even_during_emergency_stop(self, client):
        """Spec section 13: an operator must always be able to turn the
        system back to NORMAL, even from EMERGENCY_STOP."""
        admin_headers = actor_headers("admin.one", PLATFORM_ADMIN)
        client.post(
            "/api/v1/admin/kill-switch",
            json={"mode": "emergency_stop", "reason": "incident"},
            headers=admin_headers,
        )
        recover = client.post(
            "/api/v1/admin/kill-switch", json={"mode": "normal", "reason": "resolved"}, headers=admin_headers
        )
        assert recover.status_code == 200
        assert recover.json()["mode"] == "normal"

    def test_system_status_reports_expected_shape(self, client):
        resp = client.get("/api/v1/admin/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ai_provider"] == "mock"
        assert body["audit_chain_valid"] is True
        assert "compliance_finding_counts_by_status" in body
        assert "exception_counts_by_status" in body


class TestAuditEndpoints:
    def test_audit_verify_on_empty_chain_is_valid(self, client):
        resp = client.get("/api/v1/audit/verify")
        assert resp.status_code == 200
        body = resp.json()
        assert body["is_valid"] is True

    def test_audit_events_recorded_by_admin_actions(self, client):
        client.post(
            "/api/v1/admin/kill-switch",
            json={"mode": "paused", "reason": "test"},
            headers=actor_headers("admin.one", PLATFORM_ADMIN),
        )
        resp = client.get("/api/v1/audit/events")
        assert resp.status_code == 200
        actions = [e["action"] for e in resp.json()["items"]]
        assert "KILL_SWITCH_MODE_CHANGED" in actions

    def test_audit_available_during_emergency_stop(self, client):
        admin_headers = actor_headers("admin.one", PLATFORM_ADMIN)
        client.post(
            "/api/v1/admin/kill-switch",
            json={"mode": "emergency_stop", "reason": "incident"},
            headers=admin_headers,
        )
        resp = client.get("/api/v1/audit/verify")
        assert resp.status_code == 200


class TestDashboard:
    def test_dashboard_renders(self, client):
        resp = client.get("/dashboard")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
