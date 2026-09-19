"""Tests for the demo/mock data seed and reset scripts
(demo/scripts/seed_demo_data.py, demo/scripts/reset_demo_data.py).

Loaded by file path (importlib) rather than as a package import -- these
are standalone scripts meant to be run directly
(`python demo/scripts/seed_demo_data.py`), not a package other code
imports from, so they deliberately have no `demo/__init__.py`.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from sqlalchemy import text

from tests.conftest import DATABASE_URL

_SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "demo" / "scripts"


def _load(module_name: str, filename: str):
    spec = importlib.util.spec_from_file_location(module_name, _SCRIPTS_DIR / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


seed_demo_data = _load("seed_demo_data", "seed_demo_data.py")
reset_demo_data = _load("reset_demo_data", "reset_demo_data.py")

DEMO_SCOPED_TABLES = reset_demo_data._DEMO_SCOPED_TABLES


def _table_counts(db_engine) -> dict[str, int]:
    with db_engine.begin() as conn:
        return {
            table: conn.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()  # noqa: S608
            for table in DEMO_SCOPED_TABLES
        }


class TestSeedIsIdempotent:
    def test_seed_creates_all_eight_demo_systems(self, client, db_engine):
        log = seed_demo_data.seed(client)
        assert len(log.seeded_systems) == 8
        assert log.skipped_systems == []

        resp = client.get("/api/v1/systems")
        demo_systems = [s for s in resp.json()["items"] if s["system_id"].startswith("demo-")]
        assert len(demo_systems) == 8

    def test_rerunning_seed_creates_zero_duplicates(self, client, db_engine):
        seed_demo_data.seed(client)
        counts_after_first_run = _table_counts(db_engine)

        log2 = seed_demo_data.seed(client)
        assert len(log2.skipped_systems) == 8
        assert log2.seeded_systems == []

        counts_after_second_run = _table_counts(db_engine)
        assert counts_after_second_run == counts_after_first_run

    def test_every_seeded_system_is_tagged_as_demo(self, client):
        seed_demo_data.seed(client)
        resp = client.get("/api/v1/systems")
        demo_systems = [s for s in resp.json()["items"] if s["system_id"].startswith("demo-")]
        assert demo_systems, "expected at least one seeded demo system"
        for system in demo_systems:
            assert system["tags"].get("source") == "demo"
            assert system["tags"].get("is_demo") == "true"


class TestSeedProducesRealisticSpread:
    def test_severity_and_decision_mix_is_balanced(self, client):
        seed_demo_data.seed(client)

        compliance = client.get("/api/v1/findings/compliance", params={"limit": 200}).json()
        severities = {f["severity"] for f in compliance["items"]}
        assert {"LOW", "MEDIUM", "HIGH", "CRITICAL"}.issubset(severities)

        decisions_seen = set()
        for f in compliance["items"]:
            resp = client.post(
                f"/api/v1/findings/compliance/{f['finding_id']}/decision", headers=seed_demo_data.OWNER
            )
            if resp.status_code == 200:
                decisions_seen.add(resp.json()["decision"])
        # Re-deciding an already-decided finding is a fresh (new) decision
        # each time in this system's design -- this loop is only checking
        # decision variety exists across findings, not exact counts.
        assert "governance_block" in decisions_seen
        assert "remediation_required" in decisions_seen

    def test_both_cloud_providers_and_a_pending_review_case_are_present(self, client):
        seed_demo_data.seed(client)
        resp = client.get("/api/v1/systems")
        providers = {s["cloud_provider"] for s in resp.json()["items"] if s["system_id"].startswith("demo-")}
        assert providers == {"aws", "gcp"}

        pending = client.get("/api/v1/exceptions", params={"status": "under_review"}).json()
        assert pending["total"] >= 1


class TestDashboardRendersSeededData:
    def test_dashboard_200_and_shows_seeded_content(self, client):
        seed_demo_data.seed(client)
        resp = client.get("/dashboard")
        assert resp.status_code == 200
        assert "demo-aws-checkout-api" in resp.text
        assert "governance_block" in resp.text
        assert "Pending human review" in resp.text

    def test_demo_banner_hidden_by_default(self, client):
        resp = client.get("/dashboard")
        assert resp.status_code == 200
        assert "DEMO / MOCK DATA" not in resp.text

    def test_demo_banner_shown_when_demo_mode_enabled(self, client):
        from src.config import Settings, get_settings
        from src.main import app

        app.dependency_overrides[get_settings] = lambda: Settings(demo_mode=True)
        try:
            resp = client.get("/dashboard")
        finally:
            app.dependency_overrides.pop(get_settings, None)
        assert resp.status_code == 200
        assert "DEMO / MOCK DATA" in resp.text


class TestResetRemovesOnlyDemoRecords:
    def test_reset_clears_demo_tables_but_preserves_audit_and_policies(self, client, db_engine):
        seed_demo_data.seed(client)

        with db_engine.begin() as conn:
            audit_before = conn.execute(text("SELECT count(*) FROM audit_events")).scalar_one()
            policies_before = conn.execute(text("SELECT count(*) FROM policies")).scalar_one()
            packs_before = conn.execute(text("SELECT count(*) FROM policy_packs")).scalar_one()
        assert audit_before > 0
        assert policies_before == 20

        removed = reset_demo_data.reset(DATABASE_URL)
        assert removed["managed_systems"] == 8
        assert sum(removed.values()) > 0

        counts_after = _table_counts(db_engine)
        assert all(n == 0 for n in counts_after.values())

        with db_engine.begin() as conn:
            audit_after = conn.execute(text("SELECT count(*) FROM audit_events")).scalar_one()
            policies_after = conn.execute(text("SELECT count(*) FROM policies")).scalar_one()
            packs_after = conn.execute(text("SELECT count(*) FROM policy_packs")).scalar_one()
        assert audit_after == audit_before, "reset must never delete audit_events"
        assert policies_after == policies_before, "reset must never delete policies"
        assert packs_after == packs_before, "reset must never delete policy_packs"

    def test_audit_chain_still_verifies_after_reset(self, client):
        seed_demo_data.seed(client)
        reset_demo_data.reset(DATABASE_URL)
        resp = client.get("/api/v1/audit/verify")
        assert resp.status_code == 200
        assert resp.json()["is_valid"] is True

    def test_reset_is_idempotent(self, client, db_engine):
        seed_demo_data.seed(client)
        reset_demo_data.reset(DATABASE_URL)
        removed_second_time = reset_demo_data.reset(DATABASE_URL)
        assert sum(removed_second_time.values()) == 0

    def test_reset_on_an_already_empty_database_is_a_safe_no_op(self, db_engine):
        removed = reset_demo_data.reset(DATABASE_URL)
        assert sum(removed.values()) == 0

    def test_seed_reset_reseed_cycle_produces_identical_counts(self, client, db_engine):
        seed_demo_data.seed(client)
        counts_first = _table_counts(db_engine)

        reset_demo_data.reset(DATABASE_URL)
        assert all(n == 0 for n in _table_counts(db_engine).values())

        seed_demo_data.seed(client)
        counts_second = _table_counts(db_engine)
        assert counts_first == counts_second


class TestSafetyGates:
    def test_seed_script_refuses_without_demo_mode_env_var(self, monkeypatch):
        monkeypatch.delenv("POLICYGUARD_DEMO_MODE", raising=False)
        with pytest.raises(SystemExit):
            seed_demo_data._refuse_unless_authorized(seed_demo_data.HttpClient("http://unused"), force=False)

    def test_reset_script_refuses_without_demo_mode_env_var(self, monkeypatch):
        monkeypatch.delenv("POLICYGUARD_DEMO_MODE", raising=False)
        with pytest.raises(SystemExit):
            reset_demo_data._refuse_unless_authorized(force=False)

    def test_force_flag_bypasses_the_demo_mode_gate(self, monkeypatch):
        monkeypatch.delenv("POLICYGUARD_DEMO_MODE", raising=False)
        reset_demo_data._refuse_unless_authorized(force=True)  # must not raise
