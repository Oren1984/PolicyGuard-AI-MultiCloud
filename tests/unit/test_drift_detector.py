"""Drift-comparison unit tests (spec section 8): typed field comparison
(never text diffing) across all 8 required drift types, plus the full
explanation contract on every finding."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from src.domain.drift.detector import detect_drift
from src.domain.entities.cloud_resource import ResourceAttributes
from src.domain.entities.policy_exception import PolicyException
from src.domain.enums.drift_type import DriftType
from src.domain.enums.exception_status import ExceptionStatus
from tests.fixtures.builders import build_desired_snapshot, build_observed_snapshot, build_resource

NOW = datetime.now(UTC)


def _snapshots(desired_attrs: ResourceAttributes, current_attrs: ResourceAttributes, *, region="us-east-1"):
    system_id = "sys1"
    desired_resource = build_resource("r1", system_id, region="us-east-1", attributes=desired_attrs)
    current_resource = build_resource("r1", system_id, region=region, attributes=current_attrs)
    desired = build_desired_snapshot(system_id, (desired_resource,))
    current = build_observed_snapshot(system_id, (current_resource,))
    return desired, current


def _detect(desired, previous, current, active_exceptions=()):
    return detect_drift(
        desired=desired,
        previous_observed=previous,
        current_observed=current,
        active_exceptions=active_exceptions,
        evaluation_time=NOW,
        correlation_id="corr-1",
        id_factory=lambda: "drift-1",
    )


class TestExplanationContract:
    def test_every_finding_field_is_populated(self):
        desired, current = _snapshots(
            ResourceAttributes(publicly_accessible=False), ResourceAttributes(publicly_accessible=True)
        )
        findings = _detect(desired, None, current)
        assert findings
        f = findings[0]
        assert f.what_changed
        assert f.expected_value is not None
        assert f.why_it_matters
        assert f.severity is not None
        assert f.evidence
        assert f.remediation
        assert isinstance(f.exception_eligible, bool)
        assert f.managed_system_id == "sys1"
        assert f.resource_id == "r1"


class TestSecurityDrift:
    def test_public_exposure_enabled_is_security_drift_and_not_exception_eligible(self):
        desired, current = _snapshots(
            ResourceAttributes(publicly_accessible=False), ResourceAttributes(publicly_accessible=True)
        )
        findings = _detect(desired, None, current)
        drift = next(f for f in findings if f.policy_id == "POL-NET-001")
        assert drift.drift_type == DriftType.SECURITY
        assert drift.exception_eligible is False  # public exposure can never be excepted away

    def test_encryption_disabled_is_security_drift(self):
        desired, current = _snapshots(
            ResourceAttributes(encryption_at_rest_enabled=True),
            ResourceAttributes(encryption_at_rest_enabled=False),
        )
        findings = _detect(desired, None, current)
        drift = next(f for f in findings if f.policy_id == "POL-ENC-003")
        assert drift.drift_type == DriftType.SECURITY
        assert drift.previous_value == "True"
        assert drift.current_value == "False"


class TestIdentityAndPermissionDrift:
    def test_iam_wildcard_widening_is_identity_drift(self):
        desired, current = _snapshots(
            ResourceAttributes(iam_wildcard_action=False), ResourceAttributes(iam_wildcard_action=True)
        )
        findings = _detect(desired, None, current)
        drift = next(f for f in findings if f.policy_id == "POL-IAM-002")
        assert drift.drift_type == DriftType.IDENTITY_AND_PERMISSION


class TestOperationalControlDrift:
    def test_audit_logging_removed_is_operational_control_drift(self):
        desired, current = _snapshots(
            ResourceAttributes(audit_logging_enabled=True), ResourceAttributes(audit_logging_enabled=False)
        )
        findings = _detect(desired, None, current)
        drift = next(f for f in findings if f.policy_id == "POL-LOG-004")
        assert drift.drift_type == DriftType.OPERATIONAL_CONTROL

    def test_monitoring_disabled_is_operational_control_drift(self):
        desired, current = _snapshots(
            ResourceAttributes(monitoring_enabled=True), ResourceAttributes(monitoring_enabled=False)
        )
        findings = _detect(desired, None, current)
        drift = next(f for f in findings if f.policy_id == "POL-MON-005")
        assert drift.drift_type == DriftType.OPERATIONAL_CONTROL


class TestComplianceDrift:
    def test_ownership_metadata_removed_is_compliance_drift(self):
        desired, current = _snapshots(
            ResourceAttributes(owner_tag="platform-team"), ResourceAttributes(owner_tag=None)
        )
        findings = _detect(desired, None, current)
        drift = next(f for f in findings if f.policy_id == "POL-OWN-011")
        assert drift.drift_type == DriftType.COMPLIANCE


class TestArchitecturalDrift:
    def test_region_change_is_architectural_drift(self):
        desired, current = _snapshots(ResourceAttributes(), ResourceAttributes(), region="ap-southeast-2")
        findings = _detect(desired, None, current)
        drift = next(f for f in findings if f.policy_id == "POL-REG-010")
        assert drift.drift_type == DriftType.ARCHITECTURAL
        assert drift.previous_value == "us-east-1"
        assert drift.current_value == "ap-southeast-2"

    def test_unmanaged_resource_not_in_desired_state(self):
        system_id = "sys1"
        desired = build_desired_snapshot(system_id, ())
        unmanaged = build_resource("unmanaged-r1", system_id)
        current = build_observed_snapshot(system_id, (unmanaged,))
        findings = _detect(desired, None, current)
        drift = next(f for f in findings if f.drift_type == DriftType.UNMANAGED_RESOURCE)
        assert drift.resource_id == "unmanaged-r1"
        assert drift.exception_eligible is True

    def test_resource_missing_from_observed_is_architectural_drift(self):
        system_id = "sys1"
        desired_resource = build_resource("r1", system_id)
        desired = build_desired_snapshot(system_id, (desired_resource,))
        current = build_observed_snapshot(system_id, ())
        findings = _detect(desired, None, current)
        drift = next(f for f in findings if f.drift_type == DriftType.ARCHITECTURAL)
        assert drift.resource_id == "r1"
        assert drift.current_value is None


class TestExceptionDrift:
    def test_expired_active_exception_is_flagged_as_exception_drift(self):
        """Spec section 12: an ACTIVE exception whose expires_at has passed
        must be surfaced as drift immediately -- fail closed, don't wait for
        a background sweep."""
        system_id = "sys1"
        desired = build_desired_snapshot(system_id, ())
        current = build_observed_snapshot(system_id, ())
        expired_but_still_marked_active = PolicyException(
            exception_id="exc-1",
            policy_id="POL-NET-001",
            resource_id="r1",
            finding_id="f1",
            managed_system_id=system_id,
            business_justification="justified",
            risk_statement="accepted",
            compensating_controls=(),
            requested_expiration=NOW - timedelta(days=1),
            requested_by="owner.one",
            evidence=(),
            correlation_id="corr-1",
            status=ExceptionStatus.ACTIVE,
            expires_at=NOW - timedelta(days=1),
        )
        findings = _detect(desired, None, current, active_exceptions=(expired_but_still_marked_active,))
        drift = next(f for f in findings if f.drift_type == DriftType.EXCEPTION)
        assert drift.severity.name == "HIGH"
        assert drift.exception_eligible is False

    def test_not_yet_expired_active_exception_is_not_flagged(self):
        system_id = "sys1"
        desired = build_desired_snapshot(system_id, ())
        current = build_observed_snapshot(system_id, ())
        still_valid = PolicyException(
            exception_id="exc-1",
            policy_id="POL-NET-001",
            resource_id="r1",
            finding_id="f1",
            managed_system_id=system_id,
            business_justification="justified",
            risk_statement="accepted",
            compensating_controls=(),
            requested_expiration=NOW + timedelta(days=30),
            requested_by="owner.one",
            evidence=(),
            correlation_id="corr-1",
            status=ExceptionStatus.ACTIVE,
            expires_at=NOW + timedelta(days=30),
        )
        findings = _detect(desired, None, current, active_exceptions=(still_valid,))
        assert not any(f.drift_type == DriftType.EXCEPTION for f in findings)


class TestConfigurationDrift:
    def test_dev_grade_settings_in_production_is_configuration_drift(self):
        from src.domain.entities.state_snapshot import DesiredStateSnapshot, ObservedStateSnapshot
        from src.domain.enums.environment import Environment

        system_id = "sys1"
        desired_resource = build_resource(
            "r1",
            system_id,
            environment=Environment.PRODUCTION,
            attributes=ResourceAttributes(dev_grade_setting_in_production=False),
        )
        current_resource = build_resource(
            "r1",
            system_id,
            environment=Environment.PRODUCTION,
            attributes=ResourceAttributes(dev_grade_setting_in_production=True),
        )
        desired = DesiredStateSnapshot(
            snapshot_id="d1",
            managed_system_id=system_id,
            source="test",
            resources=(desired_resource,),
            baseline=build_desired_snapshot(system_id, ()).baseline,
            submitted_by="tester",
        )
        current = ObservedStateSnapshot(
            snapshot_id="c1", managed_system_id=system_id, source="test", resources=(current_resource,)
        )
        findings = _detect(desired, None, current)
        drift = next(f for f in findings if f.policy_id == "POL-ENV-008")
        assert drift.drift_type == DriftType.CONFIGURATION


def test_no_drift_when_current_matches_desired_exactly():
    attrs = ResourceAttributes()
    desired, current = _snapshots(attrs, attrs)
    findings = _detect(desired, None, current)
    assert findings == ()


def test_previous_observed_is_optional_first_run():
    # The very first drift run for a system has no "previous observed"
    # snapshot yet; detect_drift must not require one.
    desired, current = _snapshots(
        ResourceAttributes(publicly_accessible=False), ResourceAttributes(publicly_accessible=True)
    )
    findings = _detect(desired, None, current)
    assert findings
