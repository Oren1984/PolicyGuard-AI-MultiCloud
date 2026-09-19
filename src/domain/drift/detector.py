"""Pure drift-detection engine (spec section 8).

Compares approved desired state, previously observed state, and current
observed state using typed field comparison — never raw text diffing — and
produces DriftFinding objects that satisfy the spec's full explanation
contract (what changed / previous / current / expected / why it matters /
policy / severity / evidence / remediation / exception eligibility).

No I/O, no non-deterministic behavior beyond the injected clock and id
factory.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime

from src.domain.entities.cloud_resource import CloudResource
from src.domain.entities.drift_finding import DriftFinding
from src.domain.entities.policy_exception import PolicyException
from src.domain.entities.state_snapshot import DesiredStateSnapshot, ObservedStateSnapshot
from src.domain.enums.drift_type import DriftType
from src.domain.enums.environment import Environment
from src.domain.enums.exception_status import ExceptionStatus
from src.domain.enums.policy_severity import PolicySeverity


def detect_drift(
    *,
    desired: DesiredStateSnapshot,
    previous_observed: ObservedStateSnapshot | None,
    current_observed: ObservedStateSnapshot,
    active_exceptions: Sequence[PolicyException],
    evaluation_time: datetime,
    correlation_id: str,
    id_factory: Callable[[], str],
) -> tuple[DriftFinding, ...]:
    desired_by_id = desired.resource_by_id()
    previous_by_id = previous_observed.resource_by_id() if previous_observed else {}
    current_by_id = current_observed.resource_by_id()

    findings: list[DriftFinding] = []

    for resource_id, current in current_by_id.items():
        desired_r = desired_by_id.get(resource_id)
        previous_r = previous_by_id.get(resource_id)

        if desired_r is None:
            findings.append(
                _finding(
                    id_factory=id_factory,
                    managed_system_id=current.managed_system_id,
                    resource_id=resource_id,
                    drift_type=DriftType.UNMANAGED_RESOURCE,
                    what_changed="A resource was observed that is not part of the approved desired state.",
                    previous_value=None,
                    current_value=f"resource_type={current.resource_type.value}, region={current.region}",
                    expected_value="resource absent from desired state (unmanaged)",
                    why_it_matters="Unmanaged resources bypass approval and policy evaluation entirely.",
                    severity=PolicySeverity.HIGH,
                    evidence=("desired_resource_present=false",),
                    remediation="Add the resource to the approved architecture or decommission it.",
                    exception_eligible=True,
                    policy_id="POL-ARC-009",
                    correlation_id=correlation_id,
                    evaluation_time=evaluation_time,
                )
            )
            continue

        findings.extend(
            _compare_resource(
                desired_r=desired_r,
                previous_r=previous_r,
                current_r=current,
                correlation_id=correlation_id,
                evaluation_time=evaluation_time,
                id_factory=id_factory,
            )
        )

    for resource_id, desired_r in desired_by_id.items():
        if resource_id in current_by_id:
            continue
        findings.append(
            _finding(
                id_factory=id_factory,
                managed_system_id=desired_r.managed_system_id,
                resource_id=resource_id,
                drift_type=DriftType.ARCHITECTURAL,
                what_changed="An approved resource is no longer present in the observed inventory.",
                previous_value=f"resource_type={desired_r.resource_type.value}, region={desired_r.region}",
                current_value=None,
                expected_value="resource present, matching the approved architecture",
                why_it_matters=(
                    "Unexplained disappearance may indicate unauthorized deletion or a blind spot."
                ),
                severity=PolicySeverity.MEDIUM,
                evidence=("current_resource_present=false",),
                remediation="Confirm intentional deprovisioning or investigate the missing resource.",
                exception_eligible=True,
                policy_id=None,
                correlation_id=correlation_id,
                evaluation_time=evaluation_time,
            )
        )

    findings.extend(
        _detect_exception_drift(
            active_exceptions=active_exceptions,
            evaluation_time=evaluation_time,
            correlation_id=correlation_id,
            id_factory=id_factory,
        )
    )
    return tuple(findings)


def _compare_resource(
    *,
    desired_r: CloudResource,
    previous_r: CloudResource | None,
    current_r: CloudResource,
    correlation_id: str,
    evaluation_time: datetime,
    id_factory: Callable[[], str],
) -> list[DriftFinding]:
    d, c = desired_r.attributes, current_r.attributes
    prior = previous_r.attributes if previous_r is not None else None
    out: list[DriftFinding] = []

    def emit(
        drift_type: DriftType,
        what_changed: str,
        previous_value: object,
        current_value: object,
        expected_value: object,
        why_it_matters: str,
        severity: PolicySeverity,
        evidence: tuple[str, ...],
        remediation: str,
        exception_eligible: bool,
        policy_id: str | None,
    ) -> None:
        out.append(
            _finding(
                id_factory=id_factory,
                managed_system_id=current_r.managed_system_id,
                resource_id=current_r.resource_id,
                drift_type=drift_type,
                what_changed=what_changed,
                previous_value=str(previous_value) if previous_value is not None else None,
                current_value=str(current_value) if current_value is not None else None,
                expected_value=str(expected_value) if expected_value is not None else None,
                why_it_matters=why_it_matters,
                severity=severity,
                evidence=evidence,
                remediation=remediation,
                exception_eligible=exception_eligible,
                policy_id=policy_id,
                correlation_id=correlation_id,
                evaluation_time=evaluation_time,
            )
        )

    # ---- Security drift --------------------------------------------------
    if c.publicly_accessible and not d.publicly_accessible:
        emit(
            DriftType.SECURITY,
            "Public network accessibility was enabled.",
            prior.publicly_accessible if prior else d.publicly_accessible,
            c.publicly_accessible,
            d.publicly_accessible,
            "Public exposure materially increases the resource's attack surface.",
            PolicySeverity.CRITICAL,
            ("attributes.publicly_accessible",),
            "Restrict inbound access to approved CIDR ranges or disable public access.",
            False,
            "POL-NET-001",
        )
    if not c.encryption_at_rest_enabled and d.encryption_at_rest_enabled:
        emit(
            DriftType.SECURITY,
            "Encryption at rest was disabled.",
            prior.encryption_at_rest_enabled if prior else d.encryption_at_rest_enabled,
            c.encryption_at_rest_enabled,
            True,
            "Data at rest is no longer protected against unauthorized disk-level access.",
            PolicySeverity.HIGH,
            ("attributes.encryption_at_rest_enabled",),
            "Re-enable encryption at rest.",
            True,
            "POL-ENC-003",
        )
    if c.secrets_in_plaintext_config and not d.secrets_in_plaintext_config:
        emit(
            DriftType.SECURITY,
            "A secret is now stored in plaintext configuration.",
            prior.secrets_in_plaintext_config if prior else d.secrets_in_plaintext_config,
            c.secrets_in_plaintext_config,
            False,
            "Plaintext secrets are readable by anyone with config access.",
            PolicySeverity.CRITICAL,
            ("attributes.secrets_in_plaintext_config",),
            "Move the secret to Secrets Manager / Secret Manager.",
            False,
            "POL-SEC-007",
        )
    if c.security_controls_removed_since_baseline:
        emit(
            DriftType.SECURITY,
            "A previously approved security control was removed.",
            "present",
            "removed",
            "present",
            "Removing a security control after deployment reopens a previously mitigated risk.",
            PolicySeverity.HIGH,
            ("attributes.security_controls_removed_since_baseline",),
            "Restore the removed control and investigate the change.",
            True,
            "POL-CTL-016",
        )

    # ---- Identity and permission drift ------------------------------------
    if (c.iam_wildcard_action or c.iam_wildcard_resource) and not (
        d.iam_wildcard_action or d.iam_wildcard_resource
    ):
        emit(
            DriftType.IDENTITY_AND_PERMISSION,
            "IAM permissions were widened to include a wildcard action/resource.",
            f"action={prior.iam_wildcard_action if prior else d.iam_wildcard_action}",
            f"action={c.iam_wildcard_action}, resource={c.iam_wildcard_resource}",
            "action=false, resource=false",
            "Wildcard IAM permissions grant far more access than intended.",
            PolicySeverity.HIGH,
            ("attributes.iam_wildcard_action", "attributes.iam_wildcard_resource"),
            "Scope the IAM policy to least-privilege actions and resources.",
            True,
            "POL-IAM-002",
        )
    if c.privilege_escalation_enabled and not d.privilege_escalation_enabled:
        emit(
            DriftType.IDENTITY_AND_PERMISSION,
            "A privilege-escalation path was introduced.",
            prior.privilege_escalation_enabled if prior else d.privilege_escalation_enabled,
            c.privilege_escalation_enabled,
            False,
            "Privilege escalation paths let a low-privilege identity gain broader access.",
            PolicySeverity.CRITICAL,
            ("attributes.privilege_escalation_enabled",),
            "Remove the permissions/trust relationship enabling escalation.",
            False,
            "POL-PRI-015",
        )

    # ---- Operational-control drift ----------------------------------------
    if not c.audit_logging_enabled and d.audit_logging_enabled:
        emit(
            DriftType.OPERATIONAL_CONTROL,
            "Audit logging was disabled.",
            prior.audit_logging_enabled if prior else d.audit_logging_enabled,
            c.audit_logging_enabled,
            True,
            "Without audit logging, subsequent activity on this resource is unaccountable.",
            PolicySeverity.MEDIUM,
            ("attributes.audit_logging_enabled",),
            "Re-enable CloudTrail / Cloud Audit Logs for this resource.",
            True,
            "POL-LOG-004",
        )
    if not c.monitoring_enabled and d.monitoring_enabled:
        emit(
            DriftType.OPERATIONAL_CONTROL,
            "Monitoring/alerting was disabled.",
            prior.monitoring_enabled if prior else d.monitoring_enabled,
            c.monitoring_enabled,
            True,
            "Without monitoring, operational or security incidents may go undetected.",
            PolicySeverity.MEDIUM,
            ("attributes.monitoring_enabled",),
            "Re-enable CloudWatch / Cloud Monitoring alerting.",
            True,
            "POL-MON-005",
        )
    if not c.backup_enabled and d.backup_enabled:
        emit(
            DriftType.OPERATIONAL_CONTROL,
            "Backups were disabled.",
            prior.backup_enabled if prior else d.backup_enabled,
            c.backup_enabled,
            True,
            "Without backups, this resource cannot be recovered from data loss or corruption.",
            PolicySeverity.MEDIUM,
            ("attributes.backup_enabled",),
            "Re-enable automated backups with a defined retention policy.",
            True,
            "POL-BAK-006",
        )
    if not c.high_availability_configured and d.high_availability_configured:
        emit(
            DriftType.OPERATIONAL_CONTROL,
            "High-availability configuration was removed.",
            prior.high_availability_configured if prior else d.high_availability_configured,
            c.high_availability_configured,
            True,
            "Losing high-availability configuration increases outage risk for a critical resource.",
            PolicySeverity.MEDIUM,
            ("attributes.high_availability_configured",),
            "Restore multi-AZ / multi-zone high-availability configuration.",
            True,
            "POL-HAV-018",
        )

    # ---- Compliance drift ---------------------------------------------------
    if c.owner_tag != d.owner_tag and (not c.owner_tag or d.owner_tag):
        emit(
            DriftType.COMPLIANCE,
            "Ownership metadata changed or was removed.",
            d.owner_tag,
            c.owner_tag,
            d.owner_tag,
            "Missing ownership metadata breaks accountability for the resource.",
            PolicySeverity.LOW,
            ("attributes.owner_tag",),
            "Restore an accurate owner tag.",
            True,
            "POL-OWN-011",
        )
    if not c.required_tags_present and d.required_tags_present:
        emit(
            DriftType.COMPLIANCE,
            "One or more required tags were removed.",
            d.required_tags_present,
            c.required_tags_present,
            True,
            "Missing required tags breaks cost, ownership, or compliance reporting.",
            PolicySeverity.LOW,
            ("attributes.required_tags_present",),
            "Reapply the missing required tags.",
            True,
            "POL-TAG-012",
        )
    if c.runtime_version != d.runtime_version and d.runtime_version is not None:
        emit(
            DriftType.COMPLIANCE,
            "The runtime version changed.",
            d.runtime_version,
            c.runtime_version,
            d.runtime_version,
            "An unreviewed runtime version change may introduce unsupported or vulnerable software.",
            PolicySeverity.MEDIUM,
            ("attributes.runtime_version",),
            "Confirm the new runtime version is supported or roll back.",
            True,
            "POL-VER-013",
        )
    if not c.data_retention_compliant and d.data_retention_compliant:
        emit(
            DriftType.COMPLIANCE,
            "Data-retention configuration fell out of compliance.",
            d.data_retention_days,
            c.data_retention_days,
            "compliant retention window",
            "Non-compliant retention can violate contractual or regulatory obligations.",
            PolicySeverity.MEDIUM,
            ("attributes.data_retention_compliant", "attributes.data_retention_days"),
            "Adjust the retention configuration to meet the required minimum.",
            True,
            "POL-RET-017",
        )

    # ---- Architectural drift -------------------------------------------------
    if current_r.region != desired_r.region:
        emit(
            DriftType.ARCHITECTURAL,
            "The resource's region changed from the approved region.",
            desired_r.region,
            current_r.region,
            desired_r.region,
            "Region changes can move data outside an approved data-residency boundary.",
            PolicySeverity.HIGH,
            ("region",),
            "Migrate the resource back to an approved region or update the baseline.",
            True,
            "POL-REG-010",
        )
    if not c.matches_architecture_baseline and d.matches_architecture_baseline:
        emit(
            DriftType.ARCHITECTURAL,
            "The resource no longer matches the approved architecture/Terraform baseline.",
            d.matches_architecture_baseline,
            c.matches_architecture_baseline,
            True,
            "Architecture drift undermines the guarantees the approved design was reviewed for.",
            PolicySeverity.MEDIUM,
            ("attributes.matches_architecture_baseline",),
            "Reconcile the resource with the approved Terraform/architecture baseline.",
            True,
            "POL-BAS-019",
        )

    # ---- Configuration drift (generic, catch-all typed fields) --------------
    if c.dev_grade_setting_in_production and not d.dev_grade_setting_in_production:
        env_is_prod = current_r.environment == Environment.PRODUCTION
        if env_is_prod:
            emit(
                DriftType.CONFIGURATION,
                "Production resource began using development-grade settings.",
                d.dev_grade_setting_in_production,
                c.dev_grade_setting_in_production,
                False,
                "Development-grade settings in production typically weaken hardening and reliability.",
                PolicySeverity.HIGH,
                ("attributes.dev_grade_setting_in_production", "environment"),
                "Apply the production configuration profile.",
                True,
                "POL-ENV-008",
            )
    if c.modified_outside_maintenance_window:
        emit(
            DriftType.CONFIGURATION,
            "The resource was modified outside its approved maintenance window.",
            False,
            True,
            False,
            "Unplanned changes outside maintenance windows increase operational risk.",
            PolicySeverity.LOW,
            ("attributes.modified_outside_maintenance_window",),
            "Schedule future changes within the approved maintenance window.",
            True,
            "POL-MTW-014",
        )

    return out


def _detect_exception_drift(
    *,
    active_exceptions: Sequence[PolicyException],
    evaluation_time: datetime,
    correlation_id: str,
    id_factory: Callable[[], str],
) -> list[DriftFinding]:
    """Flags exceptions that are still ACTIVE in the repository but have
    passed their expiration timestamp — they must stop suppressing findings
    immediately (spec section 12), so this is surfaced as drift in its own
    right, not silently handled."""
    out: list[DriftFinding] = []
    for exception in active_exceptions:
        if exception.status != ExceptionStatus.ACTIVE or exception.expires_at is None:
            continue
        if exception.expires_at > evaluation_time:
            continue
        out.append(
            _finding(
                id_factory=id_factory,
                managed_system_id=exception.managed_system_id,
                resource_id=exception.resource_id,
                drift_type=DriftType.EXCEPTION,
                what_changed="An active exception passed its expiration timestamp.",
                previous_value="status=active",
                current_value=f"expires_at={exception.expires_at.isoformat()}",
                expected_value="status=expired",
                why_it_matters=(
                    "An expired exception must stop suppressing findings immediately (fail closed)."
                ),
                severity=PolicySeverity.HIGH,
                evidence=(f"exception_id={exception.exception_id}",),
                remediation="Transition the exception to EXPIRED and re-evaluate the underlying violation.",
                exception_eligible=False,
                policy_id="POL-EXC-020",
                correlation_id=correlation_id,
                evaluation_time=evaluation_time,
            )
        )
    return out


def _finding(
    *,
    id_factory: Callable[[], str],
    managed_system_id: str,
    resource_id: str,
    drift_type: DriftType,
    what_changed: str,
    previous_value: str | None,
    current_value: str | None,
    expected_value: str | None,
    why_it_matters: str,
    severity: PolicySeverity,
    evidence: tuple[str, ...],
    remediation: str,
    exception_eligible: bool,
    policy_id: str | None,
    correlation_id: str,
    evaluation_time: datetime,
) -> DriftFinding:
    return DriftFinding(
        finding_id=id_factory(),
        managed_system_id=managed_system_id,
        resource_id=resource_id,
        drift_type=drift_type,
        what_changed=what_changed,
        previous_value=previous_value,
        current_value=current_value,
        expected_value=expected_value,
        why_it_matters=why_it_matters,
        severity=severity,
        evidence=evidence,
        remediation=remediation,
        exception_eligible=exception_eligible,
        policy_id=policy_id,
        correlation_id=correlation_id,
        detected_at=evaluation_time,
    )
