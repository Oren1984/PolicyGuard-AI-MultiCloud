"""The 20 required deterministic policy definitions (spec section 7).

Every `evaluate` function is a pure function of a PolicyEvaluationContext:
no I/O, no clock reads beyond the context's own `evaluation_time`, no
randomness, and no LLM call. Each is independently unit-testable.
"""

from __future__ import annotations

from src.domain.entities.policy import Policy, PolicyEvaluationContext, PolicyPack
from src.domain.enums.policy_category import PolicyCategory
from src.domain.enums.policy_severity import PolicySeverity
from src.domain.enums.resource_criticality import ResourceCriticality
from src.domain.enums.resource_type import ResourceType


def _pol_public_network_exposure(ctx: PolicyEvaluationContext):
    from src.domain.entities.policy import PolicyCheckOutcome

    if ctx.resource.attributes.publicly_accessible:
        return PolicyCheckOutcome(
            passed=False,
            explanation=f"{ctx.resource.name} ({ctx.resource.resource_id}) is publicly accessible.",
            evidence=("attributes.publicly_accessible=true",),
        )
    return PolicyCheckOutcome(passed=True, explanation="")


def _pol_overly_permissive_iam(ctx: PolicyEvaluationContext):
    from src.domain.entities.policy import PolicyCheckOutcome

    a = ctx.resource.attributes
    if a.iam_wildcard_action or a.iam_wildcard_resource:
        return PolicyCheckOutcome(
            passed=False,
            explanation=f"{ctx.resource.name} grants wildcard IAM action and/or resource permissions.",
            evidence=(
                f"attributes.iam_wildcard_action={a.iam_wildcard_action}",
                f"attributes.iam_wildcard_resource={a.iam_wildcard_resource}",
            ),
        )
    return PolicyCheckOutcome(passed=True, explanation="")


_STORAGE_TYPES = frozenset({ResourceType.OBJECT_STORAGE_BUCKET, ResourceType.RELATIONAL_DATABASE})


def _pol_unencrypted_storage(ctx: PolicyEvaluationContext):
    from src.domain.entities.policy import PolicyCheckOutcome

    if ctx.resource.resource_type not in _STORAGE_TYPES:
        return PolicyCheckOutcome(passed=True, explanation="not applicable to this resource type")
    if not ctx.resource.attributes.encryption_at_rest_enabled:
        return PolicyCheckOutcome(
            passed=False,
            explanation=f"{ctx.resource.name} does not have encryption at rest enabled.",
            evidence=("attributes.encryption_at_rest_enabled=false",),
        )
    return PolicyCheckOutcome(passed=True, explanation="")


def _pol_missing_logging(ctx: PolicyEvaluationContext):
    from src.domain.entities.policy import PolicyCheckOutcome

    if not ctx.resource.attributes.audit_logging_enabled:
        return PolicyCheckOutcome(
            passed=False,
            explanation=f"{ctx.resource.name} has audit logging disabled or missing.",
            evidence=("attributes.audit_logging_enabled=false",),
        )
    return PolicyCheckOutcome(passed=True, explanation="")


def _pol_disabled_monitoring(ctx: PolicyEvaluationContext):
    from src.domain.entities.policy import PolicyCheckOutcome

    if not ctx.resource.attributes.monitoring_enabled:
        return PolicyCheckOutcome(
            passed=False,
            explanation=f"{ctx.resource.name} has monitoring/alerting disabled.",
            evidence=("attributes.monitoring_enabled=false",),
        )
    return PolicyCheckOutcome(passed=True, explanation="")


_BACKUP_APPLICABLE_TYPES = frozenset(
    {ResourceType.RELATIONAL_DATABASE, ResourceType.OBJECT_STORAGE_BUCKET}
)


def _pol_missing_backup(ctx: PolicyEvaluationContext):
    from src.domain.entities.policy import PolicyCheckOutcome

    if ctx.resource.resource_type not in _BACKUP_APPLICABLE_TYPES:
        return PolicyCheckOutcome(passed=True, explanation="not applicable to this resource type")
    if not ctx.resource.attributes.backup_enabled:
        return PolicyCheckOutcome(
            passed=False,
            explanation=f"{ctx.resource.name} has no backup/recovery configuration.",
            evidence=("attributes.backup_enabled=false",),
        )
    return PolicyCheckOutcome(passed=True, explanation="")


def _pol_unsafe_secrets_storage(ctx: PolicyEvaluationContext):
    from src.domain.entities.policy import PolicyCheckOutcome

    if ctx.resource.attributes.secrets_in_plaintext_config:
        return PolicyCheckOutcome(
            passed=False,
            explanation=f"{ctx.resource.name} stores secrets in plaintext configuration fields.",
            evidence=("attributes.secrets_in_plaintext_config=true",),
        )
    return PolicyCheckOutcome(passed=True, explanation="")


def _pol_prod_using_dev_settings(ctx: PolicyEvaluationContext):
    from src.domain.entities.policy import PolicyCheckOutcome
    from src.domain.enums.environment import Environment

    if ctx.resource.environment != Environment.PRODUCTION:
        return PolicyCheckOutcome(passed=True, explanation="not applicable outside production")
    if ctx.resource.attributes.dev_grade_setting_in_production:
        return PolicyCheckOutcome(
            passed=False,
            explanation=f"{ctx.resource.name} runs in production with development-grade settings.",
            evidence=("attributes.dev_grade_setting_in_production=true", "environment=production"),
        )
    return PolicyCheckOutcome(passed=True, explanation="")


def _pol_unapproved_baseline_resource(ctx: PolicyEvaluationContext):
    from src.domain.entities.policy import PolicyCheckOutcome

    if ctx.desired_resource is None or not ctx.resource.attributes.within_approved_baseline:
        return PolicyCheckOutcome(
            passed=False,
            explanation=f"{ctx.resource.name} exists outside the approved architecture baseline.",
            evidence=(f"desired_resource_present={ctx.desired_resource is not None}",),
        )
    return PolicyCheckOutcome(passed=True, explanation="")


def _pol_unauthorized_region(ctx: PolicyEvaluationContext):
    from src.domain.entities.policy import PolicyCheckOutcome

    if not ctx.baseline.allowed_regions:
        return PolicyCheckOutcome(passed=True, explanation="no region allow-list configured")
    if ctx.resource.region not in ctx.baseline.allowed_regions:
        return PolicyCheckOutcome(
            passed=False,
            explanation=f"{ctx.resource.name} is deployed in unauthorized region '{ctx.resource.region}'.",
            evidence=(f"region={ctx.resource.region}", f"allowed_regions={ctx.baseline.allowed_regions}"),
        )
    return PolicyCheckOutcome(passed=True, explanation="")


def _pol_missing_ownership_metadata(ctx: PolicyEvaluationContext):
    from src.domain.entities.policy import PolicyCheckOutcome

    owner = ctx.resource.attributes.owner_tag
    if not owner:
        return PolicyCheckOutcome(
            passed=False,
            explanation=f"{ctx.resource.name} has no ownership/accountability metadata.",
            evidence=("attributes.owner_tag=<missing>",),
        )
    return PolicyCheckOutcome(passed=True, explanation="")


def _pol_missing_required_tags(ctx: PolicyEvaluationContext):
    from src.domain.entities.policy import PolicyCheckOutcome

    if not ctx.baseline.required_tag_keys:
        return PolicyCheckOutcome(passed=True, explanation="no required tags configured")
    missing = tuple(k for k in ctx.baseline.required_tag_keys if k not in ctx.resource.tags)
    if missing:
        return PolicyCheckOutcome(
            passed=False,
            explanation=f"{ctx.resource.name} is missing required tags: {', '.join(missing)}.",
            evidence=(f"missing_tag_keys={missing}",),
        )
    return PolicyCheckOutcome(passed=True, explanation="")


def _pol_unsupported_runtime_version(ctx: PolicyEvaluationContext):
    from src.domain.entities.policy import PolicyCheckOutcome

    a = ctx.resource.attributes
    if a.runtime_version is None:
        return PolicyCheckOutcome(passed=True, explanation="no runtime version reported")
    supported = ctx.baseline.supported_runtime_versions
    version_allowed = (not supported) or (a.runtime_version in supported)
    if not a.runtime_version_supported or not version_allowed:
        return PolicyCheckOutcome(
            passed=False,
            explanation=f"{ctx.resource.name} runs unsupported runtime version '{a.runtime_version}'.",
            evidence=(f"runtime_version={a.runtime_version}", f"supported_runtime_versions={supported}"),
        )
    return PolicyCheckOutcome(passed=True, explanation="")


def _pol_outside_maintenance_window(ctx: PolicyEvaluationContext):
    from src.domain.entities.policy import PolicyCheckOutcome

    if ctx.resource.attributes.modified_outside_maintenance_window:
        return PolicyCheckOutcome(
            passed=False,
            explanation=f"{ctx.resource.name} was modified outside an approved maintenance window.",
            evidence=("attributes.modified_outside_maintenance_window=true",),
        )
    return PolicyCheckOutcome(passed=True, explanation="")


def _pol_privilege_escalation(ctx: PolicyEvaluationContext):
    from src.domain.entities.policy import PolicyCheckOutcome

    if ctx.resource.attributes.privilege_escalation_enabled:
        return PolicyCheckOutcome(
            passed=False,
            explanation=f"{ctx.resource.name} allows excessive privilege escalation.",
            evidence=("attributes.privilege_escalation_enabled=true",),
        )
    return PolicyCheckOutcome(passed=True, explanation="")


def _pol_security_control_removed(ctx: PolicyEvaluationContext):
    from src.domain.entities.policy import PolicyCheckOutcome

    if ctx.resource.attributes.security_controls_removed_since_baseline:
        return PolicyCheckOutcome(
            passed=False,
            explanation=f"{ctx.resource.name} had a security control removed after deployment.",
            evidence=("attributes.security_controls_removed_since_baseline=true",),
        )
    return PolicyCheckOutcome(passed=True, explanation="")


def _pol_data_retention_violation(ctx: PolicyEvaluationContext):
    from src.domain.entities.policy import PolicyCheckOutcome

    a = ctx.resource.attributes
    required = ctx.baseline.required_retention_days
    below_minimum = (
        required is not None and a.data_retention_days is not None and a.data_retention_days < required
    )
    if not a.data_retention_compliant or below_minimum:
        return PolicyCheckOutcome(
            passed=False,
            explanation=f"{ctx.resource.name} violates the required data-retention policy.",
            evidence=(f"data_retention_days={a.data_retention_days}", f"required_retention_days={required}"),
        )
    return PolicyCheckOutcome(passed=True, explanation="")


_HA_APPLICABLE_TYPES = frozenset({ResourceType.RELATIONAL_DATABASE, ResourceType.CONTAINER_SERVICE})


def _pol_missing_high_availability(ctx: PolicyEvaluationContext):
    from src.domain.entities.policy import PolicyCheckOutcome

    applicable = (
        ctx.resource.criticality == ResourceCriticality.CRITICAL
        or ctx.resource.resource_type in _HA_APPLICABLE_TYPES
    )
    if not applicable:
        return PolicyCheckOutcome(passed=True, explanation="not applicable to this resource")
    if not ctx.resource.attributes.high_availability_configured:
        return PolicyCheckOutcome(
            passed=False,
            explanation=(
                f"{ctx.resource.name} is a critical resource without high-availability configuration."
            ),
            evidence=("attributes.high_availability_configured=false",),
        )
    return PolicyCheckOutcome(passed=True, explanation="")


def _pol_architecture_baseline_drift(ctx: PolicyEvaluationContext):
    from src.domain.entities.policy import PolicyCheckOutcome

    if not ctx.resource.attributes.matches_architecture_baseline:
        return PolicyCheckOutcome(
            passed=False,
            explanation=f"{ctx.resource.name} has drifted from the approved Terraform/architecture snapshot.",
            evidence=("attributes.matches_architecture_baseline=false",),
        )
    return PolicyCheckOutcome(passed=True, explanation="")


def _pol_expired_policy_exception(ctx: PolicyEvaluationContext):
    from src.domain.entities.policy import PolicyCheckOutcome

    if ctx.has_expired_or_revoked_exception_on_record:
        return PolicyCheckOutcome(
            passed=False,
            explanation=(
                f"{ctx.resource.name} has an expired or revoked policy exception on record; "
                "the underlying violation is no longer suppressed and must be re-reviewed."
            ),
            evidence=("has_expired_or_revoked_exception_on_record=true",),
        )
    return PolicyCheckOutcome(passed=True, explanation="")


def build_default_policy_pack() -> PolicyPack:
    """Builds the reference PolicyPack covering all 20 required categories.
    Stable, hand-assigned policy IDs — never regenerated at runtime."""
    policies = (
        Policy(
            policy_id="POL-NET-001",
            title="Public network exposure",
            description="Resource must not be reachable directly from the public internet.",
            category=PolicyCategory.PUBLIC_NETWORK_EXPOSURE,
            severity=PolicySeverity.CRITICAL,
            evaluate=_pol_public_network_exposure,
            required_evidence=("attributes.publicly_accessible",),
            explanation_template="{resource_name} is publicly accessible from the internet.",
            remediation_guidance="Restrict inbound access to approved CIDR ranges or disable public access.",
            exception_eligible=False,
        ),
        Policy(
            policy_id="POL-IAM-002",
            title="Overly permissive IAM roles or wildcard permissions",
            description="IAM policies must not grant wildcard actions or resources.",
            category=PolicyCategory.OVERLY_PERMISSIVE_IAM,
            severity=PolicySeverity.HIGH,
            evaluate=_pol_overly_permissive_iam,
            required_evidence=("attributes.iam_wildcard_action", "attributes.iam_wildcard_resource"),
            explanation_template="{resource_name} grants wildcard IAM permissions.",
            remediation_guidance="Scope IAM policies to least-privilege actions and resources.",
            exception_eligible=True,
        ),
        Policy(
            policy_id="POL-ENC-003",
            title="Unencrypted storage or databases",
            description="Storage and database resources must have encryption at rest enabled.",
            category=PolicyCategory.UNENCRYPTED_STORAGE,
            severity=PolicySeverity.HIGH,
            evaluate=_pol_unencrypted_storage,
            required_evidence=("attributes.encryption_at_rest_enabled",),
            explanation_template="{resource_name} lacks encryption at rest.",
            remediation_guidance="Enable provider-managed or customer-managed encryption at rest.",
            exception_eligible=True,
        ),
        Policy(
            policy_id="POL-LOG-004",
            title="Missing logging or audit controls",
            description="Resources must have audit logging enabled.",
            category=PolicyCategory.MISSING_LOGGING,
            severity=PolicySeverity.MEDIUM,
            evaluate=_pol_missing_logging,
            required_evidence=("attributes.audit_logging_enabled",),
            explanation_template="{resource_name} has audit logging disabled.",
            remediation_guidance="Enable CloudTrail / Cloud Audit Logs for this resource.",
            exception_eligible=True,
        ),
        Policy(
            policy_id="POL-MON-005",
            title="Disabled monitoring or alerting",
            description="Resources must have monitoring/alerting enabled.",
            category=PolicyCategory.DISABLED_MONITORING,
            severity=PolicySeverity.MEDIUM,
            evaluate=_pol_disabled_monitoring,
            required_evidence=("attributes.monitoring_enabled",),
            explanation_template="{resource_name} has monitoring disabled.",
            remediation_guidance="Enable CloudWatch / Cloud Monitoring alerting for this resource.",
            exception_eligible=True,
        ),
        Policy(
            policy_id="POL-BAK-006",
            title="Missing backup or recovery controls",
            description="Stateful resources must have backups enabled.",
            category=PolicyCategory.MISSING_BACKUP,
            severity=PolicySeverity.MEDIUM,
            evaluate=_pol_missing_backup,
            required_evidence=("attributes.backup_enabled",),
            explanation_template="{resource_name} has no backup/recovery configuration.",
            remediation_guidance="Enable automated backups with a defined retention policy.",
            exception_eligible=True,
        ),
        Policy(
            policy_id="POL-SEC-007",
            title="Secrets stored in unsafe configuration fields",
            description="Secrets must never be stored in plaintext configuration.",
            category=PolicyCategory.UNSAFE_SECRETS_STORAGE,
            severity=PolicySeverity.CRITICAL,
            evaluate=_pol_unsafe_secrets_storage,
            required_evidence=("attributes.secrets_in_plaintext_config",),
            explanation_template="{resource_name} stores secrets in plaintext.",
            remediation_guidance="Move secrets to Secrets Manager / Secret Manager references.",
            exception_eligible=False,
        ),
        Policy(
            policy_id="POL-ENV-008",
            title="Production resources using development-grade settings",
            description="Production resources must not run with dev-grade configuration.",
            category=PolicyCategory.PROD_USING_DEV_SETTINGS,
            severity=PolicySeverity.HIGH,
            evaluate=_pol_prod_using_dev_settings,
            required_evidence=("attributes.dev_grade_setting_in_production", "environment"),
            explanation_template="{resource_name} runs production with development-grade settings.",
            remediation_guidance="Apply the production configuration profile to this resource.",
            exception_eligible=True,
        ),
        Policy(
            policy_id="POL-ARC-009",
            title="Resources created outside the approved architecture baseline",
            description="Every observed resource must map to an approved desired-state resource.",
            category=PolicyCategory.UNAPPROVED_BASELINE_RESOURCE,
            severity=PolicySeverity.MEDIUM,
            evaluate=_pol_unapproved_baseline_resource,
            required_evidence=("desired_resource_present", "attributes.within_approved_baseline"),
            explanation_template="{resource_name} exists outside the approved baseline.",
            remediation_guidance="Add the resource to the approved architecture or decommission it.",
            exception_eligible=True,
        ),
        Policy(
            policy_id="POL-REG-010",
            title="Unauthorized region usage",
            description="Resources must be deployed only in approved regions.",
            category=PolicyCategory.UNAUTHORIZED_REGION,
            severity=PolicySeverity.HIGH,
            evaluate=_pol_unauthorized_region,
            required_evidence=("region", "baseline.allowed_regions"),
            explanation_template="{resource_name} is deployed in an unauthorized region.",
            remediation_guidance="Migrate the resource to an approved region.",
            exception_eligible=True,
        ),
        Policy(
            policy_id="POL-OWN-011",
            title="Missing ownership or accountability metadata",
            description="Every resource must declare an accountable owner.",
            category=PolicyCategory.MISSING_OWNERSHIP_METADATA,
            severity=PolicySeverity.LOW,
            evaluate=_pol_missing_ownership_metadata,
            required_evidence=("attributes.owner_tag",),
            explanation_template="{resource_name} has no declared owner.",
            remediation_guidance="Set an owner tag identifying the accountable team or individual.",
            exception_eligible=True,
        ),
        Policy(
            policy_id="POL-TAG-012",
            title="Missing required tags or labels",
            description="Resources must carry all organizationally required tags.",
            category=PolicyCategory.MISSING_REQUIRED_TAGS,
            severity=PolicySeverity.LOW,
            evaluate=_pol_missing_required_tags,
            required_evidence=("tags", "baseline.required_tag_keys"),
            explanation_template="{resource_name} is missing required tags.",
            remediation_guidance="Apply the missing required tags/labels.",
            exception_eligible=True,
        ),
        Policy(
            policy_id="POL-VER-013",
            title="Unsupported software or runtime versions",
            description="Runtimes must be within the supported version list.",
            category=PolicyCategory.UNSUPPORTED_RUNTIME_VERSION,
            severity=PolicySeverity.MEDIUM,
            evaluate=_pol_unsupported_runtime_version,
            required_evidence=("attributes.runtime_version", "baseline.supported_runtime_versions"),
            explanation_template="{resource_name} runs an unsupported runtime version.",
            remediation_guidance="Upgrade to a supported runtime version.",
            exception_eligible=True,
        ),
        Policy(
            policy_id="POL-MTW-014",
            title="Configuration changes outside approved maintenance windows",
            description="Changes must occur inside an approved maintenance window.",
            category=PolicyCategory.OUTSIDE_MAINTENANCE_WINDOW,
            severity=PolicySeverity.LOW,
            evaluate=_pol_outside_maintenance_window,
            required_evidence=("attributes.modified_outside_maintenance_window",),
            explanation_template="{resource_name} was changed outside its maintenance window.",
            remediation_guidance="Schedule future changes within the approved maintenance window.",
            exception_eligible=True,
        ),
        Policy(
            policy_id="POL-PRI-015",
            title="Excessive privilege escalation",
            description="Resources must not allow privilege escalation paths.",
            category=PolicyCategory.PRIVILEGE_ESCALATION,
            severity=PolicySeverity.CRITICAL,
            evaluate=_pol_privilege_escalation,
            required_evidence=("attributes.privilege_escalation_enabled",),
            explanation_template="{resource_name} allows privilege escalation.",
            remediation_guidance="Remove the permissions or trust relationships enabling escalation.",
            exception_eligible=False,
        ),
        Policy(
            policy_id="POL-CTL-016",
            title="Security controls removed after deployment",
            description="Previously approved security controls must remain in place.",
            category=PolicyCategory.SECURITY_CONTROL_REMOVED,
            severity=PolicySeverity.HIGH,
            evaluate=_pol_security_control_removed,
            required_evidence=("attributes.security_controls_removed_since_baseline",),
            explanation_template="{resource_name} had a security control removed post-deployment.",
            remediation_guidance="Restore the removed security control and investigate the change.",
            exception_eligible=True,
        ),
        Policy(
            policy_id="POL-RET-017",
            title="Data-retention policy violations",
            description="Data retention must meet the configured minimum.",
            category=PolicyCategory.DATA_RETENTION_VIOLATION,
            severity=PolicySeverity.MEDIUM,
            evaluate=_pol_data_retention_violation,
            required_evidence=("attributes.data_retention_days", "baseline.required_retention_days"),
            explanation_template="{resource_name} violates the data-retention policy.",
            remediation_guidance="Adjust the retention configuration to meet the required minimum.",
            exception_eligible=True,
        ),
        Policy(
            policy_id="POL-HAV-018",
            title="Critical resources without high-availability configuration",
            description="Critical resources must be configured for high availability.",
            category=PolicyCategory.MISSING_HIGH_AVAILABILITY,
            severity=PolicySeverity.MEDIUM,
            evaluate=_pol_missing_high_availability,
            required_evidence=("attributes.high_availability_configured", "criticality"),
            explanation_template="{resource_name} is critical but not highly available.",
            remediation_guidance="Enable multi-AZ / multi-zone high-availability configuration.",
            exception_eligible=True,
        ),
        Policy(
            policy_id="POL-BAS-019",
            title="Drift from an approved Terraform or architecture snapshot",
            description="Observed configuration must match the approved architecture snapshot.",
            category=PolicyCategory.ARCHITECTURE_BASELINE_DRIFT,
            severity=PolicySeverity.MEDIUM,
            evaluate=_pol_architecture_baseline_drift,
            required_evidence=("attributes.matches_architecture_baseline",),
            explanation_template="{resource_name} has drifted from the approved architecture snapshot.",
            remediation_guidance="Reconcile the resource with the approved Terraform/architecture baseline.",
            exception_eligible=True,
        ),
        Policy(
            policy_id="POL-EXC-020",
            title="Expired policy exceptions",
            description="An expired or revoked exception must no longer suppress its violation.",
            category=PolicyCategory.EXPIRED_POLICY_EXCEPTION,
            severity=PolicySeverity.HIGH,
            evaluate=_pol_expired_policy_exception,
            required_evidence=("has_expired_or_revoked_exception_on_record",),
            explanation_template=(
                "{resource_name} has an expired/revoked exception no longer suppressing a violation."
            ),
            remediation_guidance="Re-request an exception or remediate the underlying violation immediately.",
            exception_eligible=False,
        ),
    )
    return PolicyPack(
        pack_id="PACK-DEFAULT-001",
        name="PolicyGuard Default Reference Pack",
        version=1,
        policies=policies,
        active=True,
        description="The 20 required reference policy categories (spec section 7).",
    )
