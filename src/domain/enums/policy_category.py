from enum import StrEnum


class PolicyCategory(StrEnum):
    """The 20 required policy categories (spec section 7)."""

    PUBLIC_NETWORK_EXPOSURE = "public_network_exposure"
    OVERLY_PERMISSIVE_IAM = "overly_permissive_iam"
    UNENCRYPTED_STORAGE = "unencrypted_storage"
    MISSING_LOGGING = "missing_logging"
    DISABLED_MONITORING = "disabled_monitoring"
    MISSING_BACKUP = "missing_backup"
    UNSAFE_SECRETS_STORAGE = "unsafe_secrets_storage"
    PROD_USING_DEV_SETTINGS = "prod_using_dev_settings"
    UNAPPROVED_BASELINE_RESOURCE = "unapproved_baseline_resource"
    UNAUTHORIZED_REGION = "unauthorized_region"
    MISSING_OWNERSHIP_METADATA = "missing_ownership_metadata"
    MISSING_REQUIRED_TAGS = "missing_required_tags"
    UNSUPPORTED_RUNTIME_VERSION = "unsupported_runtime_version"
    OUTSIDE_MAINTENANCE_WINDOW = "outside_maintenance_window"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SECURITY_CONTROL_REMOVED = "security_control_removed"
    DATA_RETENTION_VIOLATION = "data_retention_violation"
    MISSING_HIGH_AVAILABILITY = "missing_high_availability"
    ARCHITECTURE_BASELINE_DRIFT = "architecture_baseline_drift"
    EXPIRED_POLICY_EXCEPTION = "expired_policy_exception"
