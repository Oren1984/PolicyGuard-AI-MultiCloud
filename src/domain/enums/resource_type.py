from enum import StrEnum


class ResourceType(StrEnum):
    """Provider-independent normalized resource categories.

    Cloud adapters (built in a later phase) must translate provider-specific
    resource kinds into these normalized types. Mapping used by this POC
    (see section 6 of the spec):

    AWS                              -> ResourceType
    ---------------------------------------------------
    IAM roles / policies             -> IAM_ROLE
    Security groups                  -> SECURITY_GROUP
    S3 buckets                       -> OBJECT_STORAGE_BUCKET
    RDS instances                    -> RELATIONAL_DATABASE
    ECS services                     -> CONTAINER_SERVICE
    Secrets Manager references       -> SECRETS_REFERENCE
    CloudTrail configuration         -> AUDIT_LOG_CONFIG
    CloudWatch logging configuration -> MONITORING_CONFIG

    GCP                              -> ResourceType
    ---------------------------------------------------
    IAM bindings / service accounts  -> IAM_BINDING
    VPC firewall rules               -> FIREWALL_RULE
    Cloud Storage buckets            -> OBJECT_STORAGE_BUCKET
    Cloud SQL instances               -> RELATIONAL_DATABASE
    Cloud Run services                -> CONTAINER_SERVICE
    Secret Manager references         -> SECRETS_REFERENCE
    Cloud Audit Logs configuration    -> AUDIT_LOG_CONFIG
    Cloud Monitoring configuration    -> MONITORING_CONFIG
    """

    IAM_ROLE = "iam_role"
    IAM_BINDING = "iam_binding"
    SECURITY_GROUP = "security_group"
    FIREWALL_RULE = "firewall_rule"
    OBJECT_STORAGE_BUCKET = "object_storage_bucket"
    RELATIONAL_DATABASE = "relational_database"
    CONTAINER_SERVICE = "container_service"
    SECRETS_REFERENCE = "secrets_reference"
    AUDIT_LOG_CONFIG = "audit_log_config"
    MONITORING_CONFIG = "monitoring_config"
