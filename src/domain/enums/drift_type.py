from enum import StrEnum


class DriftType(StrEnum):
    """The 8 required drift types (spec section 8)."""

    CONFIGURATION = "configuration"
    SECURITY = "security"
    IDENTITY_AND_PERMISSION = "identity_and_permission"
    ARCHITECTURAL = "architectural"
    OPERATIONAL_CONTROL = "operational_control"
    COMPLIANCE = "compliance"
    UNMANAGED_RESOURCE = "unmanaged_resource"
    EXCEPTION = "exception"
