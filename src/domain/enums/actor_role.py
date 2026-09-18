from enum import StrEnum


class ActorRole(StrEnum):
    """Roles recognized by PolicyGuard. See spec section 12 (separation of
    duties) and section 13 (kill switch authorization)."""

    SYSTEM_OWNER = "system_owner"
    SECURITY_REVIEWER = "security_reviewer"
    COMPLIANCE_APPROVER = "compliance_approver"
    PLATFORM_ADMIN = "platform_admin"
    AUDITOR = "auditor"


# Roles permitted to review/approve/reject a policy exception. The requester
# (identified by actor id, not role) is separately barred from deciding their
# own request regardless of role — see
# src/application/services/exception_authorization.py.
EXCEPTION_DECISION_ROLES = frozenset(
    {ActorRole.SECURITY_REVIEWER, ActorRole.COMPLIANCE_APPROVER, ActorRole.PLATFORM_ADMIN}
)

# Roles permitted to revoke an active exception.
EXCEPTION_REVOCATION_ROLES = frozenset(
    {ActorRole.SECURITY_REVIEWER, ActorRole.COMPLIANCE_APPROVER, ActorRole.PLATFORM_ADMIN}
)

# Roles permitted to change kill-switch state.
KILL_SWITCH_ROLES = frozenset({ActorRole.PLATFORM_ADMIN})

# Roles permitted to activate/deactivate policies and policy packs.
POLICY_ADMIN_ROLES = frozenset({ActorRole.PLATFORM_ADMIN, ActorRole.COMPLIANCE_APPROVER})
