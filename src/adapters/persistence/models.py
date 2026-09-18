"""SQLAlchemy 2.x ORM models for PolicyGuard AI MultiCloud (spec sections 3,
14). PostgreSQL only -- JSONB columns are used throughout; this schema is not
intended to be SQLite-compatible (spec section 3: no SQLite anywhere).

Nested domain value objects (CloudResource, ResourceAttributes,
ArchitectureBaseline, ExceptionApproval, ...) are stored as JSONB rather than
normalized into their own tables -- the same convention the sibling
ChangeGuard AI MultiCloud project uses for its nested Terraform-plan
evidence. See src/adapters/persistence/mappers.py for the serialization
rules applied at the boundary between these rows and the pure domain
entities.

Alembic migrations are out of scope for this phase (noted in the phase
report); `Base.metadata.create_all()` is sufficient for local smoke
checks against a real PostgreSQL instance.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _uuid_str() -> str:
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    pass


class ManagedSystemORM(Base):
    __tablename__ = "managed_systems"

    system_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(256))
    cloud_provider: Mapped[str] = mapped_column(String(16))
    environment: Mapped[str] = mapped_column(String(16))
    owner_actor_id: Mapped[str] = mapped_column(String(256))
    criticality: Mapped[int] = mapped_column(Integer, default=0)
    description: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class DesiredStateSnapshotORM(Base):
    __tablename__ = "desired_state_snapshots"

    snapshot_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    managed_system_id: Mapped[str] = mapped_column(String(128), index=True)
    source: Mapped[str] = mapped_column(String(128))
    resources: Mapped[list] = mapped_column(JSONB, default=list)
    baseline: Mapped[dict] = mapped_column(JSONB, default=dict)
    submitted_by: Mapped[str] = mapped_column(String(256))
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class ObservedStateSnapshotORM(Base):
    __tablename__ = "observed_state_snapshots"

    snapshot_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    managed_system_id: Mapped[str] = mapped_column(String(128), index=True)
    source: Mapped[str] = mapped_column(String(128))
    resources: Mapped[list] = mapped_column(JSONB, default=list)
    correlation_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class PolicyORM(Base):
    __tablename__ = "policies"

    policy_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(64))
    severity: Mapped[int] = mapped_column(Integer)
    required_evidence: Mapped[list] = mapped_column(JSONB, default=list)
    explanation_template: Mapped[str] = mapped_column(Text)
    remediation_guidance: Mapped[str] = mapped_column(Text)
    exception_eligible: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class PolicyPackORM(Base):
    __tablename__ = "policy_packs"

    pack_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(256))
    version: Mapped[int] = mapped_column(Integer, default=1)
    policy_ids: Mapped[list] = mapped_column(JSONB, default=list)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str] = mapped_column(Text, default="")


class ComplianceFindingORM(Base):
    __tablename__ = "compliance_findings"

    finding_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    managed_system_id: Mapped[str] = mapped_column(String(128), index=True)
    resource_id: Mapped[str] = mapped_column(String(256), index=True)
    policy_id: Mapped[str] = mapped_column(String(64), index=True)
    category: Mapped[str] = mapped_column(String(64))
    severity: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(256))
    explanation: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list] = mapped_column(JSONB, default=list)
    remediation_guidance: Mapped[str] = mapped_column(Text)
    exception_eligible: Mapped[bool] = mapped_column(Boolean, default=True)
    correlation_id: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32), default="open")
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class DriftFindingORM(Base):
    __tablename__ = "drift_findings"

    finding_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    managed_system_id: Mapped[str] = mapped_column(String(128), index=True)
    resource_id: Mapped[str] = mapped_column(String(256), index=True)
    drift_type: Mapped[str] = mapped_column(String(64))
    what_changed: Mapped[str] = mapped_column(Text)
    previous_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    current_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    expected_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    why_it_matters: Mapped[str] = mapped_column(Text)
    severity: Mapped[int] = mapped_column(Integer)
    evidence: Mapped[list] = mapped_column(JSONB, default=list)
    remediation: Mapped[str] = mapped_column(Text)
    exception_eligible: Mapped[bool] = mapped_column(Boolean, default=True)
    correlation_id: Mapped[str] = mapped_column(String(128))
    policy_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="open")
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class GovernanceDecisionORM(Base):
    __tablename__ = "governance_decisions"

    decision_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    managed_system_id: Mapped[str] = mapped_column(String(128), index=True)
    finding_ids: Mapped[list] = mapped_column(JSONB, default=list)
    decision: Mapped[str] = mapped_column(String(32))
    reasons: Mapped[list] = mapped_column(JSONB, default=list)
    policy_ids: Mapped[list] = mapped_column(JSONB, default=list)
    correlation_id: Mapped[str] = mapped_column(String(128))
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class PolicyExceptionORM(Base):
    __tablename__ = "policy_exceptions"

    exception_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    policy_id: Mapped[str] = mapped_column(String(64), index=True)
    resource_id: Mapped[str] = mapped_column(String(256), index=True)
    finding_id: Mapped[str] = mapped_column(String(128))
    managed_system_id: Mapped[str] = mapped_column(String(128), index=True)
    business_justification: Mapped[str] = mapped_column(Text)
    risk_statement: Mapped[str] = mapped_column(Text)
    compensating_controls: Mapped[list] = mapped_column(JSONB, default=list)
    requested_expiration: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    requested_by: Mapped[str] = mapped_column(String(256))
    evidence: Mapped[list] = mapped_column(JSONB, default=list)
    correlation_id: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32), default="requested", index=True)
    approvals: Mapped[list] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class RemediationPlanORM(Base):
    __tablename__ = "remediation_plans"

    plan_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(128), index=True)
    managed_system_id: Mapped[str] = mapped_column(String(128), index=True)
    description: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="not_started")
    assigned_to: Mapped[str | None] = mapped_column(String(256), nullable=True)
    correlation_id: Mapped[str] = mapped_column(String(128))
    verification_evidence: Mapped[list] = mapped_column(JSONB, default=list)
    due_by: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class AuditEventORM(Base):
    __tablename__ = "audit_events"
    __table_args__ = (UniqueConstraint("sequence", name="uq_audit_events_sequence"),)

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid_str)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64))
    current_hash: Mapped[str] = mapped_column(String(64))
    actor: Mapped[str] = mapped_column(String(256))
    actor_role: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(128))
    resource_type: Mapped[str] = mapped_column(String(128))
    resource_id: Mapped[str] = mapped_column(String(256))
    correlation_id: Mapped[str] = mapped_column(String(128))
    payload: Mapped[dict] = mapped_column(JSONB, default=dict)
    outcome: Mapped[str] = mapped_column(String(16), default="SUCCESS")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    # The exact canonical JSON that was hashed -- stored verbatim so
    # verify_chain() can recompute the hash identically at read time.
    canonical_payload: Mapped[str] = mapped_column(Text)


class KillSwitchStateORM(Base):
    __tablename__ = "kill_switch_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    mode: Mapped[str] = mapped_column(String(32), default="normal")
    changed_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
