from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from src.domain.entities.cloud_resource import CloudResource
from src.domain.entities.managed_system import ManagedSystem
from src.domain.entities.state_snapshot import ArchitectureBaseline
from src.domain.enums.policy_category import PolicyCategory
from src.domain.enums.policy_severity import PolicySeverity


@dataclass(frozen=True, slots=True)
class PolicyEvaluationContext:
    """Everything a single policy's evaluation function may look at.

    Deliberately a plain, serializable bag of values so every policy's
    `evaluate` callable stays a pure, unit-testable function of its inputs —
    no hidden reads of a database, clock, or network.
    """

    resource: CloudResource
    managed_system: ManagedSystem
    baseline: ArchitectureBaseline
    desired_resource: CloudResource | None
    has_active_eligible_exception: bool
    has_expired_or_revoked_exception_on_record: bool
    evaluation_time: datetime


@dataclass(frozen=True, slots=True)
class PolicyCheckOutcome:
    """The result of running one policy's evaluation function against one
    resource. `passed=True` means no violation was found."""

    passed: bool
    explanation: str
    evidence: tuple[str, ...] = ()
    details: dict = field(default_factory=dict)


PolicyEvaluationFn = Callable[[PolicyEvaluationContext], PolicyCheckOutcome]


@dataclass(frozen=True, slots=True)
class Policy:
    """A single deterministic policy definition (spec section 7). The
    `evaluate` field carries the policy's own deterministic evaluation
    logic — a pure function, never an LLM call — so the policy's rule and
    its metadata travel together as one immutable value object.
    """

    policy_id: str
    title: str
    description: str
    category: PolicyCategory
    severity: PolicySeverity
    evaluate: PolicyEvaluationFn
    required_evidence: tuple[str, ...]
    explanation_template: str
    remediation_guidance: str
    exception_eligible: bool
    version: int = 1
    active: bool = True


@dataclass(frozen=True, slots=True)
class PolicyPack:
    """A named, versioned bundle of policies evaluated together against a
    snapshot."""

    pack_id: str
    name: str
    version: int
    policies: tuple[Policy, ...]
    active: bool = True
    description: str = ""

    @property
    def active_policies(self) -> tuple[Policy, ...]:
        return tuple(p for p in self.policies if p.active)
