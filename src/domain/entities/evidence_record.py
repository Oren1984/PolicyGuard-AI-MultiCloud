from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """A piece of evidence attached to a finding or exception. `reference_type`
    names the entity it evidences (e.g. "compliance_finding", "drift_finding",
    "policy_exception") so one repository can serve all evidence without the
    domain depending on any particular storage layout."""

    evidence_id: str
    reference_type: str
    reference_id: str
    description: str
    source: str
    content_hash: str
    submitted_by: str
    captured_at: datetime = field(default_factory=lambda: datetime.now(UTC))
