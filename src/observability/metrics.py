"""Prometheus-compatible metrics (spec section 17). One private registry
(not the default global one) so repeated app-factory calls in tests don't
raise duplicate-registration errors.
"""

from __future__ import annotations

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

REGISTRY = CollectorRegistry()

http_errors_total = Counter(
    "policyguard_http_errors_total",
    "Total unhandled/HTTP error responses",
    ["status_code"],
    registry=REGISTRY,
)

evaluations_total = Counter(
    "policyguard_evaluations_total",
    "Deterministic evaluations run, by type",
    ["evaluation_type"],  # "policy_pack" | "drift"
    registry=REGISTRY,
)

evaluation_duration_seconds = Histogram(
    "policyguard_evaluation_duration_seconds",
    "Duration of a policy-pack or drift evaluation run",
    ["evaluation_type"],
    registry=REGISTRY,
)

findings_total = Counter(
    "policyguard_findings_total",
    "Findings recorded, by severity, cloud provider, and kind",
    ["severity", "provider", "kind"],  # kind: "compliance" | "drift"
    registry=REGISTRY,
)

decisions_total = Counter(
    "policyguard_decisions_total",
    "Governance decisions issued, by outcome",
    ["decision"],
    registry=REGISTRY,
)

gate_failures_total = Counter(
    "policyguard_gate_failures_total",
    "AI assurance gate failures, by gate",
    ["gate"],
    registry=REGISTRY,
)

exception_events_total = Counter(
    "policyguard_exception_events_total",
    "Policy exception workflow events, by event type",
    ["event"],  # requested | under_review | approved | rejected | revoked | expired | denied
    registry=REGISTRY,
)

audit_chain_valid = Gauge(
    "policyguard_audit_chain_valid",
    "1 if the audit chain was last verified valid, 0 if invalid",
    registry=REGISTRY,
)

db_ready = Gauge(
    "policyguard_db_ready",
    "1 if the last readiness check reached the database successfully, 0 otherwise",
    registry=REGISTRY,
)


def render_latest() -> tuple[bytes, str]:
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
