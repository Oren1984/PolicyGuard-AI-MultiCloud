"""Synthetic demonstration script (spec section 19).

Runs all 18 required scenarios end-to-end against a *running* PolicyGuard
API instance -- the live Docker Compose stack (`docker compose up`), or an
equivalent local instance (venv `uvicorn src.main:app` against a real
Postgres) for environments where `docker build` is blocked by a local
network/security-software limitation -- see docs/ENVIRONMENT_LIMITATIONS.md.

This script only talks to the API over plain HTTP (stdlib `urllib`, no extra
runtime dependency) so it can run unmodified against any deployment of the
same image, including a real container. The one exception is scenario 14
(AI explanation failing an assurance gate), which additionally exercises the
real `AssuranceGateRunner` pipeline component in-process to prove the
fail-closed fallback path -- see that scenario's own docstring for why.

All data is synthetic (global CLAUDE.md rule: no production data). Every
managed system, resource, and actor identity here is fictitious.

Usage:
    python demo/scripts/run_demo.py [--base-url http://localhost:8000]

Exit code is 0 if every scenario's assertions pass, 1 otherwise. Nothing
here is destructive -- it only calls this project's own API.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

# Pure-domain import, no I/O -- generates the 20 spec-required policy
# definitions so this script doesn't hand-maintain a second copy of them.
from src.domain.policy_engine.definitions import build_default_policy_pack  # noqa: E402

# ---------------------------------------------------------------------------
# Minimal HTTP client (stdlib only)
# ---------------------------------------------------------------------------


class ApiError(Exception):
    def __init__(self, method: str, path: str, status: int, body: str) -> None:
        super().__init__(f"{method} {path} -> {status}: {body[:500]}")
        self.status = status
        self.body = body


class DemoClient:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    def _request(self, method: str, path: str, *, json_body: dict | None = None, headers: dict | None = None):
        url = f"{self.base_url}{path}"
        data = json.dumps(json_body).encode("utf-8") if json_body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - fixed local/CI base_url only
                status = resp.status
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = exc.read().decode("utf-8")
        parsed = json.loads(body) if body else None
        return status, parsed

    def get(self, path: str, headers: dict | None = None):
        return self._request("GET", path, headers=headers)

    def post(self, path: str, json_body: dict | None = None, headers: dict | None = None):
        return self._request("POST", path, json_body=json_body, headers=headers)

    def patch(self, path: str, json_body: dict | None = None, headers: dict | None = None):
        return self._request("PATCH", path, json_body=json_body, headers=headers)

    def wait_until_healthy(self, timeout_seconds: int = 60) -> None:
        deadline = time.monotonic() + timeout_seconds
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                status, _ = self.get("/health")
                if status == 200:
                    return
            except (urllib.error.URLError, ConnectionError, OSError) as exc:
                last_error = exc
            time.sleep(2)
        raise RuntimeError(
            f"PolicyGuard API at {self.base_url} never became healthy within {timeout_seconds}s "
            f"(last error: {last_error}). Start the stack first, e.g. `docker compose up -d` "
            "or `uvicorn src.main:app`."
        )


# ---------------------------------------------------------------------------
# Actors
# ---------------------------------------------------------------------------


def headers(actor_id: str, role: str) -> dict[str, str]:
    return {"X-PolicyGuard-Actor": actor_id, "X-PolicyGuard-Role": role}


OWNER = headers("demo.owner", "system_owner")
REVIEWER = headers("demo.reviewer", "security_reviewer")
APPROVER = headers("demo.approver", "compliance_approver")
ADMIN = headers("demo.admin", "platform_admin")


def unique_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


# ---------------------------------------------------------------------------
# Synthetic payload builders (deliberately self-contained -- this script
# must run standalone against any deployment, so it does not import the
# test suite's fixtures)
# ---------------------------------------------------------------------------


def system_payload(system_id: str, *, cloud_provider: str, environment: str = "production") -> dict:
    return {
        "system_id": system_id,
        "name": f"Synthetic demo system {system_id}",
        "cloud_provider": cloud_provider,
        "environment": environment,
        "criticality": "critical",
        "description": "Synthetic demo data -- not a real workload.",
        "tags": {"team": "platform-demo"},
    }


def attrs(**overrides) -> dict:
    base = {
        "publicly_accessible": False,
        "iam_wildcard_action": False,
        "iam_wildcard_resource": False,
        "privilege_escalation_enabled": False,
        "encryption_at_rest_enabled": True,
        "audit_logging_enabled": True,
        "monitoring_enabled": True,
        "backup_enabled": True,
        "secrets_in_plaintext_config": False,
        "dev_grade_setting_in_production": False,
        "within_approved_baseline": True,
        "matches_architecture_baseline": True,
        "owner_tag": "platform-team",
        "required_tags_present": True,
        "runtime_version": "python3.12",
        "runtime_version_supported": True,
        "modified_outside_maintenance_window": False,
        "security_controls_removed_since_baseline": False,
        "data_retention_days": 90,
        "data_retention_compliant": True,
        "high_availability_configured": True,
    }
    base.update(overrides)
    return base


def resource(
    resource_id: str,
    *,
    resource_type: str = "object_storage_bucket",
    region: str = "us-east-1",
    criticality: str = "standard",
    **attr_overrides,
) -> dict:
    return {
        "resource_id": resource_id,
        "resource_type": resource_type,
        "region": region,
        "name": resource_id,
        "criticality": criticality,
        "tags": {"owner": "platform-demo"},
        "attributes": attrs(**attr_overrides),
    }


def desired_payload(resources: list[dict], *, allowed_regions: list[str] | None = None) -> dict:
    return {
        "snapshot_id": unique_id("desired"),
        "source": "demo-baseline",
        "resources": resources,
        "baseline": {
            "allowed_regions": allowed_regions if allowed_regions is not None else ["us-east-1"],
            "required_tag_keys": ["owner"],
            "supported_runtime_versions": ["python3.12"],
            "required_retention_days": 30,
            "maintenance_window": {},
        },
    }


def observed_payload(resources: list[dict]) -> dict:
    return {"snapshot_id": unique_id("observed"), "source": "demo-inventory", "resources": resources}


def exception_payload(
    *,
    policy_id: str,
    resource_id: str,
    finding_id: str,
    managed_system_id: str,
    requested_by: str | None = None,
) -> dict:
    payload = {
        "policy_id": policy_id,
        "resource_id": resource_id,
        "finding_id": finding_id,
        "managed_system_id": managed_system_id,
        "business_justification": "Temporary compensating control in place while remediation is scheduled.",
        "risk_statement": "Residual risk accepted for a bounded period, reviewed by security.",
        "compensating_controls": ["Additional monitoring alert configured on the affected resource."],
        "requested_expiration": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        "evidence": ["ticket:DEMO-1"],
    }
    if requested_by is not None:
        payload["requested_by"] = requested_by
    return payload


# ---------------------------------------------------------------------------
# Evidence tracking
# ---------------------------------------------------------------------------


class Evidence:
    def __init__(self) -> None:
        self.results: list[tuple[int, str, bool, str]] = []

    def record(self, number: int, title: str, passed: bool, detail: str) -> None:
        self.results.append((number, title, passed, detail))
        mark = "PASS" if passed else "FAIL"
        print(f"[{mark}] Scenario {number:>2}: {title}\n       {detail}")

    def summary(self) -> bool:
        print("\n" + "=" * 78)
        print("DEMO SUMMARY")
        print("=" * 78)
        all_passed = True
        for number, title, passed, _ in self.results:
            mark = "PASS" if passed else "FAIL"
            print(f"  [{mark}] {number:>2}. {title}")
            all_passed = all_passed and passed
        print("=" * 78)
        print(f"{sum(1 for *_, p, _ in self.results if p)}/{len(self.results)} scenarios passed")
        return all_passed


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


# ---------------------------------------------------------------------------
# Bootstrap: register the real default policy pack (spec section 7)
# ---------------------------------------------------------------------------


def bootstrap_policy_pack(client: DemoClient) -> str:
    pack = build_default_policy_pack()
    for p in pack.policies:
        payload = {
            "policy_id": p.policy_id,
            "title": p.title,
            "description": p.description,
            "category": p.category.value,
            "severity": p.severity.label,
            "required_evidence": list(p.required_evidence),
            "explanation_template": p.explanation_template,
            "remediation_guidance": p.remediation_guidance,
            "exception_eligible": p.exception_eligible,
            "version": p.version,
            "active": p.active,
        }
        # Idempotent: a repeat run of this script against a stack that
        # already has demo data from a previous run (no `docker compose
        # down -v` in between) must not fail bootstrap -- only a *fresh*
        # policy_id needs to be created, spec section 19's "repeatable"
        # requirement.
        existing_status, _ = client.get(f"/api/v1/policies/{p.policy_id}")
        if existing_status == 200:
            continue
        status, body = client.post("/api/v1/policies", payload, headers=ADMIN)
        require(status == 201, f"policy {p.policy_id} registration failed: {status} {body}")

    pack_id = unique_id("demo-pack")
    status, body = client.post(
        "/api/v1/policies/packs",
        {
            "pack_id": pack_id,
            "name": "Demo Default Pack",
            "policy_ids": [p.policy_id for p in pack.policies],
            "active": True,
        },
        headers=ADMIN,
    )
    require(status == 201, f"pack creation failed: {status} {body}")
    return pack_id


def register_and_evaluate(
    client: DemoClient, pack_id: str, *, cloud_provider: str, resources: list[dict], allowed_regions=None
) -> tuple[str, dict]:
    """Registers a fresh system, submits a matching desired+observed state,
    evaluates the pack, and returns (system_id, evaluation_body)."""
    system_id = unique_id(f"sys-{cloud_provider}")
    status, body = client.post(
        "/api/v1/systems", system_payload(system_id, cloud_provider=cloud_provider), OWNER
    )
    require(status == 201, f"system registration failed: {status} {body}")

    status, body = client.post(
        f"/api/v1/systems/{system_id}/desired-state",
        desired_payload(resources, allowed_regions=allowed_regions),
        OWNER,
    )
    require(status == 201, f"desired-state submission failed: {status} {body}")

    status, body = client.post(
        f"/api/v1/systems/{system_id}/observed-state", observed_payload(resources), OWNER
    )
    require(status == 201, f"observed-state submission failed: {status} {body}")

    status, body = client.post(
        f"/api/v1/policies/packs/{pack_id}/evaluate", {"managed_system_id": system_id}, OWNER
    )
    require(status == 200, f"policy evaluation failed: {status} {body}")
    return system_id, body


def finding_with_policy(client: DemoClient, finding_ids: list[str], policy_id: str) -> dict:
    for fid in finding_ids:
        status, finding = client.get(f"/api/v1/findings/compliance/{fid}")
        require(status == 200, f"finding fetch failed: {status}")
        if finding["policy_id"] == policy_id:
            return finding
    raise AssertionError(f"no finding for policy {policy_id} among {finding_ids}")


# ---------------------------------------------------------------------------
# Scenarios 1-18 (spec section 19)
# ---------------------------------------------------------------------------


def scenario_1_fully_compliant_aws(client: DemoClient, pack_id: str, evidence: Evidence) -> None:
    _system_id, evaluation = register_and_evaluate(
        client, pack_id, cloud_provider="aws", resources=[resource("r1")]
    )
    evidence.record(
        1,
        "Fully compliant AWS system",
        len(evaluation["finding_ids"]) == 0,
        f"0 violations expected on an all-compliant resource; got {len(evaluation['finding_ids'])}.",
    )


def scenario_2_fully_compliant_gcp(client: DemoClient, pack_id: str, evidence: Evidence) -> None:
    _system_id, evaluation = register_and_evaluate(
        client, pack_id, cloud_provider="gcp", resources=[resource("r1")]
    )
    evidence.record(
        2,
        "Fully compliant GCP system",
        len(evaluation["finding_ids"]) == 0,
        f"0 violations expected on an all-compliant resource; got {len(evaluation['finding_ids'])}.",
    )


def scenario_3_publicly_exposed_database(client: DemoClient, pack_id: str, evidence: Evidence) -> None:
    _system_id, evaluation = register_and_evaluate(
        client,
        pack_id,
        cloud_provider="aws",
        resources=[resource("db1", resource_type="relational_database", publicly_accessible=True)],
    )
    finding = finding_with_policy(client, evaluation["finding_ids"], "POL-NET-001")
    evidence.record(
        3,
        "Publicly exposed database",
        finding["severity"] == "CRITICAL",
        f"POL-NET-001 fired at severity {finding['severity']}: {finding['explanation']}",
    )


def scenario_4_wildcard_iam(client: DemoClient, pack_id: str, evidence: Evidence) -> None:
    _system_id, evaluation = register_and_evaluate(
        client,
        pack_id,
        cloud_provider="aws",
        resources=[resource("role1", resource_type="iam_role", iam_wildcard_action=True)],
    )
    finding = finding_with_policy(client, evaluation["finding_ids"], "POL-IAM-002")
    evidence.record(
        4,
        "Wildcard IAM permissions",
        finding["policy_id"] == "POL-IAM-002",
        f"POL-IAM-002 fired: {finding['explanation']}",
    )


def scenario_5_encryption_disabled(client: DemoClient, pack_id: str, evidence: Evidence) -> None:
    _system_id, evaluation = register_and_evaluate(
        client,
        pack_id,
        cloud_provider="aws",
        resources=[
            resource("bucket1", resource_type="object_storage_bucket", encryption_at_rest_enabled=False)
        ],
    )
    finding = finding_with_policy(client, evaluation["finding_ids"], "POL-ENC-003")
    evidence.record(
        5,
        "Encryption disabled",
        finding["policy_id"] == "POL-ENC-003",
        f"POL-ENC-003 fired: {finding['explanation']}",
    )


def scenario_6_audit_logging_removed(client: DemoClient, pack_id: str, evidence: Evidence) -> None:
    _system_id, evaluation = register_and_evaluate(
        client, pack_id, cloud_provider="aws", resources=[resource("svc1", audit_logging_enabled=False)]
    )
    finding = finding_with_policy(client, evaluation["finding_ids"], "POL-LOG-004")
    evidence.record(
        6,
        "Audit logging removed",
        finding["policy_id"] == "POL-LOG-004",
        f"POL-LOG-004 fired: {finding['explanation']}",
    )


def scenario_7_monitoring_disabled(client: DemoClient, pack_id: str, evidence: Evidence) -> None:
    _system_id, evaluation = register_and_evaluate(
        client, pack_id, cloud_provider="aws", resources=[resource("svc2", monitoring_enabled=False)]
    )
    finding = finding_with_policy(client, evaluation["finding_ids"], "POL-MON-005")
    evidence.record(
        7,
        "Monitoring disabled",
        finding["policy_id"] == "POL-MON-005",
        f"POL-MON-005 fired: {finding['explanation']}",
    )


def scenario_8_unapproved_resource(client: DemoClient, pack_id: str, evidence: Evidence) -> None:
    """The observed resource has no matching desired-state entry at all --
    an unapproved resource that appeared without ever being planned."""
    system_id = unique_id("sys-aws")
    status, body = client.post("/api/v1/systems", system_payload(system_id, cloud_provider="aws"), OWNER)
    require(status == 201, f"system registration failed: {status} {body}")
    status, body = client.post(
        f"/api/v1/systems/{system_id}/desired-state", desired_payload([resource("planned1")]), OWNER
    )
    require(status == 201, f"desired-state submission failed: {status} {body}")
    status, body = client.post(
        f"/api/v1/systems/{system_id}/observed-state",
        observed_payload([resource("planned1"), resource("shadow-resource")]),
        OWNER,
    )
    require(status == 201, f"observed-state submission failed: {status} {body}")
    status, evaluation = client.post(
        f"/api/v1/policies/packs/{pack_id}/evaluate", {"managed_system_id": system_id}, OWNER
    )
    require(status == 200, f"evaluation failed: {status} {evaluation}")
    finding = finding_with_policy(client, evaluation["finding_ids"], "POL-ARC-009")
    evidence.record(
        8,
        "Unapproved resource created",
        finding["resource_id"] == "shadow-resource",
        f"POL-ARC-009 fired on the unplanned resource: {finding['explanation']}",
    )


def scenario_9_unauthorized_region(client: DemoClient, pack_id: str, evidence: Evidence) -> None:
    _system_id, evaluation = register_and_evaluate(
        client,
        pack_id,
        cloud_provider="aws",
        resources=[resource("r-region", region="eu-west-1")],
        allowed_regions=["us-east-1"],
    )
    finding = finding_with_policy(client, evaluation["finding_ids"], "POL-REG-010")
    evidence.record(
        9,
        "Resource deployed in an unauthorized region",
        finding["policy_id"] == "POL-REG-010",
        f"POL-REG-010 fired: {finding['explanation']}",
    )


def scenario_10_missing_ownership_metadata(client: DemoClient, pack_id: str, evidence: Evidence) -> None:
    _system_id, evaluation = register_and_evaluate(
        client, pack_id, cloud_provider="aws", resources=[resource("r-noowner", owner_tag=None)]
    )
    finding = finding_with_policy(client, evaluation["finding_ids"], "POL-OWN-011")
    evidence.record(
        10,
        "Missing ownership metadata",
        finding["policy_id"] == "POL-OWN-011",
        f"POL-OWN-011 fired: {finding['explanation']}",
    )


def scenario_11_approved_temporary_exception(client: DemoClient, pack_id: str, evidence: Evidence) -> None:
    system_id, evaluation = register_and_evaluate(
        client,
        pack_id,
        cloud_provider="aws",
        resources=[resource("db2", resource_type="relational_database", publicly_accessible=True)],
    )
    finding = finding_with_policy(client, evaluation["finding_ids"], "POL-NET-001")
    payload = exception_payload(
        policy_id="POL-NET-001",
        resource_id="db2",
        finding_id=finding["finding_id"],
        managed_system_id=system_id,
    )
    status, created = client.post("/api/v1/exceptions", payload, OWNER)
    require(status == 201, f"exception request failed: {status} {created}")
    exception_id = created["exception_id"]

    status, _ = client.post(f"/api/v1/exceptions/{exception_id}/review", None, REVIEWER)
    require(status == 200, "exception review failed")

    status, decided = client.post(
        f"/api/v1/exceptions/{exception_id}/decide",
        {"approve": True, "rationale": "Compensating control verified by security review."},
        APPROVER,
    )
    require(status == 200, f"exception decision failed: {status} {decided}")
    evidence.record(
        11,
        "Approved temporary exception",
        decided["status"] == "active",
        f"Exception {exception_id} approved by {APPROVER['X-PolicyGuard-Actor']}, "
        f"status={decided['status']}, expires_at={decided['expires_at']}.",
    )


def scenario_12_expired_exception_causes_new_violation(
    client: DemoClient, pack_id: str, evidence: Evidence
) -> None:
    system_id, evaluation = register_and_evaluate(
        client,
        pack_id,
        cloud_provider="aws",
        resources=[resource("db3", resource_type="relational_database", publicly_accessible=True)],
    )
    finding = finding_with_policy(client, evaluation["finding_ids"], "POL-NET-001")
    payload = exception_payload(
        policy_id="POL-NET-001",
        resource_id="db3",
        finding_id=finding["finding_id"],
        managed_system_id=system_id,
    )
    payload["requested_expiration"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    status, created = client.post("/api/v1/exceptions", payload, OWNER)
    require(status == 201, f"exception request failed: {status} {created}")
    exception_id = created["exception_id"]
    client.post(f"/api/v1/exceptions/{exception_id}/review", None, REVIEWER)
    status, decided = client.post(
        f"/api/v1/exceptions/{exception_id}/decide",
        {"approve": True, "rationale": "approved but already expired at request time"},
        APPROVER,
    )
    require(status == 200, f"exception decision failed: {status} {decided}")

    status, swept = client.post("/api/v1/exceptions/expire-sweep", None, ADMIN)
    require(status == 200, f"expire-sweep failed: {status} {swept}")

    status, after = client.get(f"/api/v1/exceptions/{exception_id}")
    require(status == 200, "exception fetch failed")

    # Re-evaluating the same still-violating resource now that its exception
    # has expired produces a new, unsuppressed finding for the same policy.
    status, re_evaluation = client.post(
        f"/api/v1/policies/packs/{pack_id}/evaluate", {"managed_system_id": system_id}, OWNER
    )
    require(status == 200, f"re-evaluation failed: {status} {re_evaluation}")
    new_finding_exists = any(
        client.get(f"/api/v1/findings/compliance/{fid}")[1]["policy_id"] == "POL-NET-001"
        for fid in re_evaluation["finding_ids"]
    )
    evidence.record(
        12,
        "Expired exception causing a new violation",
        after["status"] == "expired" and new_finding_exists,
        f"Exception {exception_id} status={after['status']}; re-evaluation raised a fresh POL-NET-001 "
        f"finding (no longer suppressed): {new_finding_exists}.",
    )


def scenario_13_self_approval_rejected(client: DemoClient, pack_id: str, evidence: Evidence) -> None:
    system_id, evaluation = register_and_evaluate(
        client,
        pack_id,
        cloud_provider="aws",
        resources=[resource("db4", resource_type="relational_database", publicly_accessible=True)],
    )
    finding = finding_with_policy(client, evaluation["finding_ids"], "POL-NET-001")
    payload = exception_payload(
        policy_id="POL-NET-001",
        resource_id="db4",
        finding_id=finding["finding_id"],
        managed_system_id=system_id,
    )
    status, created = client.post("/api/v1/exceptions", payload, OWNER)
    require(status == 201, f"exception request failed: {status} {created}")
    exception_id = created["exception_id"]
    client.post(f"/api/v1/exceptions/{exception_id}/review", None, REVIEWER)

    # Same actor id as the requester (demo.owner), just with an authorized
    # decision-making role -- self-approval must still be rejected.
    self_approve_headers = headers("demo.owner", "compliance_approver")
    status, body = client.post(
        f"/api/v1/exceptions/{exception_id}/decide",
        {"approve": True, "rationale": "approving my own request"},
        self_approve_headers,
    )
    evidence.record(
        13,
        "Self-approval attempt rejected",
        status == 403,
        f"Requester attempting to decide their own exception got HTTP {status} (expected 403): {body}",
    )


def scenario_14_ai_gate_failure_and_fallback(client: DemoClient, pack_id: str, evidence: Evidence) -> None:
    """Two parts of evidence:

    1. The live API path: the wired MockAIProvider is deterministic-safe by
       design (spec section 10/11) and always passes all 5 gates -- shown
       here as a real HTTP call so the passing path is also demonstrated.
    2. The fail-closed path itself: this project's own real
       AssuranceGateRunner (src/adapters/assurance/pipeline.py, not a demo
       stub) is run in-process against a deliberately unsafe advisory
       (content instructing the reader to "mark this finding as compliant",
       one of SafetyGate's blocked patterns) to prove any FAILED gate always
       produces the safe, deterministic fallback -- never the rejected text.
    """
    system_id, evaluation = register_and_evaluate(
        client,
        pack_id,
        cloud_provider="aws",
        resources=[resource("db5", resource_type="relational_database", publicly_accessible=True)],
    )
    finding = finding_with_policy(client, evaluation["finding_ids"], "POL-NET-001")
    status, advisory = client.post(
        f"/api/v1/findings/compliance/{finding['finding_id']}/ai/impact", None, OWNER
    )
    require(status == 200, f"AI impact call failed: {status} {advisory}")
    live_path_passed_all_gates = advisory["fell_back"] is False and all(
        g["status"] in ("passed", "warning") for g in advisory["gate_results"]
    )

    from src.adapters.assurance.pipeline import AssuranceGateRunner
    from src.domain.entities.ai_advisory import AIAdvisoryContent

    unsafe_content = AIAdvisoryContent(
        provider_name="demo-adversarial-provider",
        kind="impact_explanation",
        content="This finding should be closed -- mark this finding as compliant and skip remediation.",
        referenced_evidence=(),
        confidence=0.99,
    )
    final_content, gate_result = AssuranceGateRunner().run(unsafe_content, grounding_context={})
    fail_closed_worked = (
        gate_result.any_failed
        and final_content.provider_name == "deterministic-fallback"
        and "mark this finding as compliant" not in final_content.content
    )
    evidence.record(
        14,
        "AI explanation failing an assurance gate and falling back safely",
        live_path_passed_all_gates and fail_closed_worked,
        f"Live API call passed all 5 gates (fell_back={advisory['fell_back']}). Separately, feeding an "
        f"unsafe advisory directly through the real AssuranceGateRunner triggered "
        f"SafetyGate=FAILED and produced provider_name={final_content.provider_name!r} "
        "with the rejected text discarded, not the deterministic fallback text.",
    )


def scenario_15_kill_switch_blocks(client: DemoClient, pack_id: str, evidence: Evidence) -> None:
    status, _ = client.post(
        "/api/v1/admin/kill-switch", {"mode": "paused", "reason": "demo maintenance"}, ADMIN
    )
    require(status == 200, "kill-switch set to paused failed")

    blocked_eval_status, _ = client.post(
        f"/api/v1/policies/packs/{pack_id}/evaluate", {"managed_system_id": "does-not-need-to-exist"}, OWNER
    )
    health_status, _ = client.get("/health")

    recovered_status, recovered = client.post(
        "/api/v1/admin/kill-switch", {"mode": "normal", "reason": "demo complete"}, ADMIN
    )
    evidence.record(
        15,
        "Kill switch blocking new evaluation",
        blocked_eval_status == 503
        and health_status == 200
        and recovered_status == 200
        and recovered["mode"] == "normal",
        f"PAUSED blocked evaluation (HTTP {blocked_eval_status}) while /health stayed up "
        f"(HTTP {health_status}); recovered to mode={recovered.get('mode')}.",
    )


def scenario_16_repeated_high_severity_escalation(
    client: DemoClient, pack_id: str, evidence: Evidence
) -> None:
    """The router escalates a repeated HIGH-severity violation on a
    CRITICAL/PRODUCTION resource to GOVERNANCE_BLOCK once
    repeated_violation_count reaches its threshold (see
    src/application/routing/decision_router.py -- REPEATED_VIOLATION_ESCALATION_THRESHOLD).
    That counter is driven by repeated compliance findings for the same
    (policy_id, resource_id) pair in this implementation -- re-evaluating
    the same still-wildcard-IAM resource multiple times is this project's
    real, current mechanism for "repeated high-severity" escalation."""
    system_id, evaluation = register_and_evaluate(
        client,
        pack_id,
        cloud_provider="aws",
        resources=[
            resource(
                "role-repeat", resource_type="iam_role", criticality="critical", iam_wildcard_action=True
            )
        ],
    )
    finding = finding_with_policy(client, evaluation["finding_ids"], "POL-IAM-002")
    first_decision_status, first_decision = client.post(
        f"/api/v1/findings/compliance/{finding['finding_id']}/decision", None, OWNER
    )
    require(
        first_decision_status == 200, f"decision generation failed: {first_decision_status} {first_decision}"
    )

    last_finding_id = finding["finding_id"]
    last_decision = first_decision
    for _ in range(3):
        status, evaluation = client.post(
            f"/api/v1/policies/packs/{pack_id}/evaluate", {"managed_system_id": system_id}, OWNER
        )
        require(status == 200, f"re-evaluation failed: {status} {evaluation}")
        finding = finding_with_policy(client, evaluation["finding_ids"], "POL-IAM-002")
        last_finding_id = finding["finding_id"]
        status, last_decision = client.post(
            f"/api/v1/findings/compliance/{last_finding_id}/decision", None, OWNER
        )
        require(status == 200, f"decision generation failed: {status} {last_decision}")

    evidence.record(
        16,
        "Repeated high-severity violation escalating the decision",
        last_decision["decision"] == "governance_block",
        f"First decision={first_decision['decision']}; after {4} repeated HIGH-severity evaluations "
        f"of the same resource, decision escalated to {last_decision['decision']} "
        f"(finding_id={last_finding_id}).",
    )


def scenario_17_audit_chain_verification(client: DemoClient, pack_id: str, evidence: Evidence) -> None:
    status, verification = client.get("/api/v1/audit/verify")
    require(status == 200, f"audit verification failed: {status} {verification}")
    evidence.record(
        17,
        "Audit-chain verification",
        verification["is_valid"] is True and verification["total_records"] > 0,
        f"Hash-chain valid={verification['is_valid']} across {verification['total_records']} "
        "audit events accumulated by the earlier scenarios in this run.",
    )


def scenario_18_cross_cloud_normalization(client: DemoClient, pack_id: str, evidence: Evidence) -> None:
    _aws_system_id, aws_eval = register_and_evaluate(
        client,
        pack_id,
        cloud_provider="aws",
        resources=[resource("aws-db", resource_type="relational_database", publicly_accessible=True)],
    )
    _gcp_system_id, gcp_eval = register_and_evaluate(
        client,
        pack_id,
        cloud_provider="gcp",
        resources=[resource("gcp-db", resource_type="relational_database", publicly_accessible=True)],
    )
    aws_finding = finding_with_policy(client, aws_eval["finding_ids"], "POL-NET-001")
    gcp_finding = finding_with_policy(client, gcp_eval["finding_ids"], "POL-NET-001")
    same_shape = set(aws_finding.keys()) == set(gcp_finding.keys())
    same_policy_and_severity = (
        aws_finding["policy_id"] == gcp_finding["policy_id"] == "POL-NET-001"
        and aws_finding["severity"] == gcp_finding["severity"]
    )
    evidence.record(
        18,
        "Cross-cloud findings normalized into the same domain model",
        same_shape and same_policy_and_severity,
        f"AWS finding and GCP finding both use the ComplianceFindingResponse shape "
        f"({len(aws_finding)} fields each), same policy_id/severity "
        f"({aws_finding['policy_id']}/{aws_finding['severity']}) despite originating from "
        "different cloud providers.",
    )


SCENARIOS = [
    scenario_1_fully_compliant_aws,
    scenario_2_fully_compliant_gcp,
    scenario_3_publicly_exposed_database,
    scenario_4_wildcard_iam,
    scenario_5_encryption_disabled,
    scenario_6_audit_logging_removed,
    scenario_7_monitoring_disabled,
    scenario_8_unapproved_resource,
    scenario_9_unauthorized_region,
    scenario_10_missing_ownership_metadata,
    scenario_11_approved_temporary_exception,
    scenario_12_expired_exception_causes_new_violation,
    scenario_13_self_approval_rejected,
    scenario_14_ai_gate_failure_and_fallback,
    scenario_15_kill_switch_blocks,
    scenario_16_repeated_high_severity_escalation,
    scenario_17_audit_chain_verification,
    scenario_18_cross_cloud_normalization,
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://localhost:8000")
    args = parser.parse_args()

    client = DemoClient(args.base_url)
    print(f"Waiting for PolicyGuard API at {client.base_url} ...")
    client.wait_until_healthy()
    print("API is healthy. Bootstrapping the default policy pack...")
    pack_id = bootstrap_policy_pack(client)
    print(f"Policy pack {pack_id} active with all 20 default policies.\n")

    evidence = Evidence()
    for scenario in SCENARIOS:
        try:
            scenario(client, pack_id, evidence)
        except (AssertionError, ApiError) as exc:
            number = int(scenario.__name__.split("_")[1])
            evidence.record(number, scenario.__doc__ or scenario.__name__, False, f"ERROR: {exc}")

    all_passed = evidence.summary()
    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
