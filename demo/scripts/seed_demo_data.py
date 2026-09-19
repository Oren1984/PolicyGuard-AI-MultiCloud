"""Idempotent demo/mock data seeder for the dashboard.

The dashboard (`GET /dashboard`) is a read-only view over whatever is
actually in the database -- on a freshly-migrated instance it is empty,
which is correct but not very demonstrative. This script populates it with
realistic, clearly-marked synthetic data by calling the real, unmodified API
(the same one `demo/scripts/run_demo.py` exercises) -- it does not touch
the database directly, does not bypass any policy/decision/assurance/audit
logic, and does not add any new capability to the application itself.

Safety (spec: "demo data must never load automatically in production"):

1. This script only ever runs when explicitly invoked by a human or an
   explicit command -- nothing in the application itself calls it.
2. It additionally refuses to run unless `POLICYGUARD_DEMO_MODE=true` is set
   in *this script's own environment* (a `--force` flag overrides this for
   deliberate manual use).
3. It also queries the target server's own `/api/v1/admin/status` and
   refuses to seed if that server reports `environment=production` (again
   overridable with `--force`), so pointing this script at the wrong URL by
   mistake doesn't silently write demo data into a real deployment.

Idempotency and identification: every seeded managed system uses a fixed,
human-readable id under the reserved `demo-` prefix (e.g.
`demo-aws-checkout-api`) and carries `tags={"source": "demo",
"is_demo": "true", ...}`. Before creating anything for a given system, the
script checks whether that system id already exists and skips the entire
block if so -- re-running this script is always safe and never creates
duplicate findings, decisions, or exceptions. `reset_demo_data.py` (in this
same directory) removes everything under the `demo-` prefix and nothing
else -- see that script's own docstring for why it does not touch
`audit_events` (append-only, hash-chained -- see docs/SECURITY.md).

Usage:
    POLICYGUARD_DEMO_MODE=true python demo/scripts/seed_demo_data.py \
        [--base-url http://localhost:8000] [--force]
"""

from __future__ import annotations

import argparse
import json as json_module
import os
import sys
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

# Pure-domain import, no I/O -- reuses the real 20 policy definitions rather
# than hand-maintaining a second copy of them.
from src.domain.policy_engine.definitions import build_default_policy_pack  # noqa: E402

DEMO_PREFIX = "demo-"
DEMO_ACTOR = "demo.seed.bot"
DEMO_PACK_ID = "demo-default-pack"
DEMO_TAGS = {"source": "demo", "is_demo": "true"}


# ---------------------------------------------------------------------------
# Minimal HTTP client (stdlib only). Method signatures deliberately match
# FastAPI's TestClient / httpx.Client (`.get/.post/.patch(path, json=,
# headers=)` -> object with `.status_code`/`.json()`), so every function
# below also works unmodified when called from a pytest test with a real
# TestClient instance instead of this class -- see tests/demo/test_demo_seed.py.
# ---------------------------------------------------------------------------


class _Response:
    def __init__(self, status_code: int, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


class HttpClient:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    def _request(self, method: str, path: str, *, json=None, headers: dict | None = None) -> _Response:
        url = f"{self.base_url}{path}"
        data = json_module.dumps(json).encode("utf-8") if json is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - operator-supplied base_url only
                status, body = resp.status, resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            status, body = exc.code, exc.read().decode("utf-8")
        return _Response(status, json_module.loads(body) if body else None)

    def get(self, path: str, headers: dict | None = None) -> _Response:
        return self._request("GET", path, headers=headers)

    def post(self, path: str, json=None, headers: dict | None = None) -> _Response:
        return self._request("POST", path, json=json, headers=headers)

    def patch(self, path: str, json=None, headers: dict | None = None) -> _Response:
        return self._request("PATCH", path, json=json, headers=headers)


def headers(actor_id: str, role: str) -> dict[str, str]:
    return {"X-PolicyGuard-Actor": actor_id, "X-PolicyGuard-Role": role}


ADMIN = headers(DEMO_ACTOR, "platform_admin")
OWNER = headers(DEMO_ACTOR, "system_owner")
REVIEWER = headers("demo.reviewer.bot", "security_reviewer")
APPROVER = headers("demo.approver.bot", "compliance_approver")


# ---------------------------------------------------------------------------
# Payload builders (self-contained -- mirrors run_demo.py's own choice not
# to import tests/fixtures/builders.py)
# ---------------------------------------------------------------------------


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
    tags: dict | None = None,
    **attr_overrides,
) -> dict:
    return {
        "resource_id": resource_id,
        "resource_type": resource_type,
        "region": region,
        "name": resource_id,
        "criticality": criticality,
        "tags": tags if tags is not None else {"owner": "platform-team"},
        "attributes": attrs(**attr_overrides),
    }


def desired_payload(resources: list[dict], *, allowed_regions: list[str] | None = None) -> dict:
    return {
        "snapshot_id": f"demo-desired-{uuid.uuid4().hex[:10]}",
        "source": "demo-seed-baseline",
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
    return {
        "snapshot_id": f"demo-observed-{uuid.uuid4().hex[:10]}",
        "source": "demo-seed-inventory",
        "resources": resources,
    }


def exception_payload(
    *, policy_id: str, resource_id: str, finding_id: str, managed_system_id: str, days: int = 45
) -> dict:
    return {
        "policy_id": policy_id,
        "resource_id": resource_id,
        "finding_id": finding_id,
        "managed_system_id": managed_system_id,
        "business_justification": "Temporary compensating control in place while remediation is scheduled.",
        "risk_statement": "Residual risk accepted for a bounded period, reviewed by security.",
        "compensating_controls": ["Additional monitoring alert configured on the affected resource."],
        "requested_expiration": (datetime.now(UTC) + timedelta(days=days)).isoformat(),
        "evidence": ["ticket:DEMO-SEED-1"],
    }


# ---------------------------------------------------------------------------
# Bootstrap: ensure the real default policy pack exists (idempotent -- shared
# infrastructure, not itself "demo data", so it is never removed by reset)
# ---------------------------------------------------------------------------


def ensure_policy_pack(client) -> str:
    pack = build_default_policy_pack()
    for p in pack.policies:
        if client.get(f"/api/v1/policies/{p.policy_id}").status_code == 200:
            continue
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
        resp = client.post("/api/v1/policies", json=payload, headers=ADMIN)
        if resp.status_code != 201:
            raise RuntimeError(f"policy {p.policy_id} registration failed: {resp.status_code} {resp.json()}")

    if client.get(f"/api/v1/policies/packs/{DEMO_PACK_ID}").status_code == 200:
        return DEMO_PACK_ID

    resp = client.post(
        "/api/v1/policies/packs",
        json={
            "pack_id": DEMO_PACK_ID,
            "name": "Demo Default Pack",
            "policy_ids": [p.policy_id for p in pack.policies],
            "active": True,
        },
        headers=ADMIN,
    )
    if resp.status_code != 201:
        raise RuntimeError(f"demo pack creation failed: {resp.status_code} {resp.json()}")
    return DEMO_PACK_ID


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def system_exists(client, system_id: str) -> bool:
    return client.get(f"/api/v1/systems/{system_id}").status_code == 200


def register_system(
    client,
    *,
    system_id: str,
    name: str,
    cloud_provider: str,
    environment: str,
    criticality: str,
    owner: str,
    team: str,
) -> None:
    payload = {
        "system_id": system_id,
        "name": name,
        "cloud_provider": cloud_provider,
        "environment": environment,
        "criticality": criticality,
        "owner_actor_id": owner,
        "description": f"Synthetic demo system seeded by demo/scripts/seed_demo_data.py -- {name}.",
        "tags": {**DEMO_TAGS, "team": team},
    }
    resp = client.post("/api/v1/systems", json=payload, headers=OWNER)
    if resp.status_code != 201:
        raise RuntimeError(f"system {system_id} registration failed: {resp.status_code} {resp.json()}")


def submit_state(
    client, system_id: str, *, resources: list[dict], allowed_regions: list[str] | None = None
) -> None:
    d = client.post(
        f"/api/v1/systems/{system_id}/desired-state",
        json=desired_payload(resources, allowed_regions=allowed_regions),
        headers=OWNER,
    )
    if d.status_code != 201:
        raise RuntimeError(f"desired-state for {system_id} failed: {d.status_code} {d.json()}")
    o = client.post(
        f"/api/v1/systems/{system_id}/observed-state", json=observed_payload(resources), headers=OWNER
    )
    if o.status_code != 201:
        raise RuntimeError(f"observed-state for {system_id} failed: {o.status_code} {o.json()}")


def evaluate(client, system_id: str, pack_id: str) -> list[dict]:
    resp = client.post(
        f"/api/v1/policies/packs/{pack_id}/evaluate", json={"managed_system_id": system_id}, headers=OWNER
    )
    if resp.status_code != 200:
        raise RuntimeError(f"evaluation for {system_id} failed: {resp.status_code} {resp.json()}")
    finding_ids = resp.json()["finding_ids"]
    return [client.get(f"/api/v1/findings/compliance/{fid}").json() for fid in finding_ids]


def finding_for_policy(findings: list[dict], policy_id: str) -> dict:
    for f in findings:
        if f["policy_id"] == policy_id:
            return f
    raise AssertionError(f"no seeded finding for {policy_id} among {[f['policy_id'] for f in findings]}")


def decide(client, finding_id: str) -> dict:
    resp = client.post(f"/api/v1/findings/compliance/{finding_id}/decision", json=None, headers=OWNER)
    if resp.status_code != 200:
        raise RuntimeError(f"decision for {finding_id} failed: {resp.status_code} {resp.json()}")
    return resp.json()


def request_exception(
    client, *, policy_id: str, resource_id: str, finding_id: str, managed_system_id: str, days: int = 45
) -> str:
    resp = client.post(
        "/api/v1/exceptions",
        json=exception_payload(
            policy_id=policy_id,
            resource_id=resource_id,
            finding_id=finding_id,
            managed_system_id=managed_system_id,
            days=days,
        ),
        headers=OWNER,
    )
    if resp.status_code != 201:
        raise RuntimeError(f"exception request failed: {resp.status_code} {resp.json()}")
    return resp.json()["exception_id"]


# ---------------------------------------------------------------------------
# Demo systems (each self-contained: register -> submit state -> evaluate ->
# decide/except/remediate as scripted). Every function is a no-op if its
# system id already exists.
# ---------------------------------------------------------------------------


def seed_checkout_api(client, pack_id: str, log) -> None:
    """CRITICAL public-exposure violation -> a hard GOVERNANCE_BLOCK."""
    system_id = "demo-aws-checkout-api"
    if system_exists(client, system_id):
        return log.skip(system_id)
    register_system(
        client,
        system_id=system_id,
        name="Checkout API",
        cloud_provider="aws",
        environment="production",
        criticality="critical",
        owner="alex.chen",
        team="payments-eng",
    )
    resources = [
        resource("checkout-api-role", resource_type="iam_role"),
        resource(
            "checkout-db",
            resource_type="relational_database",
            criticality="critical",
            publicly_accessible=True,
        ),
    ]
    submit_state(client, system_id, resources=resources)
    findings = evaluate(client, system_id, pack_id)
    finding = finding_for_policy(findings, "POL-NET-001")
    decision = decide(client, finding["finding_id"])
    log.seeded(system_id, f"1 CRITICAL finding -> decision={decision['decision']}")


def seed_user_database(client, pack_id: str, log) -> None:
    """A HIGH finding with a pending exception (human-review case) plus a
    MEDIUM finding routed straight to remediation."""
    system_id = "demo-aws-user-database"
    if system_exists(client, system_id):
        return log.skip(system_id)
    register_system(
        client,
        system_id=system_id,
        name="User Database",
        cloud_provider="aws",
        environment="production",
        criticality="critical",
        owner="priya.patel",
        team="platform-data",
    )
    resources = [
        resource(
            "user-db-primary",
            resource_type="relational_database",
            criticality="critical",
            encryption_at_rest_enabled=False,
        ),
        resource("user-db-backup-job", resource_type="object_storage_bucket", backup_enabled=False),
    ]
    submit_state(client, system_id, resources=resources)
    findings = evaluate(client, system_id, pack_id)

    enc_finding = finding_for_policy(findings, "POL-ENC-003")
    exception_id = request_exception(
        client,
        policy_id="POL-ENC-003",
        resource_id="user-db-primary",
        finding_id=enc_finding["finding_id"],
        managed_system_id=system_id,
    )
    client.post(f"/api/v1/exceptions/{exception_id}/review", json=None, headers=REVIEWER)
    decision = decide(client, enc_finding["finding_id"])

    bak_finding = finding_for_policy(findings, "POL-BAK-006")
    decision2 = decide(client, bak_finding["finding_id"])
    log.seeded(
        system_id,
        f"pending exception -> decision={decision['decision']}; "
        f"backup finding -> decision={decision2['decision']}",
    )


def seed_auth_service(client, pack_id: str, log) -> None:
    """Repeated HIGH-severity violation on a critical production resource
    escalating to GOVERNANCE_BLOCK, plus a rejected exception attempt."""
    system_id = "demo-aws-auth-service"
    if system_exists(client, system_id):
        return log.skip(system_id)
    register_system(
        client,
        system_id=system_id,
        name="Auth Service",
        cloud_provider="aws",
        environment="production",
        criticality="critical",
        owner="jordan.lee",
        team="identity",
    )
    resources = [
        resource(
            "auth-service-role", resource_type="iam_role", criticality="critical", iam_wildcard_action=True
        )
    ]
    submit_state(client, system_id, resources=resources)

    findings = evaluate(client, system_id, pack_id)
    finding = finding_for_policy(findings, "POL-IAM-002")
    last_decision = decide(client, finding["finding_id"])
    for _ in range(3):
        findings = evaluate(client, system_id, pack_id)
        finding = finding_for_policy(findings, "POL-IAM-002")
        last_decision = decide(client, finding["finding_id"])

    exception_id = request_exception(
        client,
        policy_id="POL-IAM-002",
        resource_id="auth-service-role",
        finding_id=finding["finding_id"],
        managed_system_id=system_id,
    )
    client.post(f"/api/v1/exceptions/{exception_id}/review", json=None, headers=REVIEWER)
    client.post(
        f"/api/v1/exceptions/{exception_id}/decide",
        json={
            "approve": False,
            "rationale": "Wildcard IAM on a critical auth path cannot be excepted -- remediate instead.",
        },
        headers=APPROVER,
    )
    log.seeded(system_id, f"repeated violation -> decision={last_decision['decision']}; exception rejected")


def seed_billing_service(client, pack_id: str, log) -> None:
    """Low-severity, informational-only findings plus a drift finding from a
    second observed-state submission."""
    system_id = "demo-gcp-billing-service"
    if system_exists(client, system_id):
        return log.skip(system_id)
    register_system(
        client,
        system_id=system_id,
        name="Billing Service",
        cloud_provider="gcp",
        environment="production",
        criticality="important",
        owner="sam.okafor",
        team="finance-eng",
    )
    resources = [
        resource("billing-worker", resource_type="container_service", owner_tag=None),
        resource("billing-events-topic", resource_type="object_storage_bucket", tags={}),
    ]
    submit_state(client, system_id, resources=resources)
    findings = evaluate(client, system_id, pack_id)
    own_finding = finding_for_policy(findings, "POL-OWN-011")
    decision = decide(client, own_finding["finding_id"])

    # A second, changed observed snapshot -> real drift on re-detection.
    drifted_resources = [
        resource(
            "billing-worker", resource_type="container_service", owner_tag=None, monitoring_enabled=False
        ),
        resource("billing-events-topic", resource_type="object_storage_bucket", tags={}),
    ]
    client.post(
        f"/api/v1/systems/{system_id}/observed-state", json=observed_payload(drifted_resources), headers=OWNER
    )
    drift = client.post(f"/api/v1/systems/{system_id}/drift-detection", json=None, headers=OWNER)
    drift_count = len(drift.json()["findings"]) if drift.status_code == 200 else 0
    log.seeded(
        system_id,
        f"informational findings -> decision={decision['decision']}; {drift_count} drift finding(s)",
    )


def seed_analytics_pipeline(client, pack_id: str, log) -> None:
    """MEDIUM/LOW mix on a non-production system, plus a remediation plan in
    progress."""
    system_id = "demo-gcp-analytics-pipeline"
    if system_exists(client, system_id):
        return log.skip(system_id)
    register_system(
        client,
        system_id=system_id,
        name="Analytics Pipeline",
        cloud_provider="gcp",
        environment="staging",
        criticality="standard",
        owner="morgan.diaz",
        team="data-platform",
    )
    resources = [
        resource("analytics-job-runner", resource_type="container_service", runtime_version_supported=False),
        resource(
            "analytics-etl-window",
            resource_type="container_service",
            modified_outside_maintenance_window=True,
        ),
    ]
    submit_state(client, system_id, resources=resources)
    findings = evaluate(client, system_id, pack_id)

    ver_finding = finding_for_policy(findings, "POL-VER-013")
    decision = decide(client, ver_finding["finding_id"])
    plan = client.post(
        f"/api/v1/findings/compliance/{ver_finding['finding_id']}/remediation-plan",
        json={
            "description": "Upgrade analytics-job-runner to a supported Python runtime.",
            "assigned_to": "morgan.diaz",
        },
        headers=OWNER,
    )
    if plan.status_code == 201:
        plan_id = plan.json()["plan_id"]
        client.patch(
            f"/api/v1/findings/remediation-plans/{plan_id}/status",
            json={"target_status": "in_progress", "verification_evidence": []},
            headers=OWNER,
        )

    mtw_finding = finding_for_policy(findings, "POL-MTW-014")
    decision2 = decide(client, mtw_finding["finding_id"])
    log.seeded(
        system_id,
        f"runtime finding -> decision={decision['decision']} (+remediation plan); "
        f"maintenance-window finding -> decision={decision2['decision']}",
    )


def seed_payments_gateway(client, pack_id: str, log) -> None:
    """Fully compliant baseline system -- zero findings, demonstrating the
    system doesn't manufacture violations that aren't there."""
    system_id = "demo-aws-payments-gateway"
    if system_exists(client, system_id):
        return log.skip(system_id)
    register_system(
        client,
        system_id=system_id,
        name="Payments Gateway",
        cloud_provider="aws",
        environment="production",
        criticality="critical",
        owner="taylor.kim",
        team="payments-eng",
    )
    resources = [
        resource("payments-gateway-svc", resource_type="container_service", criticality="critical"),
        resource("payments-gateway-db", resource_type="relational_database", criticality="critical"),
    ]
    submit_state(client, system_id, resources=resources)
    findings = evaluate(client, system_id, pack_id)
    log.seeded(system_id, f"fully compliant baseline -> {len(findings)} findings")


def seed_internal_tools(client, pack_id: str, log) -> None:
    """A second CRITICAL finding (privilege escalation) plus a HIGH removed-
    control finding, both blocked/remediation-required."""
    system_id = "demo-gcp-internal-tools"
    if system_exists(client, system_id):
        return log.skip(system_id)
    register_system(
        client,
        system_id=system_id,
        name="Internal Admin Tools",
        cloud_provider="gcp",
        environment="dev",
        criticality="standard",
        owner="chris.nguyen",
        team="platform-infra",
    )
    resources = [
        resource(
            "internal-admin-console", resource_type="container_service", privilege_escalation_enabled=True
        ),
        resource(
            "internal-audit-relay",
            resource_type="monitoring_config",
            security_controls_removed_since_baseline=True,
        ),
    ]
    submit_state(client, system_id, resources=resources)
    findings = evaluate(client, system_id, pack_id)
    pri_decision = decide(client, finding_for_policy(findings, "POL-PRI-015")["finding_id"])
    ctl_decision = decide(client, finding_for_policy(findings, "POL-CTL-016")["finding_id"])
    log.seeded(
        system_id,
        f"privilege escalation -> decision={pri_decision['decision']}; "
        f"removed control -> decision={ctl_decision['decision']}",
    )


def seed_legacy_reporting(client, pack_id: str, log) -> None:
    """Unauthorized-region finding resolved through a full, approved
    exception workflow -- an ALLOW reached through governance, not silence."""
    system_id = "demo-aws-legacy-reporting"
    if system_exists(client, system_id):
        return log.skip(system_id)
    register_system(
        client,
        system_id=system_id,
        name="Legacy Reporting Service",
        cloud_provider="aws",
        environment="staging",
        criticality="important",
        owner="riley.brooks",
        team="reporting",
    )
    resources = [resource("legacy-reporting-svc", resource_type="container_service", region="eu-west-1")]
    submit_state(client, system_id, resources=resources, allowed_regions=["us-east-1"])
    findings = evaluate(client, system_id, pack_id)
    finding = finding_for_policy(findings, "POL-REG-010")

    exception_id = request_exception(
        client,
        policy_id="POL-REG-010",
        resource_id="legacy-reporting-svc",
        finding_id=finding["finding_id"],
        managed_system_id=system_id,
    )
    client.post(f"/api/v1/exceptions/{exception_id}/review", json=None, headers=REVIEWER)
    client.post(
        f"/api/v1/exceptions/{exception_id}/decide",
        json={
            "approve": True,
            "rationale": "Region pinned for data-residency reasons during migration; monitored.",
        },
        headers=APPROVER,
    )
    decision = decide(client, finding["finding_id"])

    # A couple of AI advisory calls for extra realism/audit diversity -- the
    # deterministic mock provider always passes all 5 gates.
    client.post(f"/api/v1/findings/compliance/{finding['finding_id']}/ai/impact", json=None, headers=OWNER)
    client.patch(
        f"/api/v1/findings/compliance/{finding['finding_id']}/status",
        json={"target_status": "acknowledged"},
        headers=OWNER,
    )
    log.seeded(system_id, f"approved exception -> decision={decision['decision']}")


SEED_FUNCTIONS = [
    seed_checkout_api,
    seed_user_database,
    seed_auth_service,
    seed_billing_service,
    seed_analytics_pipeline,
    seed_payments_gateway,
    seed_internal_tools,
    seed_legacy_reporting,
]


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


class SeedLog:
    def __init__(self) -> None:
        self.seeded_systems: list[str] = []
        self.skipped_systems: list[str] = []

    def seeded(self, system_id: str, detail: str) -> None:
        self.seeded_systems.append(system_id)
        print(f"[seeded] {system_id}: {detail}")

    def skip(self, system_id: str) -> None:
        self.skipped_systems.append(system_id)
        print(f"[skip]   {system_id}: already exists, no-op")


def seed(client, *, quiet: bool = False) -> SeedLog:
    """Runs every demo system's idempotent seed function. Safe to call
    repeatedly -- each function is individually a no-op if its system
    already exists. Returns a SeedLog with what was seeded vs. skipped."""
    log = SeedLog()
    pack_id = ensure_policy_pack(client)
    if not quiet:
        print(f"Policy pack ready: {pack_id}")
    for fn in SEED_FUNCTIONS:
        fn(client, pack_id, log)
    return log


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------


def _refuse_unless_authorized(client: HttpClient, force: bool) -> None:
    if not force and os.environ.get("POLICYGUARD_DEMO_MODE", "").strip().lower() != "true":
        raise SystemExit(
            "Refusing to seed: POLICYGUARD_DEMO_MODE is not set to 'true' in this script's own "
            "environment. Set POLICYGUARD_DEMO_MODE=true to run this deliberately, or pass --force."
        )
    status_resp = client.get("/api/v1/admin/status")
    if status_resp.status_code == 200:
        reported_env = str(status_resp.json().get("environment", "")).strip().lower()
        if reported_env == "production" and not force:
            raise SystemExit(
                f"Refusing to seed: target server at {client.base_url} reports "
                f"environment='{status_resp.json().get('environment')}'. Pass --force if you are "
                "certain this is intended (it should never be, for a real production deployment)."
            )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Bypass the POLICYGUARD_DEMO_MODE and environment=production safety checks.",
    )
    args = parser.parse_args()

    client = HttpClient(args.base_url)
    if client.get("/health").status_code != 200:
        raise SystemExit(f"PolicyGuard API at {client.base_url} is not reachable. Start it first.")

    _refuse_unless_authorized(client, args.force)

    log = seed(client)
    print(f"\nDone: {len(log.seeded_systems)} system(s) seeded, {len(log.skipped_systems)} already present.")
    print(f"View the result at {args.base_url}/dashboard")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
