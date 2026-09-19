# PolicyGuard AI MultiCloud — Continuous Policy, Drift & Compliance Governance POC

A post-deployment governance platform that continuously asks one question — **does the environment still comply with what was approved?** — and answers it with a deterministic policy engine and typed drift detector, never an AI opinion.

---

## The Why

A system that passed every pre-deployment check does not stay compliant on its own. A security group gets loosened for a "temporary" debugging session and never reverted. A rotation removes a required tag. An IAM role picks up a wildcard permission during an incident fix. An approved exception quietly expires while the underlying violation is still there. None of this shows up in a pre-deployment gate — it happens *after* deployment, gradually, usually without anyone deciding "let's become non-compliant."

Continuous governance closes that gap: re-evaluate the real, observed state against policy and against the last approved baseline, on a repeatable schedule, not just at release time.

Generative AI can summarize a violation, explain its blast radius, and draft remediation guidance faster than a human can read the raw evidence. It should not decide whether something is compliant, change a severity, approve its own exception, or close a finding — an LLM is fluent enough to sound authoritative while being wrong, and letting it hold decision authority would trade a slow, safe governance process for a fast, unaccountable one. **Deterministic policy evaluation decides. AI explains. Humans approve exceptions and consequential decisions.** Every explanation, gate result, decision, and human action is written to a tamper-evident audit chain.

## The What

PolicyGuard AI MultiCloud is the **continuous, post-deployment** member of a three-part governance trilogy (see [Trilogy positioning](#enterprise-ai-governance-trilogy) below). It:

- Ingests a normalized **desired state** (the approved baseline) and **observed state** (what a cloud inventory provider actually reports) for AWS and GCP resources.
- Runs the observed state through a **deterministic policy engine** — 20 policy categories, each a pure, independently unit-testable rule — and a **typed drift detector** that compares desired vs. previously-observed vs. currently-observed state field-by-field (never text diffing) across 8 drift types.
- Routes every violation through a **pure decision router** to exactly one governance outcome:

| Decision | Meaning |
|---|---|
| `COMPLIANT` | No violation detected. |
| `OBSERVATION_RECORDED` | Informational: LOW/INFO severity, or an active/eligible exception currently suppresses the finding. |
| `REMEDIATION_REQUIRED` | MEDIUM/HIGH severity, incomplete evidence, or a LOW-severity finding on a critical production resource. |
| `EXCEPTION_REVIEW_REQUIRED` | A policy exception is pending human review. |
| `GOVERNANCE_BLOCK` | CRITICAL severity, a non-exception-eligible critical finding, a failed AI assurance gate, an active emergency stop, or a repeated HIGH-severity violation on a critical production resource. |

- Offers a **policy-exception workflow** (request → review → approve/reject → active → expire/revoke) with enforced separation of duties: a requester can never approve, review, or reject their own exception, and a suppressed finding un-suppresses itself immediately once its exception expires or is revoked.
- Generates AI advisory explanations (summary, impact, grouping, remediation outline) that must pass **five mandatory assurance gates** — schema, grounding, confidence, safety, consistency — before being shown to anyone; a failed gate falls back to a deterministic, evidence-only explanation, never the rejected AI text.
- Provides a **kill switch** (`NORMAL` / `PAUSED` / `EMERGENCY_STOP`) that fails closed: an unreadable kill-switch state is always treated as blocking, never as `NORMAL`.
- Records every governance-relevant action to a **SHA-256 hash-chained audit log**, independently verifiable at any time.

Primary users: security/compliance reviewers, system owners, platform administrators, and auditors — not autonomous agents. Nothing in this system calls a real cloud API, applies Terraform, or remediates anything on its own.

## The How

- **Clean Architecture, modular monolith.** `domain/` (47 modules, zero framework imports — grep-verified for fastapi/sqlalchemy/pydantic/alembic/uvicorn/psycopg/boto3/google.*) → `application/` (use cases, the exception-authorization service, the pure decision router) → `ports/` (`typing.Protocol` interfaces) + `adapters/` (SQLAlchemy persistence, mock AWS/GCP cloud-inventory providers, mock/external AI provider, the five assurance gates, redaction) → `api/` (FastAPI routes, strict Pydantic schemas, dependency wiring).
- **Deterministic policy engine.** 20 policy categories (`POL-NET-001` … `POL-EXC-020`), each with its own pure `evaluate` callable — public network exposure, overly permissive IAM, unencrypted storage, missing logging/monitoring/backup, unsafe secrets storage, prod-using-dev-settings, unapproved baseline resources, unauthorized region, missing ownership/tags, unsupported runtime, outside maintenance window, privilege escalation, removed security controls, data-retention violation, missing HA, architecture-baseline drift, expired exceptions. No AI involved in evaluation.
- **Typed drift detector.** Compares desired/previous-observed/current-observed CloudResource attributes field-by-field across 8 drift types (configuration, security, identity & permission, architectural, operational control, compliance, unmanaged resource, exception), producing a full explanation contract per finding: what changed, previous/current/expected value, why it matters, policy, severity, evidence, remediation, exception eligibility.
- **Pure decision router.** A single function (`route_governance_decision`) turns deterministic evidence into one of the five decisions above. Its input dataclass has no field typed to accept raw AI output — not a design convention, a type-system guarantee — see [`docs/AI_ASSURANCE_AND_GOVERNANCE.md`](docs/AI_ASSURANCE_AND_GOVERNANCE.md).
- **AI provider protocol.** A deterministic, offline `MockAIProvider` is the default and is all tests run against; an `ExternalAIProvider` adapter exists but is disabled unless explicitly configured — no network access or API key is ever required to run this project.
- **Five mandatory assurance gates** run on every AI response: schema validation, grounding (no fabricated evidence citations), confidence thresholds (hard floor + review band), a categorical safety blocklist (destructive actions, fabricated authority claims, credential-like strings), and cross-opinion consistency against the deterministic decision/severity it was generated to explain.
- **PostgreSQL-only, hash-chained audit trail.** Every record's `current_hash = SHA256(previous_hash + canonical_payload)`; `verify_chain()` recomputes every link and detects mutation, reordering, and sequence gaps.
- **Docker Compose environment**: app + PostgreSQL 16 + Alembic migrations + optional Prometheus, one command to stand up.
- **Layered Pytest suite**: unit, application, PostgreSQL integration, API, AI assurance, security, and end-to-end — 293 passing tests, no SQLite anywhere.
- **AWS and GCP Terraform references**: ECS Fargate/RDS/Secrets Manager vs. Cloud Run/Cloud SQL/Secret Manager, both `fmt`+`validate` clean, neither ever applied.

### Architecture flow

```mermaid
flowchart LR
    A[Desired state: approved baseline] --> C[Drift Detector]
    B[Observed state: mock AWS/GCP inventory] --> C
    B --> D[Deterministic Policy Engine]
    C --> F[Pure Decision Router]
    D --> F
    F -->|compliant| G[COMPLIANT]
    F -->|remediation| H[REMEDIATION_REQUIRED]
    F -->|exception pending| I[EXCEPTION_REVIEW_REQUIRED]
    F -->|critical / gate failure| J[GOVERNANCE_BLOCK]
    E[AI Advisory: summary / impact / remediation] --> K[5 Assurance Gates]
    K -.explanation only, never routed into F.-> F
    D -.audit.-> L[(Hash-chained Audit Log)]
    C -.audit.-> L
    F -.audit.-> L
    K -.audit.-> L
```

## Key capabilities

- Deterministic, explainable policy evaluation and drift detection — independent of any AI call.
- AI advisory output that is schema-validated, grounding-checked, confidence-gated, safety-screened, and consistency-checked before it can be shown to anyone.
- A kill switch, checked on every mutation and evaluation path, that fails closed if its own state cannot be read.
- Separation-of-duties exception workflow with a real, audited request/review/decide/revoke trail and spoofed-identity rejection.
- Tamper-evident audit chain with a `/api/v1/audit/verify` endpoint and regression tests proving both tampering and record deletion are detected.
- A read-only dashboard for system/finding/exception/audit status.

## Quick start

```bash
cp .env.example .env
docker compose build
docker compose up -d
docker compose ps
```

Then:

- API docs: <http://localhost:8000/docs>
- Dashboard: <http://localhost:8000/dashboard>
- Health / readiness / metrics: `/health`, `/ready`, `/metrics`

Tear down: `docker compose down` (add `-v` to also drop the database volume).

If `docker build` fails on your machine with a TLS/certificate error, that's almost always an HTTPS-intercepting proxy (corporate network, antivirus) — see [`docs/ENVIRONMENT_LIMITATIONS.md`](docs/ENVIRONMENT_LIMITATIONS.md) for the exact, verified fix (trust the intercepting root certificate via `certs/`, documented there). A Python venv plus a disposable `postgres:16` container is also always a valid alternative — exact commands in [`docs/OPERATIONS_AND_OBSERVABILITY.md`](docs/OPERATIONS_AND_OBSERVABILITY.md).

## Demo execution

18 reproducible synthetic scenarios (fully compliant AWS/GCP systems, public exposure, wildcard IAM, disabled encryption/logging/monitoring, unapproved resources, unauthorized region, missing ownership, approved and expired exceptions, self-approval rejection, an AI gate failing closed, kill-switch blocking, repeated-violation escalation, audit-chain verification, cross-cloud normalization) run against a live instance:

```bash
python demo/scripts/run_demo.py --base-url http://localhost:8000
```

The script is idempotent (safe to re-run against a stack that already has demo data) and exits non-zero if any scenario fails. See [`docs/TESTING_AND_VALIDATION.md`](docs/TESTING_AND_VALIDATION.md) for what each scenario proves.

## Demo / mock dashboard data

`run_demo.py` above proves the 18 required scenarios and then exits — it isn't meant to leave a browsable dataset behind. `demo/scripts/seed_demo_data.py` is a separate, purpose-built script for that: it populates the [dashboard](#quick-start) with 8 realistic, clearly-marked synthetic systems (AWS + GCP, a full LOW/MEDIUM/HIGH/CRITICAL severity spread, `GOVERNANCE_BLOCK`/`REMEDIATION_REQUIRED`/`OBSERVATION_RECORDED` decisions, exceptions in all 4 real states, a drift finding, a remediation plan, and AI advisory calls) so the dashboard looks like a live, in-use system instead of an empty page — useful for demos, screenshots, or just seeing what the governance model looks like with data behind it.

**Why it exists:** a freshly-migrated instance has an empty dashboard, which is correct but not demonstrative. Real usage naturally populates it over time; this script does the same thing immediately, through the same real, unmodified API every other client uses — it does not bypass policy evaluation, the decision router, assurance gates, or the audit trail.

**How production stays protected:**
- Nothing in the application ever calls this script automatically — it only runs when a human explicitly invokes it.
- It refuses to run unless `POLICYGUARD_DEMO_MODE=true` is set in its own environment, and separately refuses if the *target server* reports `environment=production` — both checks must be deliberately bypassed with `--force` to override.
- Every seeded record is clearly marked: managed system ids use the reserved `demo-` prefix (e.g. `demo-aws-checkout-api`) and carry `tags={"source": "demo", "is_demo": "true"}`.
- The dashboard only shows the "⚠ DEMO / MOCK DATA" banner when `POLICYGUARD_DEMO_MODE=true` is set on the running server itself — off by default, and never implied by the mere presence of data.

**Seed** (idempotent — safe to re-run; already-seeded systems are skipped, never duplicated):

```bash
# Docker Compose
docker compose exec app env POLICYGUARD_DEMO_MODE=true python demo/scripts/seed_demo_data.py

# Local venv
POLICYGUARD_DEMO_MODE=true python demo/scripts/seed_demo_data.py --base-url http://localhost:8000
```

**Reset** (removes only the demo records it created — see below for exactly what it does and doesn't touch):

```bash
# Docker Compose
docker compose exec app env POLICYGUARD_DEMO_MODE=true python demo/scripts/reset_demo_data.py

# Local venv (connects directly to Postgres -- reads POLICYGUARD_DATABASE_URL)
POLICYGUARD_DEMO_MODE=true python demo/scripts/reset_demo_data.py
```

`reset_demo_data.py` deletes rows scoped to the reserved `demo-` id prefix across managed systems, snapshots, findings, decisions, exceptions, and remediation plans — and nothing else. It never touches `audit_events` (the hash chain is append-only and tamper-evident by design; deleting from the middle of it would trigger the *same* tamper detection that protects real history — see [`docs/SECURITY.md`](docs/SECURITY.md)) or `policies`/`policy_packs` (shared infrastructure, not demo data). Both scripts, plus dashboard rendering and demo-mode gating, are covered by `tests/demo/test_demo_seed.py`.

## API endpoints

47 route/method combinations across 8 capability groups (full list at `/openapi.json` once running):

```
POST/GET   /api/v1/systems                          register / list managed systems
POST       /api/v1/systems/{id}/desired-state        submit approved baseline
POST       /api/v1/systems/{id}/observed-state[/fetch]  submit or fetch mock inventory
GET        /api/v1/systems/{id}/snapshot-comparison   desired vs. observed
POST       /api/v1/systems/{id}/drift-detection       run typed drift comparison
POST/GET   /api/v1/policies[/packs]                   create/list/activate policies & packs
POST       /api/v1/policies/packs/{id}/evaluate       run the deterministic policy engine
GET/PATCH  /api/v1/findings/{kind}/{id}[/status]      list/detail findings, status transitions
POST       /api/v1/findings/{kind}/{id}/decision      generate a governance decision
POST       /api/v1/findings/{kind}/{id}/ai/*          AI summary/impact/remediation (gated)
POST/GET   /api/v1/findings/{kind}/{id}/remediation-plan  create / inspect a remediation plan
PATCH      /api/v1/findings/remediation-plans/{id}/status  transition a remediation plan
POST/GET   /api/v1/exceptions[/{id}/review|decide|revoke]  the exception lifecycle
POST       /api/v1/exceptions/expire-sweep            sweep expired exceptions
GET/POST   /api/v1/admin/kill-switch                  read / change system mode
GET        /api/v1/admin/status                       aggregate system status
GET        /api/v1/audit/events | /api/v1/audit/verify  audit query & hash-chain verification
GET        /dashboard   /health   /ready   /metrics
```

Actor identity for this POC is via `X-PolicyGuard-Actor` / `X-PolicyGuard-Role` headers — a documented, explicit boundary, not production-grade authentication (see [Security boundaries](#security-boundaries)).

## Testing

```bash
# Everything needs PostgreSQL (see docker-compose.yml's db service) -- never SQLite.
POLICYGUARD_DATABASE_URL=postgresql+psycopg://policyguard:policyguard@localhost:5432/policyguard_test \
  pytest -v
```

| Layer | What it covers | Count |
|---|---|---|
| `tests/unit` | Policy engine (all 20 categories), drift detector (all 8 types), decision router (incl. the AI-cannot-influence-decision regression), state machines, separation of duties | 125 |
| `tests/application` | Use-case orchestration over fake repositories | 13 |
| `tests/integration` | Real PostgreSQL: repositories, audit hash-chain, kill-switch storage, remediation use case | 33 |
| `tests/api` | Every route, real Postgres via `TestClient` | 67 |
| `tests/assurance` | All 5 gates individually, the fallback pipeline, AI-cannot-influence-decision at the HTTP layer | 30 |
| `tests/security` | Self-approval, spoofed identity, expired-exception reuse, audit tampering, kill-switch bypass, malformed evidence, invalid transitions, payload/schema hardening | 22 |
| `tests/e2e` | Full governance lifecycle over HTTP; a real `docker compose build`/`up`/healthcheck/call/`down` against the containerized app | 3 |
| `tests/demo` | The demo/mock data seed + reset scripts: idempotency, tagging, dashboard rendering, reset scope | 16 |

**309 passed, 0 skipped.** Ruff and mypy are clean across the repository.

## Repository structure

```
src/
├── domain/          entities, enums, policy engine, drift detector, state machines — no framework imports
├── application/     use cases, decision router, exception-authorization service
├── ports/           Protocol definitions for repositories, AI, and cloud-inventory providers
├── adapters/        SQLAlchemy persistence, mock AWS/GCP inventory, mock/external AI, 5 assurance gates, redaction
├── api/             FastAPI routes, strict schemas, dependency wiring
├── observability/   structured logging, correlation IDs, Prometheus metrics
├── security/        actor/role header parsing
└── main.py
tests/{unit,application,integration,api,assurance,security,e2e}/
demo/scripts/run_demo.py   18 synthetic scenarios against a live instance
migrations/                 Alembic
infrastructure/{aws,gcp}/   Terraform reference architectures (validated, never applied)
docs/                        architecture, policy/drift model, AI governance, exceptions, security, testing, ops, multi-cloud, roadmap, trilogy
```

## Security boundaries

- **Identity is header-based** (`X-PolicyGuard-Actor`/`X-PolicyGuard-Role`) — a documented POC boundary. Production needs OIDC/OAuth2, an enterprise IdP, and signed tokens (see roadmap doc).
- **The audit chain is tamper-evident, not immutable.** SHA-256 hash chaining detects retroactive mutation or record deletion; it does not physically prevent someone with direct database access from rewriting the whole chain consistently. External WORM storage/ledger anchoring is a documented production-hardening step.
- **AI never gets the last word.** `route_governance_decision`'s input dataclass has no field that can carry AI output — enforced by the type system, proven by a dedicated regression test, not just policy.
- Strict Pydantic schemas (`extra="forbid"` on every request model), a 1 MB payload limit, secret/credential redaction on every audit payload and error response, non-root Docker user, parameterized database access throughout.

Full detail in [`docs/SECURITY.md`](docs/SECURITY.md).

## Known limitations

- Synchronous, single-process evaluation — no background worker/queue.
- Header-based actor identity, not a real auth system.
- In-database hash chain rather than external ledger anchoring.
- Terraform is validated (`fmt`+`init`) but never applied — no cloud resources exist because of this repository.
- `terraform validate` itself fails on this specific development machine: Norton AV's HTTPS-scanning proxy interferes with Terraform's own internal loopback handshake to its provider-plugin subprocess (a different mechanism from the item below — not a system-CA-trust problem, so it has no equivalent fix). Root-caused and documented, not hidden — see [`docs/ENVIRONMENT_LIMITATIONS.md`](docs/ENVIRONMENT_LIMITATIONS.md). Expected to pass unmodified in GitHub Actions CI or on a machine without that interception.
- (Resolved) `docker build` previously failed on this same machine for the same underlying reason (the proxy also intercepts `pip install`'s connection to `pypi.org`); fixed by explicitly trusting the intercepting root certificate — see [`docs/ENVIRONMENT_LIMITATIONS.md`](docs/ENVIRONMENT_LIMITATIONS.md) for exactly how and why this doesn't weaken TLS verification. `docker build`/`docker compose up` now work end-to-end on this machine; all 293 tests (including the real Dockerized e2e test) pass with zero skips.

## Production-hardening roadmap

OIDC/OAuth2 + enterprise IdP · async evaluation scheduler/queue · WORM/ledger audit anchoring · multi-AZ RDS/Cloud SQL · private networking end-to-end · real (non-mock) cloud inventory collectors · alerting on gate failures and kill-switch changes. Full detail in [`docs/TRADEOFFS_AND_PRODUCTION_ROADMAP.md`](docs/TRADEOFFS_AND_PRODUCTION_ROADMAP.md).

## Enterprise AI Governance Trilogy

PolicyGuard is the **continuous, post-deployment** member of a three-part governance architecture:

- **ChangeGuard AI MultiCloud** — is a proposed change safe enough to progress toward deployment?
- **ArchGuard AI** — runtime incident response and architectural impact once something is already live.
- **PolicyGuard AI MultiCloud** (this repo) — does the current environment still comply with its approved state and policies, continuously, after deployment?

All three share the same philosophy — deterministic gates, fail-closed behavior, human-in-the-loop, provider-independence, tamper-evident auditability — but own distinct business questions and never overlap in responsibility. See [`docs/TRILOGY_POSITIONING.md`](docs/TRILOGY_POSITIONING.md).
