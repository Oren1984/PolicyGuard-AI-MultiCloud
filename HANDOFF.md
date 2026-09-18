# PolicyGuard AI MultiCloud — Build Handoff

Internal build-tracking document. Not part of the final deliverable set in
`promrt_1.md` §24 — remove this file during final cleanup (§21/§26) once the
project is complete and its content is superseded by `README.md` / `docs/`.

Full authoritative spec: `promrt_1.md` (repo root, 33 sections). Architecture
style reference (do not copy business logic): sibling repo
`C:\Users\ORENS\ChangeGuard-AI-MultiCloud`.

Build strategy: sequential phases, each executed by a fresh delegated agent
with no memory of prior phases, briefed with the exact class/interface names
the previous phase produced. This doc is the cross-session source of truth
for those names and for what's done vs. pending.

---

## Status as of last update (2026-09-18)

- **Phase 1 — Domain / Application / Ports: COMPLETE.**
- **Phase 2 — Adapters (persistence, cloud mocks, AI, assurance gates, audit chain): COMPLETE** (agent finished between sessions; report absorbed below, verified by re-import smoke test this session).
- **Phase 3 — API layer (src/api/, src/main.py, src/config.py, src/security/, src/observability/): COMPLETE** (2026-09-18). Verified with a real, temporary Docker Postgres container (not just imports) — full demo workflow (register system → fetch mock AWS inventory → submit desired state → create policy/pack → evaluate → generate governance decision → AI explanation through all 5 assurance gates → exception request/self-approval-rejection/spoofing-rejection/review/approve → kill-switch EMERGENCY_STOP blocking mutations while health/audit stay up → PAUSED blocking evaluations/approvals only → audit-chain verification → dashboard render) all passed against live PostgreSQL via FastAPI TestClient. Ruff clean; mypy clean for every Phase 3 file (pre-existing Phase 1/2 mypy findings in `src/ports/exception_repository.py`, `src/application/use_cases/expire_exceptions.py`, `src/application/use_cases/generate_governance_decision.py`, `src/adapters/persistence/exception_repository_sqlalchemy.py` are out of Phase 3 scope and were left untouched, per instructions not to modify those layers).
  - **Independently re-verified this session** (parent session, not the delegated agent) before accepting the report: `git status --short` confirmed all new files (`src/`, `static/`, `templates/`) are untracked with nothing committed; every claimed file path was confirmed to exist on disk; `python -c "from src.main import app; app.openapi()"` succeeded standalone and produced 41 path entries / 47 route+method combos; `ruff check src/api src/main.py src/config.py src/security src/observability` passed with no findings.
- **Phases 4–7: NOT STARTED — resume here next.** Phase 4 (Infrastructure: Dockerfile, docker-compose.yml, Alembic migrations, Terraform for AWS/GCP, GitHub Actions CI) is the next phase to brief and delegate. See "Remaining phases" below for its exact scope, and "How to resume" for the briefing procedure.

This commit includes all Phase 1–3 work (domain/application/ports, adapters,
API layer). Per explicit instruction from the user this turn, it has now
been committed and pushed — this is the first commit/push of this build; do
**not** treat this as blanket standing permission to commit/push future
phases without being asked again.

---

## Phase 1 — DONE

Scope: `src/domain/`, `src/application/`, `src/ports/`, plus repo scaffolding
(`pyproject.toml`, `.gitignore`, package `__init__.py` placeholders for
`adapters/`, `api/`, `infrastructure/`).

Verified: domain layer has **zero framework imports** (grep-verified for
fastapi/sqlalchemy/pydantic/alembic/uvicorn/psycopg/boto3/google.*, plus all
76 modules import successfully with no third-party deps installed).

### Exact names Phase 2+ must build against

**Domain enums** (`src/domain/enums/`): CloudProvider, Environment,
ResourceType, PolicyCategory, PolicySeverity, DriftType, FindingStatus,
DecisionType, ExceptionStatus, RemediationStatus, ActorRole, SystemMode,
**ResourceCriticality**, **GateName**, **GateStatus** (last 3 are documented
additions beyond the spec's mandatory 12, needed structurally for the
decision router / gate contracts).

**Domain entities** (`src/domain/entities/`, frozen dataclasses): all 16
spec-required entities (ManagedSystem, CloudResource,
DesiredStateSnapshot, ObservedStateSnapshot, Policy, PolicyPack,
PolicyEvaluation, DriftFinding, ComplianceFinding, GovernanceDecision,
RemediationPlan, PolicyException, ExceptionApproval, EvidenceRecord,
AuditEvent, Actor, CorrelationContext) plus **GateResult**,
**GatePipelineResult**, **AIAdvisoryContent**.

**State machines** (`src/domain/state_machine/`): `finding_transitions.py`,
`exception_transitions.py` (Requested→Under review→Approved/Rejected→
Active→Expired/Revoked), `remediation_transitions.py`,
`decision_transitions.py`. Each is an explicit allow-list dict +
`validate_transition()` raising `InvalidStateTransitionError` (fail closed).

**Policy engine** (`src/domain/policy_engine/`):
`definitions.py::build_default_policy_pack()` — all 20 spec categories as
`Policy` objects, stable IDs `POL-NET-001` … `POL-EXC-020`, each with its own
pure `evaluate` callable. `evaluator.py::evaluate_policy_pack(...)`.

**Drift detection** (`src/domain/drift/detector.py`):
`detect_drift(...)` — typed field comparison (not text diffing), all 8 drift
types, full explanation contract (what/previous/current/expected/why/
policy/severity/evidence/remediation/exception-eligible).

**Decision router** — `src/application/routing/decision_router.py`:
`route_governance_decision(context: GovernanceDecisionContext) ->
GovernanceRoutingResult`. **Structural guarantee (spec §9): `GovernanceDecisionContext` has no field typed to accept AI output** — only deterministic
inputs (severity, environment, resource_criticality, evidence_complete,
exception_status, exception_eligible, critical_non_eligible,
repeated_violation_count, system_mode, `gates: GatePipelineResult | None`).
A regression test proving this separation is still owed to Phase 5 (Testing)
if not already covered.

**Application use cases** (`src/application/use_cases/`):
SubmitDesiredStateSnapshotUseCase, SubmitObservedStateSnapshotUseCase,
EvaluatePolicyPackUseCase, DetectDriftUseCase,
GenerateGovernanceDecisionUseCase, RequestPolicyExceptionUseCase,
ReviewPolicyExceptionUseCase, DecidePolicyExceptionUseCase,
RevokePolicyExceptionUseCase, ExpireExceptionsUseCase,
UpdateRemediationStatusUseCase, KillSwitchUseCase, RecordAuditEventUseCase,
VerifyAuditChainUseCase.

Separation-of-duties: `src/application/services/exception_authorization.py`
→ `ExceptionAuthorizationService` (authorize_request / authorize_decision /
authorize_revocation), backed by pure rules in
`src/domain/policies/separation_of_duties.py`.

**Ports** (`src/ports/`, Protocol/ABC — Phase 2 implements adapters for
every one of these):
- `ManagedSystemRepository`
- `DesiredStateSnapshotRepository`, `ObservedStateSnapshotRepository`
- `PolicyRepository`, `PolicyPackRepository`
- `ComplianceFindingRepository`, `DriftFindingRepository`
- `GovernanceDecisionRepository`
- `PolicyExceptionRepository`
- `RemediationPlanRepository`
- `AuditEventRepository`
- `KillSwitchRepository`
- `AIProvider` (summarize_findings, explain_impact,
  group_related_violations, generate_remediation_outline — no
  compliance/severity/decision methods, by design)
- `CloudInventoryProvider` (fetch_observed_snapshot; provider: CloudProvider)
- `AssuranceGate` (interface only — implementations are Phase 2)

### Deviations from spec (Phase 1, all documented in code comments)

1. Added `ResourceCriticality`, `GateName`, `GateStatus` enums beyond the
   mandatory 12 — needed as typed inputs to the decision router/gate
   contract.
2. `PolicyException` carries a `resource_id` field (not just `finding_id`)
   since finding IDs regenerate each evaluation run; suppression keys off
   `(policy_id, resource_id)`.
3. Decision router lives in `src/application/routing/` (not
   `src/domain/decision/`) — matches ChangeGuard's convention; still a pure
   function with no I/O.
4. Gate-failure escalation in the router only hard-blocks on `FAILED` (not
   `WARNING`) — `WARNING` is audited but doesn't independently change
   decision type this phase. Revisit if Phase 2/5 need stricter behavior.

---

## Phase 2 — DONE

Scope built: `src/adapters/persistence/`, `src/adapters/cloud/`,
`src/adapters/ai/`, `src/adapters/assurance/`, `src/adapters/security/`.
The delegated agent finished between sessions; no completion message was
ever absorbed into this file. This session verified the result directly
against the filesystem (file listing + class grep + a full-module Python
import smoke test — all adapter modules import cleanly with dependencies
installed) rather than trusting the stale "IN PROGRESS" status.

### Exact names Phase 3+ must build against

**Persistence** (`src/adapters/persistence/`):

- `models.py` — SQLAlchemy 2.x ORM (`Base(DeclarativeBase)`):
  `ManagedSystemORM`, `DesiredStateSnapshotORM`, `ObservedStateSnapshotORM`,
  `PolicyORM`, `PolicyPackORM`, `ComplianceFindingORM`, `DriftFindingORM`,
  `GovernanceDecisionORM`, `PolicyExceptionORM`, `RemediationPlanORM`,
  `AuditEventORM`, `KillSwitchStateORM`.
- `db.py` — engine/session setup.
- `mappers.py` — ORM ⟷ domain entity mapping.
- Repository implementations (one per Phase 1 port):
  `SqlAlchemyManagedSystemRepository`,
  `SqlAlchemyDesiredStateSnapshotRepository`,
  `SqlAlchemyObservedStateSnapshotRepository`, `SqlAlchemyPolicyRepository`,
  `SqlAlchemyPolicyPackRepository`, `SqlAlchemyComplianceFindingRepository`,
  `SqlAlchemyDriftFindingRepository`, `SqlAlchemyGovernanceDecisionRepository`,
  `SqlAlchemyPolicyExceptionRepository`, `SqlAlchemyRemediationPlanRepository`,
  `SqlAlchemyAuditEventRepository`, `SqlAlchemyKillSwitchRepository` (raises
  `KillSwitchStateUnavailableError` when no row exists — fail-closed).
- `SqlAlchemyAuditEventRepository.verify_chain() -> ChainVerificationResult`
  implements the hash-chain check. **No port change needed** — Phase 1's
  `AuditEventRepository` Protocol already declared `verify_chain` and
  `list_recent`; the impl also adds `list_for_resource(resource_type,
  resource_id)` as an extra convenience method (not on the Protocol, callers
  needing it must depend on the concrete class or the port should be
  extended in Phase 3 if the API layer needs it — currently undecided, flag
  this to Phase 3's agent).
- `policy_registry.py::resolve_evaluate_fn(policy_id)` — deliberate
  documented deviation (see below): reattaches each `Policy`'s pure
  `evaluate` callable at read time since it can't be persisted to Postgres;
  fails closed (`_fail_closed_evaluate`, always reports a violation) for any
  policy_id with no registered evaluator.

**Cloud mocks** (`src/adapters/cloud/`): `MockAWSInventoryProvider`,
`MockGCPInventoryProvider` — both implement `CloudInventoryProvider`,
deterministic synthetic inventories with a deliberate mix of
compliant/violating resources per spec §6.

**AI** (`src/adapters/ai/`): `MockAIProvider` (default,
implements `AIProvider`), `ExternalAIProvider` (disabled stub for future
real-provider wiring).

**Assurance gates** (`src/adapters/assurance/`), all implementing
`AssuranceGate`: `SchemaGate` (validates `AIAdvisoryContent` via internal
Pydantic model `_AIAdvisoryContentSchema`), `GroundingGate`,
`ConfidenceGate` (+ `ConfidenceThresholds` config object), `SafetyGate`,
`ConsistencyGate`. `pipeline.py::AssuranceGateRunner` runs all five in
sequence and produces `GatePipelineResult`.

**Security** (`src/adapters/security/redaction.py`): `redact_value(value:
str) -> str`, `redact_mapping(data: dict) -> dict` — applied inside
`SqlAlchemyAuditEventRepository.append()` to sanitize payloads before
hash-chaining/persisting, per the port's documented contract.

### Deviations from spec / Phase 1 plan (Phase 2, documented in code)

1. `policy_registry.py`: policy engine is not fully data-driven. Policy
   *metadata* is persisted/versioned via `SqlAlchemyPolicyRepository`; the
   executable `evaluate` rule stays code-defined in
   `src/domain/policy_engine/definitions.py` and is looked up by
   `policy_id`. A custom policy registered only in Postgres (not also
   registered in `build_default_policy_pack()` or this registry) has no
   executable rule and fails closed rather than silently passing.
2. `SqlAlchemyAuditEventRepository` exposes `list_for_resource(...)` beyond
   the `AuditEventRepository` Protocol's declared methods — Phase 3 should
   decide whether to promote it onto the port if the API/audit endpoints
   need it, or keep it adapter-only.

Explicitly deferred, still out of scope: API routes, `main.py`, Docker,
real Alembic migration files, tests directory, docs — all Phase 3+.

---

## Phase 3 — DONE

Scope built: `src/config.py`, `src/main.py`, `src/security/actor_context.py`,
`src/observability/{correlation,logging,metrics}.py`,
`src/api/dependencies/{actor,db,repositories,providers,use_cases,kill_switch_gate}.py`,
`src/api/schemas/{error,system,policy,finding,exception,admin,audit}_schemas.py`,
`src/api/routes/{health,systems,policies,findings,exceptions,admin,audit,dashboard}.py`
+ `src/api/routes/_converters.py`, `templates/dashboard.html`,
`static/css/dashboard.css`.

### Exact names Phase 4+ must build against

- **Config**: `src/config.py::Settings` (pydantic-settings, env prefix
  `POLICYGUARD_`, reads `POLICYGUARD_DATABASE_URL`,
  `POLICYGUARD_KILL_SWITCH_DEFAULT_MODE`, `POLICYGUARD_AI_PROVIDER`, etc.),
  `get_settings()` (lru_cached).
- **App factory**: `src/main.py::create_app()` / module-level `app`.
- **Actor identity**: `src/security/actor_context.py::parse_actor_context()`
  returns the domain's own `Actor` entity directly (no separate
  ActorContext type) from headers `X-PolicyGuard-Actor` /
  `X-PolicyGuard-Role`. Wired via `src/api/dependencies/actor.py::get_actor`.
- **Kill-switch gating**: two FastAPI dependencies in
  `src/api/dependencies/kill_switch_gate.py` —
  `require_mutation_allowed` (blocks only in EMERGENCY_STOP) and
  `require_normal_mode_for_evaluation` (blocks in PAUSED or
  EMERGENCY_STOP), both fail-closed on `KillSwitchStateUnavailableError`.
  `EvaluatePolicyPackUseCase`/`DetectDriftUseCase` rely on their own
  built-in equivalent check instead (mapped to 503 in `main.py`) rather
  than a duplicate dependency.
- **Metrics** (`src/observability/metrics.py`, prefix `policyguard_`):
  `evaluations_total`, `evaluation_duration_seconds`, `findings_total`
  (severity/provider/kind), `decisions_total`, `gate_failures_total`,
  `exception_events_total`, `audit_chain_valid` (Gauge), `db_ready`
  (Gauge), `http_errors_total`.
- **41 routes** across 8 routers — see `src/main.py`'s `include_router`
  calls and each router module's own docstring for the exact path list;
  full path list also visible at `/openapi.json` once the app is running.
- **AI advisory orchestration**: `src/api/dependencies/providers.py::AIAdvisoryOrchestrator`
  — thin glue over the existing `AIProvider` port and
  `AssuranceGateRunner` pipeline (no new business logic; added at the API
  layer rather than `src/application/`, which was out of Phase 3 scope).
- **Two thin Phase-3 fill-ins for gaps in the Phase 1 application layer**
  (documented in `src/api/routes/findings.py`'s module docstring): creating
  a `RemediationPlan` for a finding, and transitioning a finding's own
  `FindingStatus` — neither had a use case in Phase 1, so both are done as
  validate-then-persist-then-audit orchestration directly in the route,
  mirroring the pattern of e.g. `SubmitDesiredStateSnapshotUseCase`.
- **`list_for_resource` / `AuditEventRepository` Protocol question
  (flagged by Phase 2) resolved**: no port change was needed —
  `list_for_resource(resource_type, resource_id)` was already declared on
  the `AuditEventRepository` Protocol in `src/ports/audit_repository.py`
  by the time Phase 3 started (Phase 2's note was stale); `src/api/routes/audit.py`
  calls it directly through the Protocol-typed dependency.

### Deviations from spec / brief (Phase 3, documented in code comments)

1. Header-based identity resolves directly into the domain's own `Actor`
   entity rather than a separate API-layer `ActorContext` type (unlike the
   ChangeGuard style reference) — Phase 1's use cases already take
   `actor: Actor` everywhere, so a second type would only add a conversion
   step with no benefit.
2. Kill-switch mode gating is implemented as two selectively-applied
   FastAPI dependencies, not ASGI middleware — a dependency is directly
   attachable per-route, avoiding hand-rolled path-matching logic a
   middleware implementation would need.
3. `_require_policy_admin` (role check for policy/pack create/activate/
   deactivate) is enforced directly in `src/api/routes/policies.py` against
   the domain's `POLICY_ADMIN_ROLES` set rather than through a dedicated
   application-layer authorization service (unlike exceptions, which do
   have `ExceptionAuthorizationService`) — Phase 1 didn't build one for
   this narrower, single-role check.
4. Reused `src/adapters/security/redaction.py` (Phase 2) instead of adding
   a second, duplicate `src/security/redaction.py` — the brief said "re-use
   / wiring", so `src/observability/logging.py` and `src/main.py`'s error
   handler both import from the Phase 2 module directly.
5. A real bug was caught and fixed during this phase's own end-to-end
   smoke test: `src/api/schemas/system_schemas.py` originally declared its
   own second, structurally-identical `DriftFindingResponse` class instead
   of reusing the one in `finding_schemas.py`; FastAPI's strict
   response-model validation rejected real converter output as "not an
   instance of" the wrong class. Fixed by importing the one class instead
   of duplicating it.

### What was verified vs. not

Verified: every Phase 3 file imports cleanly; `app.openapi()` generates a
valid schema for all 41 routes; Ruff and mypy are clean for every file this
phase touched (pre-existing mypy findings in Phase 1/2 files at
`src/ports/exception_repository.py`, `src/adapters/persistence/exception_repository_sqlalchemy.py`,
and two `src/application/use_cases/*.py` files are unrelated to Phase 3 and
were left as-is). A temporary `postgres:16-alpine` Docker container was
used (started and removed within this session — no permanent
infrastructure added, Docker/Compose remain Phase 4's job) to run the full
demo workflow end-to-end through `TestClient` against real PostgreSQL:
system registration, mock-AWS inventory fetch, snapshot submission, policy/
pack creation, policy-pack evaluation, drift detection, governance-decision
generation, AI explanation through all 5 assurance gates, the full
exception workflow including a rejected self-approval and a rejected
spoofed-identity attempt, kill-switch EMERGENCY_STOP/PAUSED/NORMAL
transitions and their gating effects, audit-chain verification, and
dashboard rendering. Not verified: Docker Compose/Dockerfile (Phase 4),
Alembic migrations (Phase 4; `Base.metadata.create_all()` was used only for
this session's own manual smoke test, per the brief's explicit allowance),
and the demo/test suite proper (Phase 5).

---

## Remaining phases (planned, not yet started)

**Phase 4 — Infrastructure**: multi-stage Dockerfile (non-root user),
`docker-compose.yml` (Postgres + migrations + app + optional Prometheus,
health checks, persistent volume), `.env.example`, real Alembic migration
files generated from Phase 2's models, `monitoring/prometheus.yml`,
Terraform reference architectures for AWS (ECS Fargate, RDS Postgres,
Secrets Manager, CloudWatch, least-privilege IAM, networking/SGs) and GCP
(Cloud Run v2, Cloud SQL, Secret Manager, Cloud Logging/Monitoring, IAM
service accounts, networking) under `infrastructure/aws/` and
`infrastructure/gcp/` — `terraform fmt -check` + `terraform validate` only,
never `apply`. One lean GitHub Actions workflow (`.github/workflows/`) per
spec §23.

**Phase 5 — Tests**: domain unit, policy-engine, drift-comparison,
decision-router (including the required regression test proving AI cannot
influence the decision), state-machine, application use-case, PostgreSQL
integration (real Postgres, no SQLite anywhere), API tests, AI-assurance
tests, security tests (self-approval rejection, spoofed identity, expired
exception reuse, audit tampering, kill-switch bypass, missing/malformed
evidence, invalid transitions), exception-workflow tests, audit-chain tests,
Dockerized E2E tests. Plus `demo/` scenarios script covering all 18 scenarios
in spec §19, runnable against the live Docker Compose stack.

**Phase 6 — Documentation**: root `README.md` (What/Why/How per §30) and
`docs/` — all 10 files listed in §24 (ARCHITECTURE, POLICY_AND_DRIFT_MODEL,
AI_ASSURANCE_AND_GOVERNANCE, EXCEPTION_WORKFLOW, SECURITY,
TESTING_AND_VALIDATION, OPERATIONS_AND_OBSERVABILITY, MULTI_CLOUD_REFERENCE,
TRADEOFFS_AND_PRODUCTION_ROADMAP, TRILOGY_POSITIONING). Must be written
*after* implementation is stable so it reflects reality, not aspiration
(§33 acceptance criteria) — do this phase last, right before final
validation, and re-check it against the final repo state afterward.

**Phase 7 — Final validation** (done directly, not delegated): full pytest
suite, ruff, mypy, Docker image build, `docker compose up` from clean state,
all demo scenarios against the live stack, dashboard/health/readiness/
metrics/OpenAPI checks, Terraform validate (AWS + GCP), migrations from an
empty DB, audit-chain verification, kill-switch behavior, exception
separation-of-duties, secret-staging check, cleanup of caches/temp files
(including this `HANDOFF.md`), then the structured final report per spec §29
— ending with a request for commit/push authorization (do not commit or push
before that).

---

## How to resume this build in a new session

1. Read this file first.
2. Check whether the "IN PROGRESS" phase's delegated agent actually
   completed (a prior session may have ended before the completion
   notification arrived) — if so, absorb its report into the "DONE" section
   above with exact names, then move to the next phase.
3. Brief the next phase's agent using the exact names recorded here, plus
   pointers to `promrt_1.md` and the ChangeGuard sibling repo for style.
4. Keep this file updated after every phase completes, before starting the
   next one.
5. If any issues arise during a phase, document them immediately in this file
   under a new "ISSUES" section, and address them before proceeding further.

---
