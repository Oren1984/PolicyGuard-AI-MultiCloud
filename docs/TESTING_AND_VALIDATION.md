# Testing and Validation

## Test layers

```bash
POLICYGUARD_DATABASE_URL=postgresql+psycopg://policyguard:policyguard@localhost:5432/policyguard_test \
  pytest -v
```

| Layer | Purpose | Needs Postgres | Count |
|---|---|---|---|
| `tests/unit/` | Policy engine (all 20 categories, parametrized), drift detector (all 8 types), decision router (every routing rule + the 3-fold AI-cannot-influence regression), the 4 state machines, separation-of-duties/kill-switch pure functions, audit hash-chain algorithm | No | 125 |
| `tests/application/` | Use-case orchestration against `tests/fixtures/fake_repositories.py` (pure in-memory fakes) | No | 13 |
| `tests/integration/` | Real repository implementations: CRUD, JSONB round-tripping, the audit hash-chain repository, kill-switch storage, the remediation-status use case directly (not through HTTP) | **Yes** | 33 |
| `tests/api/` | Every route via `TestClient`, against real Postgres — systems, policies, findings/decisions, exceptions, admin/kill-switch, audit | **Yes** | 67 |
| `tests/assurance/` | All 5 gates individually, the fallback pipeline end-to-end, AI-cannot-influence-decision proven again at the HTTP layer, AI-provider-boundary checks | **Yes** (most) | 30 |
| `tests/security/` | Self-approval, spoofed identity, expired-exception reuse, audit tampering, kill-switch bypass attempts, missing/malformed evidence, invalid state transitions, oversized payloads, injection-as-inert-data, error-response redaction | **Yes** (most) | 22 |
| `tests/e2e/` | One continuous full-lifecycle HTTP flow; a real `docker compose build`/`up`/healthcheck/call/`down` flow against the containerized app | **Yes** | 3 |
| `tests/demo/` | The demo/mock data seed and reset scripts (`demo/scripts/{seed,reset}_demo_data.py`): idempotency, demo-tag marking, severity/decision/provider spread, dashboard rendering and banner on/off, reset's scope (removes only demo rows, never audit/policies), audit chain still valid after reset, safety-gate refusal | **Yes** | 16 |

**309 passed, 0 skipped, 0 failed.** No SQLite anywhere in the codebase or test suite — `tests/conftest.py`'s own docstring states this explicitly and every fixture that touches a database points at a real `postgresql+psycopg://` URL.

## PostgreSQL integration strategy

A disposable `postgres:16` container is expected to already be running and reachable at `POLICYGUARD_DATABASE_URL` before the suite is invoked — `tests/conftest.py` does not start or stop it. An autouse `_clean_db` fixture `TRUNCATE`s every application table (`RESTART IDENTITY CASCADE`) before each test, so tests never depend on execution order or leftover state from a previous test, without paying the cost of a fresh container per test. A session-scoped `client` fixture enters `TestClient(app)` as a context manager, which runs the real FastAPI lifespan hook — including kill-switch seeding — exactly as a real deployment's first boot would.

## Security and assurance regression tests

The 8 spec-mandated regression categories each have a dedicated, real (not simulated) test:

| Regression | Test |
|---|---|
| Requester self-approval | `tests/security/test_security_regressions.py::TestSelfApprovalRegression` |
| Spoofed identity fields | `tests/security/test_security_regressions.py::TestSpoofedIdentityRegression` |
| Expired exception reuse | `tests/security/test_security_regressions.py::TestExpiredExceptionReuseRegression` |
| AI attempting to influence the decision | `tests/unit/test_decision_router.py` + `tests/assurance/test_ai_cannot_influence_decision_api.py` |
| Audit-chain tampering | `tests/security/test_security_regressions.py::TestAuditChainTamperingRegression` — directly UPDATEs a persisted `audit_events` row via `db_engine` and confirms `/api/v1/audit/verify` flips to invalid at the exact tampered sequence |
| Kill-switch bypass attempts | `tests/security/test_security_regressions.py::TestKillSwitchBypassRegression` |
| Missing or malformed evidence | `tests/security/test_security_regressions.py::TestMissingOrMalformedEvidenceRegression` |
| Invalid state transitions | `tests/security/test_security_regressions.py::TestInvalidStateTransitionRegression` + all 4 `tests/unit/test_state_machines.py` classes |

## Docker validation

`Dockerfile`/`docker-compose.yml` are validated by `docker compose config` (parses and resolves the full merged config — service graph, env interpolation, healthchecks) and by `tests/e2e/test_dockerized_stack.py`, which really runs `docker compose build` + `up` + polls `/health` + makes one real HTTP call against the containerized app + tears down. This test would skip itself (not silently — with a specific, logged reason) if it detected the known local TLS-interception failure signature described in "Known environment-specific limitations" below, but on this machine `docker build` now succeeds (the limitation was fixed — see that section), so both this test and a manual `docker compose build && docker compose up -d` were verified for real this session: both compose images build, `db`→`migrations`→`app` all report healthy, `/health`/`/ready`/`/docs`/`/openapi.json`/`/dashboard`/`/metrics` all respond correctly against the real container, and all 18 demo scenarios pass against it.

## E2E demo validation

`demo/scripts/run_demo.py` is a separate, standalone script (stdlib HTTP only, no pytest) covering all 18 spec-required synthetic scenarios against a live running instance:

| # | Scenario | Proves |
|---|---|---|
| 1–2 | Fully compliant AWS / GCP system | Zero findings on an all-compliant resource, for both cloud providers |
| 3 | Publicly exposed database | `POL-NET-001` fires at CRITICAL |
| 4 | Wildcard IAM permissions | `POL-IAM-002` fires |
| 5 | Encryption disabled | `POL-ENC-003` fires |
| 6 | Audit logging removed | `POL-LOG-004` fires |
| 7 | Monitoring disabled | `POL-MON-005` fires |
| 8 | Unapproved resource created | `POL-ARC-009` fires on a resource with no matching desired-state entry |
| 9 | Unauthorized region | `POL-REG-010` fires against the baseline's `allowed_regions` |
| 10 | Missing ownership metadata | `POL-OWN-011` fires |
| 11 | Approved temporary exception | Full request → review → approve flow, `status=active` |
| 12 | Expired exception causing a new violation | Exception swept to `expired`; re-evaluation raises a fresh, unsuppressed finding |
| 13 | Self-approval attempt rejected | Requester deciding their own exception gets HTTP 403 |
| 14 | AI explanation failing a gate and falling back safely | Live call passes all 5 gates (deterministic mock is safe by design); a deliberately unsafe advisory fed directly through the real `AssuranceGateRunner` triggers `SafetyGate=FAILED` and a `deterministic-fallback` response |
| 15 | Kill switch blocking new evaluation | `PAUSED` blocks evaluation (503) while `/health` stays up |
| 16 | Repeated high-severity violation escalating the decision | 4 repeated evaluations of the same HIGH-severity, CRITICAL-criticality, PRODUCTION resource escalate the decision to `GOVERNANCE_BLOCK` |
| 17 | Audit-chain verification | `/api/v1/audit/verify` reports valid across every event the run produced |
| 18 | Cross-cloud normalization | An AWS finding and a GCP finding for the same policy use the identical response shape |

First verified 3 times against a real, disposable `postgres:16` container + `uvicorn src.main:app` (the non-Docker-equivalent execution path, back when `docker build` was still blocked on this machine — see "Known environment-specific limitations" below): the first run caught a bug in the demo script itself (scenario 16 needs `resource_criticality=CRITICAL`, not the builder's default `STANDARD`), the second confirmed the script's bootstrap is idempotent against a stack that already has prior demo data, and a third against a **completely fresh, just-migrated** database passed all 18 on the first attempt. After the Docker limitation was fixed, re-verified a 4th time against the **real, live Docker Compose stack** (`docker compose up -d` from a clean state) — 18/18 passed there too, with no non-Docker substitute needed. `--base-url` defaults to `http://localhost:8000`.

## Terraform validation

`terraform fmt -check -recursive` and `terraform init -backend=false` pass cleanly for both `infrastructure/aws/` and `infrastructure/gcp/` — real provider plugins are downloaded from the public registry, no credentials required or used. `terraform validate` could not complete on this development machine (see below); it is expected to pass unmodified on a machine or CI runner without the same local TLS-interception software, and is one of the three jobs in `.github/workflows/ci.yml`.

## CI behavior

Three jobs in one workflow (`.github/workflows/ci.yml`):

| Job | Steps |
|---|---|
| `lint-and-typecheck` | `ruff check .` (whole repo) + `mypy src` |
| `test` | A `postgres:16` service container (health-checked), `alembic upgrade head`, `pytest -v` |
| `docker-build` | `docker build .` + `docker compose config` |
| `terraform` | Matrix over `aws`/`gcp`: `fmt -check -recursive`, `init -backend=false`, `validate` |

The `test` job's exact sequence (fresh service container → migrate → full suite) was verified locally against a just-created, never-migrated `postgres:16` container before being trusted, producing the identical 293 passed / 0 skipped result. The `docker-build` job's own steps (`docker build .` + `docker compose config`) were also independently verified locally, for real, this session — see "Known environment-specific limitations" below.

## Negative-path and fail-closed testing

Every layer includes negative paths, not only success cases: invalid state transitions (409, not a silent no-op), unauthorized role/self-approval attempts (403), missing/oversized/malformed payloads (401/413/422), an unreadable kill-switch state treated as blocking rather than `NORMAL`, a policy with no registered evaluator failing closed rather than passing, a failed AI gate forcing `GOVERNANCE_BLOCK` rather than silently hiding the explanation. See `docs/SECURITY.md`'s "Fail-closed behavior" section for the consolidated list.

## Known environment-specific limitations

This development machine runs Norton AV with an HTTPS-scanning proxy that intercepts outbound TLS. Two checks were originally affected, both root-caused (not assumed) and documented in detail in `docs/ENVIRONMENT_LIMITATIONS.md`:

- `docker build` originally failed inside the Docker Desktop build VM at `pip install` with a TLS certificate-verification error — reproduced identically with a bare, unrelated `curlimages/curl` container, isolating the cause to the VM's network layer, not this project's `Dockerfile`. **Fixed**: the `Dockerfile` now trusts an extra CA certificate dropped in `certs/` (gitignored, machine-specific, a no-op on a normal network) before installing dependencies, the same pattern the sibling ChangeGuard AI MultiCloud repository already uses for this exact situation. This adds a trusted root, it does not disable or weaken certificate verification. Verified end-to-end: `docker build`, `docker compose build`, `docker compose up -d` from a clean state, all 18 demo scenarios against the real container, and `tests/e2e/test_dockerized_stack.py` all pass for real now — no skip.
- `terraform validate`'s *internal* loopback mTLS handshake between the Terraform core process and its downloaded provider plugin subprocess still fails — while a real internet HTTPS call (`terraform init`, or a plain `curl` to the Terraform registry) succeeds from the same shell. **Not fixed**: this is a different mechanism from the Docker case (a per-invocation generated certificate pair over localhost, not validated against the system CA bundle at all), so trusting an extra root certificate has no effect here — see `docs/ENVIRONMENT_LIMITATIONS.md` for the full explanation of why the same fix doesn't apply.

Every check verified directly on this machine now passes: the full 293-test Postgres-backed suite (0 skips), ruff, mypy, `terraform fmt`/`init -backend=false`, the live-app demo run against a real Docker Compose stack, and the Dockerized e2e pytest. Only `terraform validate` remains blocked, for the distinct, documented reason above.
