# Operations and Observability

## Structured logs and correlation IDs

`src/observability/logging.py::configure_logging()` installs a single JSON-formatted stream handler (`python-json-logger`) at app startup. Every log record is stamped with the request's correlation id and passed through the same `redact_value` scrubber used on audit payloads and error responses — a log line can never leak a Bearer token, AWS access key, or connection-string password that a message happened to include.

`src/observability/correlation.py`: a per-request `ContextVar` seeded from the inbound `X-Correlation-ID` header (or a fresh UUID4 if absent) by `src/main.py`'s HTTP middleware, echoed back on the response, and threaded into every audit event this request produces (`AuditEventRepository.append(..., correlation_id=...)`). Following one `correlation_id` through `GET /api/v1/audit/events` reconstructs the exact chain of actions a single API call triggered.

## Metrics

`GET /metrics` exposes a private Prometheus `CollectorRegistry` (not the global default — repeated app-factory calls in tests don't collide):

| Metric | Type | Labels | What it tracks |
|---|---|---|---|
| `policyguard_evaluations_total` | Counter | `evaluation_type` (`policy_pack`\|`drift`) | Deterministic evaluations run |
| `policyguard_evaluation_duration_seconds` | Histogram | `evaluation_type` | Evaluation duration |
| `policyguard_findings_total` | Counter | `severity`, `provider`, `kind` (`compliance`\|`drift`) | Findings recorded, by severity/provider/category |
| `policyguard_decisions_total` | Counter | `decision` | Governance decisions issued |
| `policyguard_gate_failures_total` | Counter | `gate` | AI assurance gate failures |
| `policyguard_exception_events_total` | Counter | `event` (`requested`\|`under_review`\|`approved`\|`rejected`\|`revoked`\|`expired`) | Exception lifecycle events |
| `policyguard_audit_chain_valid` | Gauge | — | 1 if the audit chain was last verified valid, 0 if invalid |
| `policyguard_db_ready` | Gauge | — | 1 if the last `/ready` check reached the database, 0 otherwise |
| `policyguard_http_errors_total` | Counter | `status_code` | Unhandled/mapped error responses |

An optional `prometheus` service (Compose `profiles: [monitoring]`, off by default) scrapes `/metrics` on a 15s interval — enable with `docker compose --profile monitoring up`. `/metrics` itself works without Prometheus running at all; it's directly `curl`-able.

## Health and readiness

- `GET /health` — pure liveness, no database dependency. Used as the container `HEALTHCHECK` and by `demo/scripts/run_demo.py`'s startup poll.
- `GET /ready` — executes `SELECT 1` against the real database and sets `policyguard_db_ready` accordingly; fails (and the gauge drops to 0) if the database is unreachable.
- `GET /api/v1/admin/status` — aggregate: environment, AI provider, kill-switch mode, audit-chain validity, managed-system count, finding/exception counts by status.

## Audit-chain verification status

`GET /api/v1/audit/verify` recomputes the entire hash chain and returns `is_valid`, `total_records`, and (on failure) the `first_invalid_sequence` and a human-readable `reason`. Both this endpoint and `GET /api/v1/admin/status` set the `policyguard_audit_chain_valid` gauge as a side effect, so a monitoring system can alert on chain invalidity without polling the verify endpoint directly, as long as something calls one of the two periodically.

## Operational troubleshooting

| Symptom | Where to look |
|---|---|
| A route returns 503 | Check `GET /api/v1/admin/kill-switch` — `PAUSED` blocks evaluations/exception review; `EMERGENCY_STOP` blocks all mutations. Health/audit/read endpoints stay up in both. |
| A route returns 409 | An invalid state transition was attempted — the response `detail` names the entity and both states; cross-reference `src/domain/state_machine/*.py`'s allow-lists. |
| `GET /api/v1/audit/verify` reports invalid | `first_invalid_sequence` + `reason` pinpoint the exact record and failure mode (sequence gap, broken hash link, or a tampered payload); direct database inspection of `audit_events` at that `sequence` is the next step. |
| `/ready` returns non-200 | Database is unreachable — check `POLICYGUARD_DATABASE_URL` and that migrations have actually run (`alembic current` should show `e62918b59be8 (head)`). |
| A request returns 401 | Missing or invalid `X-PolicyGuard-Actor`/`X-PolicyGuard-Role` headers. |
| Correlating a user report to server-side behavior | Ask for the `X-Correlation-ID` response header from their call, grep the JSON logs for it, or query `GET /api/v1/audit/events?resource_type=...&resource_id=...`. |

## What would be added for production alerting

- Alert on `policyguard_audit_chain_valid == 0` (immediate, high-severity — indicates tampering or corruption).
- Alert on a sustained rise in `policyguard_gate_failures_total` (indicates a misbehaving or degraded AI provider).
- Alert on `policyguard_db_ready == 0` for more than a short grace period.
- Alert on kill-switch mode changes (`policyguard_exception_events_total`-style event metric doesn't yet exist for kill-switch changes — would be added alongside real alerting integration).
- Dashboards/log aggregation (Grafana + the Prometheus scrape already wired, or an ELK/Loki stack) — this repository ships the metrics endpoint and an optional Prometheus service, not a hosted dashboard.

---

## Local Docker execution

```bash
cp .env.example .env
docker compose build
docker compose up -d
docker compose ps
docker compose logs -f app
docker compose down          # add -v to also drop the database volume
```

Service graph: `db` (`postgres:16`, health-checked via `pg_isready`) → `migrations` (one-shot, `alembic upgrade head`, waits for `db` healthy) → `app` (waits for `db` healthy **and** `migrations` completed successfully, own `/health`-based container healthcheck). This ordering guarantees the app's startup kill-switch seeding always finds its tables already in place on a fresh volume.

If `docker build` fails with a TLS/certificate-verification error, an HTTPS-intercepting proxy (corporate network or antivirus) is almost always the cause, not this project's `Dockerfile` — drop the intercepting proxy's root certificate into `certs/` (gitignored; the directory is a no-op when empty) and rebuild; see `docs/ENVIRONMENT_LIMITATIONS.md` for the exact mechanism and why this doesn't weaken TLS verification. The app's own compose port can be overridden with `POLICYGUARD_HOST_PORT` (default `8000`) if that port is already in use.

## Direct Python execution (troubleshooting / when Docker is unavailable)

```bash
docker run -d --name pg-tmp -e POSTGRES_USER=policyguard -e POSTGRES_PASSWORD=policyguard \
  -e POSTGRES_DB=policyguard -p 5432:5432 postgres:16

python -m venv .venv && source .venv/Scripts/activate   # or .venv/bin/activate on Linux/macOS
pip install -e ".[dev]"

export POLICYGUARD_DATABASE_URL=postgresql+psycopg://policyguard:policyguard@localhost:5432/policyguard
alembic upgrade head
uvicorn src.main:app --reload
```

This is a generally useful path for troubleshooting or environments without Docker at all — only the official `postgres:16` image is pulled, no image containing this project's own code is built. It was also this project's own substitute path earlier in validation, back when `docker build` was locally blocked on this development machine by a TLS-interception issue that has since been fixed (see `docs/ENVIRONMENT_LIMITATIONS.md`) — `docker compose up` now works directly on this machine too.

## Database migrations

Alembic, one real migration (`migrations/versions/e62918b59be8_initial_schema.py`) creating all 12 tables + their indexes/unique constraints. `migrations/env.py` resolves the database URL with precedence `POLICYGUARD_DATABASE_URL` → plain `DATABASE_URL` → the persistence adapter's own hardcoded local default, so Alembic (a separate process from the running app) honors the same variable the app itself uses.

```bash
alembic upgrade head     # apply
alembic downgrade base   # tear back down to empty (verified round-trip-safe)
alembic current           # confirm the applied revision
```

## Configuration

All settings are read once through `src/config.py::Settings` (pydantic-settings, env prefix `POLICYGUARD_`, `lru_cache`d — the environment is captured at first read).

| Variable | Default | Purpose |
|---|---|---|
| `POLICYGUARD_ENVIRONMENT` | `local` | Free-text environment label, surfaced in `/api/v1/admin/status` |
| `POLICYGUARD_LOG_LEVEL` | `INFO` | Root logger level |
| `POLICYGUARD_DATABASE_URL` | `postgresql+psycopg://policyguard:policyguard@localhost:5432/policyguard` | The one database URL the running app and Alembic both honor |
| `POLICYGUARD_AI_PROVIDER` | `mock` | `mock` (default, offline, deterministic) or `external` |
| `POLICYGUARD_AI_EXTERNAL_BASE_URL` / `POLICYGUARD_AI_EXTERNAL_API_KEY` | unset | Only read when `AI_PROVIDER=external` |
| `POLICYGUARD_CONFIDENCE_APPROVAL_THRESHOLD` | `0.70` | Confidence-gate approval threshold |
| `POLICYGUARD_CONFIDENCE_HARD_FLOOR` | `0.35` | Confidence-gate hard failure floor |
| `POLICYGUARD_KILL_SWITCH_DEFAULT_MODE` | `normal` | Seeded once, only if no kill-switch row exists yet |
| `POLICYGUARD_MAX_PAYLOAD_BYTES` | `1000000` | Inbound request body size limit (413 beyond this) |
| `POLICYGUARD_CORS_ALLOW_ORIGINS` | `[]` | CORS allow-list |
| `POLICYGUARD_DEMO_MODE` | `false` | Shows the dashboard's "DEMO / MOCK DATA" banner; also the safety gate `demo/scripts/{seed,reset}_demo_data.py` both require — see "Demo / mock dataset" below |

Full list with inline comments in `.env.example` (committed, contains no real secrets — every value is a local-only default).

## Safe startup and shutdown

Startup: the app's lifespan hook seeds the kill-switch's single row (fail-open *only* on the seeding attempt itself — if the database isn't reachable yet at boot, the app still starts, and every kill-switch-gated route then fails closed per-request via `KillSwitchStateUnavailableError` → 503, rather than the whole process refusing to boot). Shutdown: `docker compose down` stops containers cleanly; the named volume `policyguard_db_data` persists across restarts unless `-v` is passed.

## Backup and recovery considerations

This POC has no automated backup mechanism — the Postgres data lives in a Docker named volume (or a real managed database in the Terraform reference architectures: RDS/Cloud SQL, both with encryption at rest configured). A production deployment needs: scheduled `pg_dump`/managed-snapshot backups, a tested restore runbook, and — given the audit chain's hash-linking — a restore procedure that either restores the *entire* chain from one consistent backup point or accepts that `verify_chain()` will (correctly) flag a partial restore as invalid at the first missing/inconsistent record.

## Audit verification (operational)

Run `GET /api/v1/audit/verify` (or `POST /api/v1/admin/status`, which does the same check as a side effect) on a schedule, or triggered by a suspected-tampering event. A `false` result's `first_invalid_sequence` is the starting point for incident investigation — every record before it is provably untouched.

## Kill-switch operation

```bash
curl -X POST http://localhost:8000/api/v1/admin/kill-switch \
  -H "X-PolicyGuard-Actor: ops.oncall" -H "X-PolicyGuard-Role: platform_admin" \
  -H "Content-Type: application/json" \
  -d '{"mode": "emergency_stop", "reason": "investigating unexpected findings volume"}'
```

`NORMAL` — full operation. `PAUSED` — blocks new evaluations and exception-review/decide actions; existing data stays fully readable. `EMERGENCY_STOP` — blocks every mutating action; health, audit verification, and all read/list endpoints remain available. Recovery is the same endpoint with `mode: normal`, restricted to `platform_admin`.

## Demo / mock dataset

`demo/scripts/seed_demo_data.py` populates the dashboard with 8 realistic, permanently-marked synthetic managed systems so it's browsable/demonstrable instead of empty on a fresh instance. It talks to the real, running API (the same one any other client uses) — no direct database writes, no bypass of policy evaluation, the decision router, assurance gates, or the audit trail.

**Enable:**

```bash
export POLICYGUARD_DEMO_MODE=true   # required by both scripts below; the dashboard banner reads the
                                     # same variable from the *running app's* own environment
```

**Seed** (idempotent — re-running skips any system id that already exists, never creates duplicates):

```bash
docker compose exec app env POLICYGUARD_DEMO_MODE=true python demo/scripts/seed_demo_data.py
# or, against a non-Docker instance:
POLICYGUARD_DEMO_MODE=true python demo/scripts/seed_demo_data.py --base-url http://localhost:8000
```

**Reset** (deletes only what seeding created; connects directly to Postgres since there is no delete endpoint anywhere in this API by design):

```bash
docker compose exec app env POLICYGUARD_DEMO_MODE=true python demo/scripts/reset_demo_data.py
# or:
POLICYGUARD_DEMO_MODE=true python demo/scripts/reset_demo_data.py --database-url "$POLICYGUARD_DATABASE_URL"
# preview without deleting anything:
POLICYGUARD_DEMO_MODE=true python demo/scripts/reset_demo_data.py --dry-run
```

**Identification and scope:** every seeded managed system id uses the reserved `demo-` prefix (e.g. `demo-aws-checkout-api`, `demo-gcp-billing-service`) and carries `tags={"source": "demo", "is_demo": "true"}`. Reset deletes rows in `managed_systems`, `desired_state_snapshots`, `observed_state_snapshots`, `compliance_findings`, `drift_findings`, `governance_decisions`, `policy_exceptions`, and `remediation_plans` scoped to exactly those ids — nothing else. A real managed system must never be named with a `demo-` prefix; this is a reserved namespace.

**What reset deliberately never touches, and why:**
- `audit_events` — the hash chain is append-only and tamper-evident (`docs/SECURITY.md`); deleting rows out of the middle of it would create a sequence gap that `verify_chain()` correctly reports as tampering. The audit trail seeding produced is real, correctly hash-chained evidence of real actions taken through the real API, and stays permanently, exactly as the system's own audit-integrity guarantee intends.
- `policies` / `policy_packs` — the real 20 policy definitions are shared infrastructure the seed script ensures exist (idempotently, by id, same as everything else); they are not themselves demo data.
- The kill switch — seeding and reset never read or change kill-switch state.

**Safety, both scripts:** refuse to run unless `POLICYGUARD_DEMO_MODE=true` is set in the script's own environment (bypass with `--force`, intended only for deliberate manual use); `seed_demo_data.py` additionally queries the target server's `/api/v1/admin/status` and refuses if it reports `environment=production`. Neither script ever runs on its own — nothing in the application calls them; they are only ever invoked explicitly.

**Verification:** `tests/demo/test_demo_seed.py` (16 tests) covers idempotency (re-seeding creates zero duplicate rows), the demo-tag marking, the severity/decision/provider spread, dashboard rendering (including the banner's on/off states), and reset's scope (removes exactly the demo rows, never `audit_events`/policies, and the audit chain still verifies afterward).

## Production-readiness gaps

Synchronous single-process evaluation (no worker/queue) · header-based identity (no real auth) · in-database hash chain (no external ledger anchoring) · manually-triggered exception expiry sweep (no scheduler) · no rate limiting · Terraform reference architectures validated but never applied, so no real network/IAM hardening has been exercised against a live cloud account. Full roadmap in `docs/TRADEOFFS_AND_PRODUCTION_ROADMAP.md`.
