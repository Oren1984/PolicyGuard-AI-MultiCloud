# Security

## POC identity boundary

Actor identity is resolved entirely from two request headers, `X-PolicyGuard-Actor` and `X-PolicyGuard-Role`, parsed directly into the domain's own `Actor` entity by `src/security/actor_context.py::parse_actor_context()`. An invalid role value is rejected with HTTP 401; missing headers are rejected with HTTP 401. This is a **documented POC boundary, not authentication** — anyone who can reach the API can claim any actor id and any valid role. It exists so every governance rule (separation of duties, kill-switch authorization, policy-admin checks, audit attribution) has a real identity to enforce against and test, without building a full IdP integration for a proof of concept. Production hardening (OIDC/OAuth2, signed tokens, an enterprise IdP) is documented in `docs/TRADEOFFS_AND_PRODUCTION_ROADMAP.md`.

## Role-based authorization

Five roles (`system_owner`, `security_reviewer`, `compliance_approver`, `platform_admin`, `auditor`) gate specific mutating actions — see `docs/AI_ASSURANCE_AND_GOVERNANCE.md`'s governance-roles table for the full matrix. Authorization checks live in domain-layer pure functions (`src/domain/policies/separation_of_duties.py`, `src/domain/enums/actor_role.py`'s role-set constants) called from the application layer, not scattered ad hoc across route handlers.

## Separation of duties

A requester can never approve, review, reject, or revoke their own policy exception, checked against the authenticated actor id independent of role. Full detail and the live demonstration in `docs/EXCEPTION_WORKFLOW.md`.

## Spoofed-identity prevention

Any client-supplied identity field in a request body (`requested_by` on an exception request) is compared against the authenticated actor and rejected on mismatch — it can influence nothing on its own. `owner_actor_id` on a managed-system registration defaults to the authenticated actor when the client sends `null`, never silently trusting a client-supplied value as the system of record. Regression-tested in `tests/security/test_security_regressions.py::TestSpoofedIdentityRegression`.

## Strict schema validation

Every request schema in `src/api/schemas/` sets `model_config = ConfigDict(extra="forbid")` — an unrecognized field in a request body is a 422, not a silently-ignored typo or a smuggled field. Path/enum/string-length constraints are enforced by Pydantic (e.g. `system_id` must match `^[A-Za-z0-9_.\-]+$`, severities and roles are closed literal sets). `tests/security/test_security_regressions.py::TestGeneralAPIHardening` proves unknown fields, an invalid role header, and missing actor headers are all rejected.

## Payload limits

`src/main.py`'s HTTP middleware rejects any request whose `Content-Length` exceeds `POLICYGUARD_MAX_PAYLOAD_BYTES` (default 1,000,000) with HTTP 413, checked before the body is ever parsed. List fields throughout the schemas (`resources`, `tags`, `evidence`, `compensating_controls`) carry their own `max_length` bounds independent of the raw byte limit.

## Secret and sensitive-data redaction

`src/adapters/security/redaction.py` provides `redact_value` (scrubs Bearer tokens, AWS access-key-id patterns, and the password portion of a connection string out of free text) and `redact_mapping` (recursively redacts any dict value whose key matches a sensitive-name pattern — `password`, `secret`, `token`, `api_key`, `authorization`, `credential`, `private_key`, `connection_string` — case-insensitively, plus scrubbing remaining string values through `redact_value`). Every audit payload passes through `redact_mapping` before it is canonicalized, hashed, and persisted (`SqlAlchemyAuditEventRepository.append`). Every unhandled exception's message is passed through `redact_value` before being returned to a client, so even an error message cannot leak a connection string or token. Regression-tested: `tests/security/test_security_regressions.py::TestGeneralAPIHardening::test_secrets_in_exception_payload_are_never_returned_verbatim_in_audit`.

## Non-root container execution

The `Dockerfile`'s runtime stage creates a dedicated `policyguard` system user/group (`useradd --system ... --shell /usr/sbin/nologin`), `chown`s `/app` to it, and switches to it with `USER policyguard` before the container ever runs application code. The build stage (compilers, `libpq-dev`) is discarded entirely in the final image via Docker's multi-stage build — only the installed Python packages and application source are copied forward.

## Parameterized database access

All database access goes through SQLAlchemy's ORM/Core query builder — no raw string-interpolated SQL anywhere in `src/adapters/persistence/`. `tests/security/test_security_regressions.py::test_sql_injection_like_string_is_stored_as_inert_data` submits a string containing `'; DROP TABLE managed_systems; --` as ordinary field data and confirms it is stored and read back verbatim (inert data, not executed), and that the table survives. The same pattern is verified for XSS-shaped strings (`<script>...</script>` is stored and returned as inert text — there is no server-side HTML rendering of user-supplied fields to execute it against).

## Fail-closed behavior

Fail-closed is a repeated, tested design principle rather than one mechanism:

- An unreadable kill-switch state is never interpreted as `NORMAL` — `KillSwitchStateUnavailableError` maps to HTTP 503, and `blocks_all_mutations`/`blocks_new_evaluations` only ever return `True` on failure to resolve, never `False` (see `tests/security/test_security_regressions.py::test_kill_switch_state_unavailable_is_never_silently_treated_as_normal`).
- A policy registered with no matching code-defined `evaluate` function always reports a violation (`_fail_closed_evaluate`), never a silent pass.
- Incomplete evidence can never route a finding lighter than `REMEDIATION_REQUIRED`, regardless of severity.
- A failed AI assurance gate forces `GOVERNANCE_BLOCK`, not "just skip the explanation."
- Any state transition not on an explicit allow-list (finding, exception, remediation-plan, decision) raises `InvalidStateTransitionError` → HTTP 409, never silently succeeds.
- An unhandled exception anywhere in the API returns a generic 500 with no stack trace or internals, never a partial success.

## Prohibited autonomous actions

Nothing in this codebase calls a real AWS/GCP mutation API, executes a shell command derived from AI output, runs `eval`, or applies Terraform. The AI provider interface has no method capable of approving, closing, or remediating anything (see `docs/AI_ASSURANCE_AND_GOVERNANCE.md`). `infrastructure/{aws,gcp}/` is validated (`fmt`, `init -backend=false`) but `terraform apply`/`plan` against real credentials never runs, in this repository or in CI.

## Known limitations and production-hardening path

| Limitation | Production hardening |
|---|---|
| Header-based identity, not real authentication | OIDC/OAuth2 + enterprise IdP + signed, verifiable tokens |
| Audit chain is tamper-evident (detects mutation), not tamper-proof (doesn't prevent a privileged database user from rewriting the whole chain consistently) | External WORM storage or ledger anchoring for the hash chain |
| No rate limiting or request throttling | An API gateway / reverse proxy layer in front of the app |
| Synchronous, single-process evaluation | An async worker/queue so a large evaluation run doesn't block request handling |
| `expire-sweep` is manually triggered via API | A scheduled job (cron/Cloud Scheduler) calling it on an interval |
| Secrets (DB password) passed as plain environment variables in Compose/ECS/Cloud Run | AWS Secrets Manager / GCP Secret Manager references are already used in the Terraform reference architectures for the database credential; extend the same pattern to any future real credential |

Full detail in `docs/TRADEOFFS_AND_PRODUCTION_ROADMAP.md`.
