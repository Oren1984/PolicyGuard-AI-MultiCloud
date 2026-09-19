# Tradeoffs and Production Roadmap

## Explicit scope boundaries (by design, not by omission)

This is a proof of concept demonstrating a governance architecture, not a production platform. Deliberately excluded:

- Autonomous cloud remediation — nothing here ever mutates a real cloud resource.
- Real production deployment, real enterprise authentication, real AWS/GCP access — every cloud interaction is a deterministic mock; Terraform is validated, never applied.
- Billing, multi-tenancy, Kubernetes, event-streaming infrastructure, full regulatory certification.
- Complex frontend development, mobile applications, chatbot-first interaction — the dashboard is a read-only, server-rendered page, not a client-side app.
- Production SLA claims.
- Automatic pull-request creation or automatic infrastructure modification.

## Engineering trade-offs made in this implementation

| Trade-off | Why | Production alternative |
|---|---|---|
| No foreign keys in the schema; resources cross-referenced by application-level id, value objects stored as JSONB | Keeps the migration/mapping layer small for a 12-table POC schema | Normalize hot-path relationships (finding→policy, exception→finding) into real foreign keys once query patterns stabilize |
| Header-based actor identity | No IdP integration needed to demonstrate the governance rules themselves | OIDC/OAuth2 + enterprise IdP + signed, verifiable tokens |
| In-database SHA-256 hash chain (tamper-*evident*, not tamper-*proof*) | Detects mutation/deletion without external infrastructure | External WORM storage or ledger anchoring so even privileged database access can't rewrite history undetectably |
| Synchronous, single-process evaluation | Simpler to reason about and test for a POC's evaluation volume | Async worker/queue (Celery/RQ/Cloud Tasks) so a large evaluation run doesn't block request handling |
| `expire-sweep` is an API call, not a scheduled job | No scheduler infrastructure needed to demonstrate the expiry mechanism | Cron / Cloud Scheduler / EventBridge calling the same endpoint on an interval |
| Deterministic mock AI provider only, real provider adapter shipped but disabled | Zero network dependency or API key needed to run or test this project | Enable `ExternalAIProvider` against a real provider once its output has been validated against the same 5 gates in a staging environment |
| `MockAWSInventoryProvider`/`MockGCPInventoryProvider` (deterministic synthetic data) | No cloud credentials needed to run or test this project | Real AWS/GCP SDK-backed collectors implementing the same `CloudInventoryProvider` port — the policy engine and drift detector need no changes |
| Public Cloud Run invocation allowed by default (GCP reference architecture) | Convenience for a POC demo | Set `allow_unauthenticated=false` and front Cloud Run with IAP or a load balancer |
| No rate limiting | Out of scope for demonstrating the governance model | An API gateway or reverse-proxy layer |

## Production-hardening roadmap

**Identity and access**
OIDC/OAuth2 against a real enterprise IdP · signed, short-lived tokens instead of trust-on-header · per-endpoint scopes beyond the current 5 coarse roles.

**Auditability**
External WORM storage or a ledger-anchoring service for the hash chain · periodic automated `verify_chain()` runs with alerting, not only on-demand calls.

**Scale and reliability**
Async evaluation worker/queue · horizontal scaling of the API behind a load balancer · multi-AZ RDS / regional Cloud SQL with automated failover · read replicas for the dashboard/reporting paths.

**Real cloud integration**
Replace the two mock inventory providers with real AWS/GCP SDK-backed collectors (scheduled, incremental) implementing the same `CloudInventoryProvider` port — no change needed in `domain/`, `application/`, or the API layer.

**Operational maturity**
Scheduled exception-expiry sweeps · alerting on `policyguard_audit_chain_valid`, `policyguard_gate_failures_total`, and `policyguard_db_ready` · centralized log aggregation (the JSON logs are already structured and correlation-tagged, ready to ship to one) · automated backup/restore runbooks for the database, with an explicit procedure for restoring a hash-chain-consistent snapshot.

**Networking**
Private networking end-to-end for both reference architectures (already private-database-only; extend to private application ingress via VPN/PrivateLink/Private Service Connect) · disable public Cloud Run invocation by default.

**AI provider maturity**
Validate a real external AI provider against the same 5 assurance gates in a staging environment before enabling it in production · per-provider gate-failure-rate monitoring to catch a degrading model before it affects governance throughput.

None of the above is implemented in this repository — this section documents the realistic evolution path without pretending it is already built, per this project's own engineering-quality rule: never describe unimplemented functionality as completed.
