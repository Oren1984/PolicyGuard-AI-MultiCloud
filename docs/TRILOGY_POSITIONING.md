# Trilogy Positioning

PolicyGuard AI MultiCloud is the third and final member of a three-part Enterprise AI Governance architecture. All three systems share a governance philosophy while owning strictly separate business responsibilities and lifecycle stages.

## The three systems

| | Lifecycle stage | Primary question |
|---|---|---|
| **ChangeGuard AI MultiCloud** | Before a proposed production change | Is this change safe and governed enough to proceed? |
| **ArchGuard AI** | During a runtime incident or architectural impact event | What is affected, what is the impact, and what requires human attention? |
| **PolicyGuard AI MultiCloud** (this repository) | Continuously, after deployment | Does the current environment still comply with its approved state and policies? |

```
  PRE-DEPLOYMENT                RUNTIME                    POST-DEPLOYMENT (continuous)
 ┌────────────────┐      ┌────────────────────┐      ┌──────────────────────────┐
 │   ChangeGuard    │ ──▶ │     ArchGuard        │ ──▶ │       PolicyGuard          │
 │   AI MultiCloud  │      │     AI                │      │       AI MultiCloud       │
 │  "Is this change │      │  "What's affected,     │      │  "Is everything still     │
 │  safe enough to   │      │  and who needs to       │      │  compliant, or has it      │
 │  ship?"           │      │  respond?"              │      │  drifted / expired?"      │
 └────────────────┘      └────────────────────┘      └──────────────────────────┘
```

## How the three complement one another

A change ChangeGuard `AUTO_CLEAR`s or CAB-approves becomes the thing that is actually running. If that live system later suffers an incident, ArchGuard is the system that analyzes what's affected and coordinates response — not PolicyGuard, which has no incident-response concept anywhere in its domain model. If that same live system's *configuration* quietly drifts away from what was approved — a security group loosened, a tag removed, an exception expiring — long after any incident, PolicyGuard is the system that notices, on a continuous, repeatable basis, independent of whether an incident ever occurs. None of the three duplicates another's job: ChangeGuard never continuously monitors already-deployed infrastructure, ArchGuard never evaluates a change before it exists, and PolicyGuard never responds to a live incident or gates a pending change.

## Where lifecycle responsibilities begin and end

- **ChangeGuard's** responsibility ends the moment a change is cleared or blocked — it has no ongoing relationship with the system after that point.
- **ArchGuard's** responsibility is scoped to the duration of a specific incident or impact event — it does not run continuously against a healthy system.
- **PolicyGuard's** responsibility begins where ChangeGuard's ends (once something is deployed) and continues indefinitely, independent of whether an incident ever happens — it is the only one of the three with no natural "done" state; it re-evaluates on every run for as long as the system it governs exists.

## Architectural controls that are intentionally shared

| Control | How PolicyGuard implements it |
|---|---|
| Deterministic governance core | 20-policy engine + drift detector + pure decision router — no AI in the evaluation or routing path |
| Advisory AI isolated from final decisions | `GovernanceDecisionContext` has no field that can carry AI output — a type-system guarantee, not a policy |
| Five AI assurance gates | Schema, grounding, confidence, safety, consistency — identical *pattern* to the sibling projects' gate pipelines, PolicyGuard-specific *content* (policy/drift grounding context, not change-risk context) |
| Human-in-the-loop control | Exception approval, kill-switch changes, policy activation all require a human role, never an automated action |
| Separation of duties | A requester can never approve their own exception, regardless of role |
| Kill switch | `NORMAL`/`PAUSED`/`EMERGENCY_STOP`, fails closed on an unreadable state |
| Fail-closed behavior | Repeated throughout — see `docs/SECURITY.md`'s consolidated list |
| PostgreSQL persistence | Real Postgres only, no SQLite anywhere, in the app or the test suite |
| Hash-chained auditability | SHA-256 chain, tamper-evident, independently verifiable |
| Structured monitoring and observability | JSON logs, correlation IDs, Prometheus metrics, health/readiness endpoints |
| Docker-first execution | Multi-stage `Dockerfile`, non-root user, Compose with health-checked service ordering |
| Multi-cloud abstraction | A provider-independent `ResourceType`/`CloudProvider` boundary; no cloud-specific logic outside the adapter layer |
| AWS and GCP reference architectures | Both validated (`fmt`/`init`), neither ever applied |
| Security testing | Dedicated regression suite for the 8 spec-mandated security scenarios |
| Full E2E validation | A continuous full-lifecycle test plus a live Dockerized compose-up-to-real-call test |
| Honest POC boundaries | Every limitation in this document set is stated plainly, not hidden |

## Why shared controls represent consistency, not duplication

An engineer who understands PolicyGuard's assurance-gate pipeline, audit-chain design, or kill-switch semantics already understands the *shape* of the equivalent mechanism in ChangeGuard or ArchGuard — that consistency is deliberate and valuable across a governance portfolio, the same way a company standardizes on one incident-severity taxonomy across every team rather than reinventing it per system. What's shared is architectural pattern and philosophy — never a shared database, a shared decision authority, or overlapping business logic. Each system's audit trail, domain model, and decision output are entirely its own.

## How information could flow conceptually between the systems

No code in any of the three repositories calls another one directly — they are independently deployable and independently runnable. Conceptually, in a full deployment of the trilogy:

- A **ChangeGuard** decision to `AUTO_CLEAR` or CAB-approve a change could seed PolicyGuard's *desired state* for the resources that change touches — the "approved baseline" PolicyGuard's drift detector compares against is naturally the last thing ChangeGuard cleared.
- An **ArchGuard** incident whose root cause was a policy violation could reference the specific PolicyGuard finding/decision id that predicted or explains it, closing the loop from "this was already flagged as non-compliant" to "and here's the incident it caused."
- A **PolicyGuard** finding severe enough to represent an emerging incident (e.g. a CRITICAL public-exposure drift on a production system) could hand off to ArchGuard as an impact-analysis trigger.

None of this integration exists in this repository — it is a conceptual data-flow description, not an implemented dependency, consistent with each project remaining independently runnable.

## Why the projects remain independent POCs, not one platform

Merging the three into a single system would couple three different data models (a proposed change, a live incident, a continuously-evaluated deployed state), three different timing models (event-triggered, incident-triggered, continuous), and three different audit domains into one codebase that is worse at all three jobs than three focused systems are at their own — the same argument against a monolith that does everything a company's engineering org needs. Keeping them separate also means each one's fail-closed, human-in-the-loop guarantees are independently verifiable and independently deployable; a bug or outage in one does not take down governance for the other two.

## What the trilogy demonstrates together

Across all three: architecture (Clean Architecture, provider-independent domain layers), governance (deterministic decision engines that AI cannot override), security (fail-closed behavior, separation of duties, strict schema validation, redaction), assurance (a consistent five-gate pattern validating every AI output before it can be trusted), observability (structured logs, correlation IDs, Prometheus metrics, health/readiness), and human accountability (every consequential decision traceable to a specific human actor, never anonymous, never automated). PolicyGuard is the proof that this same governance architecture generalizes past a single lifecycle stage — pre-deployment, runtime, and continuous post-deployment can all be governed by the same underlying principles without collapsing into one another.
