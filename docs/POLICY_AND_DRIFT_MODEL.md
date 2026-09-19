# Policy and Drift Model

## Severity and resource criticality

`PolicySeverity` is an ordered `IntEnum` (`INFO=0 < LOW=1 < MEDIUM=2 < HIGH=3 < CRITICAL=4`) so comparisons and escalation logic can use `>=`/`max()` directly. `ResourceCriticality` (`STANDARD=0 < IMPORTANT=1 < CRITICAL=2`) is a documented addition beyond the spec's mandatory enums, required as an explicit, typed input to the decision router.

## The 20 deterministic policy categories

`src/domain/policy_engine/definitions.py::build_default_policy_pack()` builds all 20 as `Policy` objects with stable IDs, each carrying its own pure `evaluate(ctx: PolicyEvaluationContext) -> PolicyCheckOutcome` callable — no shared "generic rule engine," each category is independently readable and independently unit-tested (`tests/unit/test_policy_engine.py` parametrizes every one of the 20 over a generic compliant resource, plus targeted violation tests).

| ID | Category | Severity | Checks |
|---|---|---|---|
| `POL-NET-001` | Public network exposure | CRITICAL | `attributes.publicly_accessible` |
| `POL-IAM-002` | Overly permissive IAM | HIGH | `attributes.iam_wildcard_action` or `iam_wildcard_resource` |
| `POL-ENC-003` | Unencrypted storage | HIGH | `attributes.encryption_at_rest_enabled` (storage/database resource types only) |
| `POL-LOG-004` | Missing logging | MEDIUM | `attributes.audit_logging_enabled` |
| `POL-MON-005` | Disabled monitoring | MEDIUM | `attributes.monitoring_enabled` |
| `POL-BAK-006` | Missing backup | MEDIUM | `attributes.backup_enabled` |
| `POL-SEC-007` | Unsafe secrets storage | CRITICAL | `attributes.secrets_in_plaintext_config` |
| `POL-ENV-008` | Prod using dev settings | HIGH | `attributes.dev_grade_setting_in_production` (production environment only) |
| `POL-ARC-009` | Unapproved baseline resource | MEDIUM | no matching desired-state resource, or `attributes.within_approved_baseline` is false |
| `POL-REG-010` | Unauthorized region | HIGH | `resource.region` not in the desired baseline's `allowed_regions` |
| `POL-OWN-011` | Missing ownership metadata | LOW | `attributes.owner_tag` absent |
| `POL-TAG-012` | Missing required tags | LOW | resource tags missing a baseline-required key |
| `POL-VER-013` | Unsupported runtime version | MEDIUM | `attributes.runtime_version_supported` |
| `POL-MTW-014` | Outside maintenance window | LOW | `attributes.modified_outside_maintenance_window` |
| `POL-PRI-015` | Privilege escalation | CRITICAL | `attributes.privilege_escalation_enabled` |
| `POL-CTL-016` | Security control removed | HIGH | `attributes.security_controls_removed_since_baseline` |
| `POL-RET-017` | Data retention violation | MEDIUM | `attributes.data_retention_compliant` |
| `POL-HAV-018` | Missing high availability | MEDIUM | `attributes.high_availability_configured` (critical resources) |
| `POL-BAS-019` | Architecture baseline drift | MEDIUM | `attributes.matches_architecture_baseline` |
| `POL-EXC-020` | Expired policy exception | HIGH | an exception covering this resource/policy has expired but the underlying violation persists |

Every policy declares `exception_eligible` (all 20 default `True` in the shipped pack — a deployment can register a custom, non-eligible policy) and `required_evidence` — the evidence keys a `GenerateGovernanceDecisionUseCase` call checks for completeness before a finding can be routed lighter than `REMEDIATION_REQUIRED`.

### Policy lifecycle

Policies and packs are versioned, persisted entities (`PolicyRepository`/`PolicyPackRepository`), separate from their executable `evaluate` logic (which stays code-defined and is looked up by `policy_id` via `policy_registry.py::resolve_evaluate_fn`). A `policy_id` registered only in the database with no matching code-defined evaluator **fails closed** — `_fail_closed_evaluate` always reports a violation rather than silently passing an un-evaluable policy. Activation/deactivation of a policy or pack is restricted to `PLATFORM_ADMIN`/`COMPLIANCE_APPROVER` roles (`POLICY_ADMIN_ROLES`) — see [Human-in-the-Loop Control](AI_ASSURANCE_AND_GOVERNANCE.md).

## The 8 drift types

`src/domain/drift/detector.py::detect_drift(desired, previous_observed, current_observed, active_exceptions, ...)` is a pure function performing typed field comparison — never raw text diffing — between three snapshots keyed by `resource_id`. Every `DriftFinding` satisfies the full explanation contract required by spec section 8: what changed, previous value, current value, expected value, why it matters, policy, severity, evidence, remediation, exception eligibility.

| Drift type | Triggered by |
|---|---|
| `UNMANAGED_RESOURCE` | An observed resource has no corresponding desired-state entry — it exists without ever being approved. |
| `ARCHITECTURAL` | A desired-state resource is missing from the current observation (removed without a corresponding desired-state update), or a baseline-membership attribute mismatch. |
| `SECURITY` | `publicly_accessible`, IAM wildcards, `privilege_escalation_enabled`, or `encryption_at_rest_enabled` changed between snapshots. |
| `IDENTITY_AND_PERMISSION` | IAM-role/binding-shaped attribute changes not already covered by `SECURITY`. |
| `OPERATIONAL_CONTROL` | `audit_logging_enabled`, `monitoring_enabled`, `backup_enabled`, or `high_availability_configured` changed. |
| `COMPLIANCE` | Tag/ownership/retention/runtime-support attributes changed. |
| `CONFIGURATION` | Region, resource type, or other non-security configuration fields changed. |
| `EXCEPTION` | An active exception covering this resource/policy expired or was revoked while the underlying condition it suppressed is still present. |

Drift findings and compliance findings share the same `FindingStatus` lifecycle and the same `GovernanceDecisionContext` shape downstream — the decision router treats a drift finding and a compliance finding identically once severity/evidence/criticality are resolved.

## Decision outcomes and the routing rules

`src/application/routing/decision_router.py::route_governance_decision` is a pure function evaluated in a fixed priority order:

1. **Emergency stop active + a violation exists** → `GOVERNANCE_BLOCK` (checked first, above even "no violation," for safety).
2. **No violation** → `COMPLIANT`.
3. **CRITICAL severity on a non-exception-eligible policy** → `GOVERNANCE_BLOCK` (can never be bypassed by any exception).
4. **CRITICAL severity** → `GOVERNANCE_BLOCK`.
5. **Any AI assurance gate failed** → `GOVERNANCE_BLOCK` (fail closed rather than let a lighter decision stand on unverified advisory content — even though the gate result carries no opinion, only a PASSED/WARNING/FAILED status).
6. **Active/approved, eligible exception covers this finding** → `OBSERVATION_RECORDED` (suppressed, but not silent — still an audited, visible record).
7. **Exception pending review** → `EXCEPTION_REVIEW_REQUIRED` if the kill switch is `NORMAL`, else `REMEDIATION_REQUIRED` (new exception workflow is itself blocked while the kill switch is not `NORMAL`).
8. **Evidence incomplete** → `REMEDIATION_REQUIRED` (can never be routed lighter, regardless of severity).
9. **HIGH severity**, repeated ≥3 times on a `CRITICAL`-criticality resource in `PRODUCTION` → `GOVERNANCE_BLOCK` (escalation); otherwise → `REMEDIATION_REQUIRED`.
10. **MEDIUM severity** → `REMEDIATION_REQUIRED`.
11. **LOW severity** on a `CRITICAL`-criticality resource in `PRODUCTION` → `REMEDIATION_REQUIRED`; otherwise → `OBSERVATION_RECORDED`.
12. **INFO severity** → `OBSERVATION_RECORDED`.

Note: `EXPIRED`/`REJECTED`/`REVOKED` exception states intentionally fall through step 6/7 rather than continuing to suppress — a finding stops being covered the instant its exception leaves the active/approved state (spec section 12, demonstrated by demo scenario 12).

### Repeated-violation escalation

`repeated_violation_count` (step 9) is populated by `ComplianceFindingRepository.count_recent_violations(policy_id, resource_id, within_last=10)` — a count of prior findings for the exact same `(policy_id, resource_id)` pair, capped to the 10 most recent. It is only ever non-zero for **compliance** findings in this implementation; `GenerateGovernanceDecisionUseCase` hardcodes it to `0` for drift findings. `REPEATED_VIOLATION_ESCALATION_THRESHOLD = 3` is the exact trigger — see `docs/TESTING_AND_VALIDATION.md`'s demo-scenario-16 note for how this is exercised end-to-end.

### Decision lifecycle guard

`src/domain/state_machine/decision_transitions.py` is an explicit allow-list constraining which *successor* decision a later re-evaluation of the same finding may legitimately reach without an intervening state change (e.g. `GOVERNANCE_BLOCK` can never silently become `COMPLIANT` with no remediation or exception ever recorded). This does not gate the router itself — the router always computes fresh from current evidence — it exists to catch orchestration bugs.
