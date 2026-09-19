# Multi-Cloud Reference

## Resource normalization mapping

`ResourceType` (`src/domain/enums/resource_type.py`) is the provider-independent boundary every adapter normalizes into. Nothing downstream of this enum — the policy engine, drift detector, decision router — branches on which cloud a resource came from.

| Normalized `ResourceType` | AWS | GCP |
|---|---|---|
| `IAM_ROLE` | IAM roles / policies | — |
| `IAM_BINDING` | — | IAM bindings / service accounts |
| `SECURITY_GROUP` | Security groups | — |
| `FIREWALL_RULE` | — | VPC firewall rules |
| `OBJECT_STORAGE_BUCKET` | S3 buckets | Cloud Storage buckets |
| `RELATIONAL_DATABASE` | RDS instances | Cloud SQL instances |
| `CONTAINER_SERVICE` | ECS services | Cloud Run services |
| `SECRETS_REFERENCE` | Secrets Manager references | Secret Manager references |
| `AUDIT_LOG_CONFIG` | CloudTrail configuration | Cloud Audit Logs configuration |
| `MONITORING_CONFIG` | CloudWatch logging configuration | Cloud Monitoring configuration |

`CloudProvider` is a 2-value enum (`AWS`, `GCP`) carried on every `ManagedSystem` and `CloudResource`; `Environment` (`DEV`/`STAGING`/`PRODUCTION`) is provider-independent as well.

## Mock inventory providers

`MockAWSInventoryProvider` and `MockGCPInventoryProvider` (`src/adapters/cloud/`) both implement the `CloudInventoryProvider` port (`fetch_observed_snapshot(managed_system_id, environment, correlation_id) -> ObservedStateSnapshot`). Neither makes a real network call or requires credentials — resource *configuration* is a deterministic function of `managed_system_id`/`environment` (the same inputs always produce the same normalized resources and compliance mix), while `snapshot_id`/`captured_at` vary per call the way a real inventory poll would. Each covers every resource category listed above for its cloud, with a deliberate mix of compliant and violating resources so demo scenarios have real, reproducible data. `POST /api/v1/systems/{id}/observed-state/fetch` is the "offline equivalent of a real periodic inventory poll" this project ships in place of an actual AWS/GCP SDK integration.

## Terraform reference architectures

Both stacks are validated (`fmt`, `init -backend=false`) but **never applied** by this repository or its CI — they exist to demonstrate a realistic, security-conscious production topology for each cloud, not to provision anything.

### AWS (`infrastructure/aws/`)

VPC with 2-AZ public/private subnets, NAT gateway, an ALB (public) fronting an ECS Fargate service (private subnets only) with dedicated security groups (`alb`, `ecs_tasks`, `rds` — cross-referenced via separate `aws_security_group_rule`s to avoid a dependency cycle), RDS Postgres 16 (private-only, encrypted at rest) with its connection string in Secrets Manager, an ECR repository for the app image, CloudWatch log group, and two IAM roles: `ecs_execution` (standard execution policy) and `ecs_task` (starts with **zero** permissions — the app never calls an AWS API directly — plus one inline least-privilege `secretsmanager:GetSecretValue` policy scoped to exactly the one DB-credentials secret ARN). ALB listener terminates HTTPS; health check targets `/health`.

### GCP (`infrastructure/gcp/`)

VPC with a Cloud Run direct-egress subnet, private-services-access peering for Cloud SQL, Cloud SQL Postgres 16 (private IP only — never exposed to the public internet, even transiently), a Cloud Run v2 service reading its database URL from Secret Manager via `value_source.secret_key_ref`, an Artifact Registry repository for the app image, and a dedicated service account with exactly four least-privilege bindings (secret accessor on the one DB secret, log writer, metric writer, Cloud SQL client — nothing broader). Public invocation is gated behind `var.allow_unauthenticated` (default `true` for POC demo convenience only — the module's own comment flags that a real deployment should front Cloud Run with IAP or a load balancer instead).

### Why the two topologies differ

AWS uses a public ALB + private ECS pattern (the conventional, minimal-moving-parts shape for Fargate); GCP uses Cloud Run's own direct-egress networking plus private Cloud SQL rather than a public-IP-with-authorized-networks alternative — more moving parts, but the database is never exposed to the public internet even transiently. Both achieve the same actual security property (database never publicly reachable, application never holds broad cloud-API permissions); the mechanism differs because each cloud's managed-compute product has a different native networking model. See `infrastructure/gcp/network.tf`'s own comment for the simpler public-IP alternative this trade-off was weighed against.

## What is deliberately not multi-cloud

The API, database schema, policy engine, drift detector, and decision router have exactly one implementation each, shared across both clouds — only the inventory-fetch adapter and the two Terraform stacks are cloud-specific. Adding a third cloud provider means writing one new `CloudInventoryProvider` adapter and one new Terraform stack; it does not touch `domain/`, `application/`, or the API layer at all.
