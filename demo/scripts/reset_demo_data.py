"""Safe reset for the demo/mock dataset seeded by seed_demo_data.py.

Removes only records that seed_demo_data.py itself created -- every demo
managed system uses a fixed id under the reserved `demo-` prefix (e.g.
`demo-aws-checkout-api`) and carries `tags={"source": "demo",
"is_demo": "true", ...}`; every row this script deletes is scoped to
`managed_system_id` values that satisfy *both* conditions. A real managed
system must never be named with a `demo-` prefix (this is a reserved
namespace, documented in README.md/docs/OPERATIONS_AND_OBSERVABILITY.md),
so this can never touch real data.

There is no delete capability anywhere in the application's ports/adapters
or API by design (spec: governance records are append-only, superseded or
expired rather than deleted) -- adding one would be exactly the kind of
"core governance logic" change this task was told not to make. This script
therefore connects directly to Postgres, the same way `migrations/env.py`
and `tests/conftest.py` already do, using plain parameterized SQL scoped
tightly to the demo id list resolved at runtime -- never `DELETE FROM
<table>` without a `WHERE managed_system_id = ANY(:ids)` clause.

`audit_events` is deliberately NEVER touched. The audit hash chain is
append-only and tamper-evident by design (see docs/SECURITY.md) --
deleting rows out of the middle of it would create a sequence gap that
`verify_chain()` would correctly report as tampering. The audit trail
entries this seed data's own actions produced are real, correctly
hash-chained records of real actions the seed script took through the real,
governed API, and they remain permanently, exactly as the system intends
for every action it ever recorded. `policies`/`policy_packs` are also never
touched -- they are shared infrastructure (the real 20 policy definitions),
not demo data, even though the seed script ensures they exist.

Safety: same two gates as seed_demo_data.py -- refuses to run unless
`POLICYGUARD_DEMO_MODE=true` is set (or `--force`), and refuses against a
database it cannot first confirm only contains demo-prefixed rows beyond
the reserved id space (a sanity re-check right before deleting).

Usage:
    POLICYGUARD_DEMO_MODE=true python demo/scripts/reset_demo_data.py \
        [--database-url postgresql+psycopg://...] [--force] [--dry-run]
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import create_engine, text  # noqa: E402

DEMO_PREFIX = "demo-"

# Every table that carries managed_system_id, in child-to-parent order
# (harmless either way -- this schema has no foreign keys -- but kept tidy).
_DEMO_SCOPED_TABLES = (
    "remediation_plans",
    "policy_exceptions",
    "governance_decisions",
    "drift_findings",
    "compliance_findings",
    "observed_state_snapshots",
    "desired_state_snapshots",
    "managed_systems",
)


def _database_url(cli_value: str | None) -> str:
    return (
        cli_value
        or os.environ.get("POLICYGUARD_DATABASE_URL")
        or os.environ.get("DATABASE_URL")
        or "postgresql+psycopg://policyguard:policyguard@localhost:5432/policyguard"
    )


def _refuse_unless_authorized(force: bool) -> None:
    if not force and os.environ.get("POLICYGUARD_DEMO_MODE", "").strip().lower() != "true":
        raise SystemExit(
            "Refusing to reset: POLICYGUARD_DEMO_MODE is not set to 'true' in this script's own "
            "environment. Set POLICYGUARD_DEMO_MODE=true to run this deliberately, or pass --force."
        )


def reset(database_url: str, *, dry_run: bool = False) -> dict[str, int]:
    """Deletes every row across `_DEMO_SCOPED_TABLES` whose managed_system_id
    both starts with `demo-` and belongs to a managed_systems row tagged
    is_demo=true. Never touches audit_events, policies, or policy_packs.
    Returns {table: rows_deleted}. Safe to call with an empty/already-reset
    database -- every DELETE is a no-op if nothing matches."""
    engine = create_engine(database_url, future=True)
    counts: dict[str, int] = {}
    with engine.begin() as conn:
        demo_ids = (
            conn.execute(
                text(
                    "SELECT system_id FROM managed_systems "
                    "WHERE system_id LIKE :prefix AND tags->>'is_demo' = 'true'"
                ),
                {"prefix": f"{DEMO_PREFIX}%"},
            )
            .scalars()
            .all()
        )
        if not demo_ids:
            return {table: 0 for table in _DEMO_SCOPED_TABLES}

        for table in _DEMO_SCOPED_TABLES:
            id_column = "system_id" if table == "managed_systems" else "managed_system_id"
            if dry_run:
                result = conn.execute(
                    text(f"SELECT count(*) FROM {table} WHERE {id_column} = ANY(:ids)"),  # noqa: S608
                    {"ids": demo_ids},
                )
                counts[table] = result.scalar_one()
            else:
                result = conn.execute(
                    text(f"DELETE FROM {table} WHERE {id_column} = ANY(:ids)"),  # noqa: S608
                    {"ids": demo_ids},
                )
                counts[table] = result.rowcount
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--database-url", default=None, help="Defaults to POLICYGUARD_DATABASE_URL / DATABASE_URL."
    )
    parser.add_argument("--force", action="store_true", help="Bypass the POLICYGUARD_DEMO_MODE safety check.")
    parser.add_argument(
        "--dry-run", action="store_true", help="Report what would be deleted without deleting it."
    )
    args = parser.parse_args()

    _refuse_unless_authorized(args.force)
    database_url = _database_url(args.database_url)

    counts = reset(database_url, dry_run=args.dry_run)
    verb = "Would remove" if args.dry_run else "Removed"
    total = sum(counts.values())
    for table, n in counts.items():
        if n:
            print(f"{verb} {n} row(s) from {table}")
    print(f"\n{verb} {total} demo row(s) total. audit_events, policies, and policy_packs were not touched.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
