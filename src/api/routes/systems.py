"""Systems and inventory capability group (spec section 15): register/list
managed systems, submit desired/observed-state snapshots, list normalized
resources, retrieve snapshot comparisons, and trigger drift detection."""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, Query, status

from src.api.dependencies.actor import get_actor
from src.api.dependencies.kill_switch_gate import require_mutation_allowed, require_normal_mode_for_evaluation
from src.api.dependencies.providers import get_cloud_inventory_provider
from src.api.dependencies.repositories import (
    get_audit_repo,
    get_desired_snapshot_repo,
    get_managed_system_repo,
    get_observed_snapshot_repo,
)
from src.api.dependencies.use_cases import (
    get_detect_drift_use_case,
    get_submit_desired_state_use_case,
    get_submit_observed_state_use_case,
)
from src.api.routes._converters import (
    baseline_request_to_domain,
    baseline_to_response,
    criticality_from_literal,
    drift_finding_to_response,
    managed_system_to_response,
    resource_request_to_domain,
    resource_to_response,
)
from src.api.schemas.system_schemas import (
    CloudResourceResponse,
    DesiredStateSnapshotSubmitRequest,
    DriftDetectionResponse,
    ManagedSystemCreateRequest,
    ManagedSystemListResponse,
    ManagedSystemResponse,
    ObservedStateSnapshotSubmitRequest,
    SnapshotComparisonResponse,
    SnapshotResponse,
)
from src.application.use_cases.detect_drift import DetectDriftUseCase
from src.application.use_cases.submit_desired_state import SubmitDesiredStateSnapshotUseCase
from src.application.use_cases.submit_observed_state import SubmitObservedStateSnapshotUseCase
from src.domain.entities.actor import Actor
from src.domain.entities.managed_system import ManagedSystem
from src.domain.entities.state_snapshot import DesiredStateSnapshot, ObservedStateSnapshot
from src.observability.correlation import get_correlation_id
from src.observability.metrics import evaluation_duration_seconds, evaluations_total, findings_total

router = APIRouter(prefix="/api/v1/systems", tags=["systems"])


def _convert_resources(resources, *, system: ManagedSystem) -> tuple:
    return tuple(
        resource_request_to_domain(
            r,
            managed_system_id=system.system_id,
            cloud_provider=system.cloud_provider,
            environment=system.environment,
        )
        for r in resources
    )


@router.post("", response_model=ManagedSystemResponse, status_code=status.HTTP_201_CREATED)
def register_system(
    payload: ManagedSystemCreateRequest,
    actor: Actor = Depends(get_actor),
    managed_system_repo=Depends(get_managed_system_repo),
    audit_repo=Depends(get_audit_repo),
    _mode=Depends(require_mutation_allowed),
) -> ManagedSystemResponse:
    system = ManagedSystem(
        system_id=payload.system_id,
        name=payload.name,
        cloud_provider=payload.cloud_provider,
        environment=payload.environment,
        owner_actor_id=payload.owner_actor_id or actor.actor_id,
        criticality=criticality_from_literal(payload.criticality),
        description=payload.description,
        tags=payload.tags,
    )
    created = managed_system_repo.create(system)
    audit_repo.append(
        actor=actor.actor_id,
        actor_role=actor.role.value,
        action="MANAGED_SYSTEM_REGISTERED",
        resource_type="managed_system",
        resource_id=created.system_id,
        correlation_id=get_correlation_id(),
        payload={"cloud_provider": created.cloud_provider.value, "environment": created.environment.value},
    )
    return managed_system_to_response(created)


@router.get("", response_model=ManagedSystemListResponse)
def list_systems(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    managed_system_repo=Depends(get_managed_system_repo),
) -> ManagedSystemListResponse:
    items, total = managed_system_repo.list(limit=limit, offset=offset)
    return ManagedSystemListResponse(
        items=[managed_system_to_response(s) for s in items], total=total, limit=limit, offset=offset
    )


@router.get("/{system_id}", response_model=ManagedSystemResponse)
def get_system(system_id: str, managed_system_repo=Depends(get_managed_system_repo)) -> ManagedSystemResponse:
    return managed_system_to_response(managed_system_repo.get(system_id))


@router.post(
    "/{system_id}/desired-state", response_model=SnapshotResponse, status_code=status.HTTP_201_CREATED
)
def submit_desired_state(
    system_id: str,
    payload: DesiredStateSnapshotSubmitRequest,
    actor: Actor = Depends(get_actor),
    managed_system_repo=Depends(get_managed_system_repo),
    use_case: SubmitDesiredStateSnapshotUseCase = Depends(get_submit_desired_state_use_case),
    _mode=Depends(require_mutation_allowed),
) -> SnapshotResponse:
    system = managed_system_repo.get(system_id)
    snapshot = DesiredStateSnapshot(
        snapshot_id=payload.snapshot_id,
        managed_system_id=system_id,
        source=payload.source,
        resources=_convert_resources(payload.resources, system=system),
        baseline=baseline_request_to_domain(payload.baseline),
        submitted_by=actor.actor_id,
    )
    created = use_case.execute(snapshot, actor=actor, correlation_id=get_correlation_id())
    return SnapshotResponse(
        snapshot_id=created.snapshot_id,
        managed_system_id=created.managed_system_id,
        source=created.source,
        resources=[resource_to_response(r) for r in created.resources],
        captured_at=created.captured_at,
        baseline=baseline_to_response(created.baseline),
    )


@router.post(
    "/{system_id}/observed-state", response_model=SnapshotResponse, status_code=status.HTTP_201_CREATED
)
def submit_observed_state(
    system_id: str,
    payload: ObservedStateSnapshotSubmitRequest,
    actor: Actor = Depends(get_actor),
    managed_system_repo=Depends(get_managed_system_repo),
    use_case: SubmitObservedStateSnapshotUseCase = Depends(get_submit_observed_state_use_case),
    _mode=Depends(require_mutation_allowed),
) -> SnapshotResponse:
    system = managed_system_repo.get(system_id)
    correlation_id = get_correlation_id()
    snapshot = ObservedStateSnapshot(
        snapshot_id=payload.snapshot_id,
        managed_system_id=system_id,
        source=payload.source,
        resources=_convert_resources(payload.resources, system=system),
        correlation_id=correlation_id,
    )
    created = use_case.execute(snapshot, actor=actor, correlation_id=correlation_id)
    return SnapshotResponse(
        snapshot_id=created.snapshot_id,
        managed_system_id=created.managed_system_id,
        source=created.source,
        resources=[resource_to_response(r) for r in created.resources],
        captured_at=created.captured_at,
        correlation_id=created.correlation_id,
    )


@router.post(
    "/{system_id}/observed-state/fetch",
    response_model=SnapshotResponse,
    status_code=status.HTTP_201_CREATED,
)
def fetch_observed_state(
    system_id: str,
    actor: Actor = Depends(get_actor),
    managed_system_repo=Depends(get_managed_system_repo),
    use_case: SubmitObservedStateSnapshotUseCase = Depends(get_submit_observed_state_use_case),
    _mode=Depends(require_mutation_allowed),
) -> SnapshotResponse:
    """Fetches a fresh snapshot from the deterministic mock cloud inventory
    provider matching this system's cloud_provider (spec section 6) and
    persists it as a new observed-state snapshot -- the offline equivalent
    of a real periodic inventory poll."""
    system = managed_system_repo.get(system_id)
    correlation_id = get_correlation_id()
    provider = get_cloud_inventory_provider(system.cloud_provider)
    fetched = provider.fetch_observed_snapshot(
        managed_system_id=system_id, environment=system.environment, correlation_id=correlation_id
    )
    created = use_case.execute(fetched, actor=actor, correlation_id=correlation_id)
    return SnapshotResponse(
        snapshot_id=created.snapshot_id,
        managed_system_id=created.managed_system_id,
        source=created.source,
        resources=[resource_to_response(r) for r in created.resources],
        captured_at=created.captured_at,
        correlation_id=created.correlation_id,
    )


@router.get("/{system_id}/resources", response_model=list[CloudResourceResponse])
def list_resources(
    system_id: str, observed_snapshot_repo=Depends(get_observed_snapshot_repo)
) -> list[CloudResourceResponse]:
    snapshot = observed_snapshot_repo.get_latest_for_system(system_id)
    if snapshot is None:
        return []
    return [resource_to_response(r) for r in snapshot.resources]


@router.get("/{system_id}/snapshot-comparison", response_model=SnapshotComparisonResponse)
def get_snapshot_comparison(
    system_id: str,
    desired_snapshot_repo=Depends(get_desired_snapshot_repo),
    observed_snapshot_repo=Depends(get_observed_snapshot_repo),
) -> SnapshotComparisonResponse:
    desired = desired_snapshot_repo.get_latest_for_system(system_id)
    observed = observed_snapshot_repo.get_latest_for_system(system_id)
    return SnapshotComparisonResponse(
        managed_system_id=system_id,
        desired=(
            SnapshotResponse(
                snapshot_id=desired.snapshot_id,
                managed_system_id=desired.managed_system_id,
                source=desired.source,
                resources=[resource_to_response(r) for r in desired.resources],
                captured_at=desired.captured_at,
                baseline=baseline_to_response(desired.baseline),
            )
            if desired is not None
            else None
        ),
        observed=(
            SnapshotResponse(
                snapshot_id=observed.snapshot_id,
                managed_system_id=observed.managed_system_id,
                source=observed.source,
                resources=[resource_to_response(r) for r in observed.resources],
                captured_at=observed.captured_at,
                correlation_id=observed.correlation_id,
            )
            if observed is not None
            else None
        ),
    )


@router.post("/{system_id}/drift-detection", response_model=DriftDetectionResponse)
def run_drift_detection(
    system_id: str,
    actor: Actor = Depends(get_actor),
    managed_system_repo=Depends(get_managed_system_repo),
    use_case: DetectDriftUseCase = Depends(get_detect_drift_use_case),
    _mode=Depends(require_normal_mode_for_evaluation),
) -> DriftDetectionResponse:
    system = managed_system_repo.get(system_id)
    correlation_id = get_correlation_id()
    started = time.perf_counter()
    findings = use_case.execute(managed_system_id=system_id, actor=actor, correlation_id=correlation_id)
    evaluation_duration_seconds.labels(evaluation_type="drift").observe(time.perf_counter() - started)
    evaluations_total.labels(evaluation_type="drift").inc()
    provider = system.cloud_provider.value
    for f in findings:
        findings_total.labels(severity=f.severity.label, provider=provider, kind="drift").inc()
    return DriftDetectionResponse(
        managed_system_id=system_id, findings=[drift_finding_to_response(f) for f in findings]
    )
