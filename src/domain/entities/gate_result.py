from __future__ import annotations

from dataclasses import dataclass, field

from src.domain.enums.gate_name import GateName, GateStatus


@dataclass(frozen=True, slots=True)
class GateResult:
    """The deterministic pass/warning/fail outcome of one AI assurance gate.

    This carries only a status and a machine-checkable reason — never the
    AI's raw text — which is what lets the governance decision router treat
    gate results as a legitimate deterministic input (spec section 9)
    without ever touching AI-generated content.
    """

    gate: GateName
    status: GateStatus
    reason: str
    details: dict = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return self.status == GateStatus.PASSED

    @property
    def failed(self) -> bool:
        return self.status == GateStatus.FAILED


@dataclass(frozen=True, slots=True)
class GatePipelineResult:
    results: tuple[GateResult, ...]

    @property
    def all_passed(self) -> bool:
        return all(r.status == GateStatus.PASSED for r in self.results)

    @property
    def any_failed(self) -> bool:
        return any(r.status == GateStatus.FAILED for r in self.results)

    @property
    def any_warning(self) -> bool:
        return any(r.status == GateStatus.WARNING for r in self.results)

    def get(self, gate: GateName) -> GateResult | None:
        for r in self.results:
            if r.gate == gate:
                return r
        return None
