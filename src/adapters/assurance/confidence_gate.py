"""Gate 3 of 5 (spec section 11): rejects or downgrades AI advisory content
below the configured confidence threshold."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from src.domain.entities.ai_advisory import AIAdvisoryContent
from src.domain.entities.gate_result import GateResult
from src.domain.enums.gate_name import GateName, GateStatus


@dataclass(frozen=True, slots=True)
class ConfidenceThresholds:
    approval_threshold: float = 0.70
    hard_floor: float = 0.35


DEFAULT_THRESHOLDS = ConfidenceThresholds()


class ConfidenceGate:
    """AssuranceGate implementation for GateName.CONFIDENCE."""

    def __init__(self, thresholds: ConfidenceThresholds = DEFAULT_THRESHOLDS) -> None:
        self._thresholds = thresholds

    def evaluate(self, content: AIAdvisoryContent, *, grounding_context: dict) -> GateResult:
        confidence = content.confidence
        details = {"confidence": confidence, **asdict(self._thresholds)}

        if confidence < self._thresholds.hard_floor:
            return GateResult(
                gate=GateName.CONFIDENCE,
                status=GateStatus.FAILED,
                reason=(
                    f"Confidence {confidence:.2f} is below the hard floor "
                    f"{self._thresholds.hard_floor:.2f}."
                ),
                details=details,
            )
        if confidence < self._thresholds.approval_threshold:
            return GateResult(
                gate=GateName.CONFIDENCE,
                status=GateStatus.WARNING,
                reason=(
                    f"Confidence {confidence:.2f} is in the mandatory-review range "
                    f"[{self._thresholds.hard_floor:.2f}, {self._thresholds.approval_threshold:.2f})."
                ),
                details=details,
            )
        return GateResult(
            gate=GateName.CONFIDENCE,
            status=GateStatus.PASSED,
            reason=(
                f"Confidence {confidence:.2f} meets the approval threshold "
                f"{self._thresholds.approval_threshold:.2f}."
            ),
            details=details,
        )
