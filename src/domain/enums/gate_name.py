from enum import StrEnum


class GateName(StrEnum):
    """The 5 mandatory AI assurance gates (spec section 11). Only the gate
    *contract* (this enum, GateResult, and the AssuranceGate port) is built
    in this phase — concrete gate implementations are a later phase."""

    SCHEMA = "schema"
    GROUNDING = "grounding"
    CONFIDENCE = "confidence"
    SAFETY = "safety"
    CONSISTENCY = "consistency"


class GateStatus(StrEnum):
    PASSED = "passed"
    WARNING = "warning"
    FAILED = "failed"
    SKIPPED = "skipped"
