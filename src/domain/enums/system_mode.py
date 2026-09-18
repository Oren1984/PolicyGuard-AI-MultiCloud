from enum import StrEnum


class SystemMode(StrEnum):
    """Kill-switch modes (spec section 13). The system must fail closed
    whenever its mode cannot be determined reliably — callers that cannot
    obtain a mode must treat that as EMERGENCY_STOP, never as NORMAL."""

    NORMAL = "normal"
    PAUSED = "paused"
    EMERGENCY_STOP = "emergency_stop"
