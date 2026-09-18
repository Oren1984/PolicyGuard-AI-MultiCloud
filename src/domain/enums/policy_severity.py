from enum import IntEnum


class PolicySeverity(IntEnum):
    """Ordered so comparisons (>=, max()) work for escalation logic."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name
