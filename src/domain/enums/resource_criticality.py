from enum import IntEnum


class ResourceCriticality(IntEnum):
    """Not one of the mandatory section-5 enums, but required structurally
    as an explicit, typed input to the decision router ("resource
    criticality" — spec section 9). Ordered for comparisons."""

    STANDARD = 0
    IMPORTANT = 1
    CRITICAL = 2
