from enum import StrEnum


class CloudProvider(StrEnum):
    """Supported cloud providers. Real credentials are never required — see
    src/ports/cloud_inventory_provider.py for the normalization boundary."""

    AWS = "aws"
    GCP = "gcp"
