"""Hash-chain canonicalization and verification rules for the audit trail.

Tamper-evident, not immutable: a SHA-256 hash chain lets us *detect*
retroactive mutation or deletion of prior records, but it does not, by
itself, prevent someone with direct database access from rewriting the
entire chain consistently. Production hardening (external WORM storage,
ledger anchoring) is documented in a later phase's TRADEOFFS doc.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

GENESIS_HASH = "0" * 64


def canonicalize_payload(payload: dict) -> str:
    """Deterministic JSON serialization used for both hashing and storage."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_hash(previous_hash: str, canonical_payload: str) -> str:
    digest = hashlib.sha256()
    digest.update(previous_hash.encode("utf-8"))
    digest.update(canonical_payload.encode("utf-8"))
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class ChainLink:
    sequence: int
    previous_hash: str
    canonical_payload: str
    current_hash: str


@dataclass(frozen=True, slots=True)
class ChainVerificationResult:
    is_valid: bool
    total_records: int
    first_invalid_sequence: int | None = None
    reason: str | None = None


def verify_chain(links: list[ChainLink]) -> ChainVerificationResult:
    """Recomputes every hash in sequence order and compares against the
    stored value. Detects mutation, reordering, and sequence gaps."""
    expected_previous = GENESIS_HASH
    expected_sequence = 1
    for link in links:
        if link.sequence != expected_sequence:
            return ChainVerificationResult(
                is_valid=False,
                total_records=len(links),
                first_invalid_sequence=link.sequence,
                reason=f"sequence discontinuity: expected {expected_sequence}, found {link.sequence}",
            )
        if link.previous_hash != expected_previous:
            return ChainVerificationResult(
                is_valid=False,
                total_records=len(links),
                first_invalid_sequence=link.sequence,
                reason="previous_hash does not match the prior record's current_hash",
            )
        recomputed = compute_hash(link.previous_hash, link.canonical_payload)
        if recomputed != link.current_hash:
            return ChainVerificationResult(
                is_valid=False,
                total_records=len(links),
                first_invalid_sequence=link.sequence,
                reason="stored current_hash does not match recomputed hash (payload was tampered with)",
            )
        expected_previous = link.current_hash
        expected_sequence += 1

    return ChainVerificationResult(is_valid=True, total_records=len(links))
