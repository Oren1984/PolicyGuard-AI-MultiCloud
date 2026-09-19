"""Pure hash-chain algorithm unit tests (spec section 14) --
canonicalization, hashing, and the tamper-detection algorithm itself,
independent of PostgreSQL (the persistence-layer, real-DB version of this
regression lives in tests/integration/test_audit_repository.py and
tests/security/test_security_regressions.py)."""

from __future__ import annotations

from src.domain.policies.audit_chain import (
    GENESIS_HASH,
    ChainLink,
    canonicalize_payload,
    compute_hash,
    verify_chain,
)


def _link(sequence: int, previous_hash: str, payload: dict) -> ChainLink:
    canonical = canonicalize_payload(payload)
    current_hash = compute_hash(previous_hash, canonical)
    return ChainLink(
        sequence=sequence, previous_hash=previous_hash, canonical_payload=canonical, current_hash=current_hash
    )


def test_canonicalize_payload_is_deterministic_regardless_of_key_order():
    a = canonicalize_payload({"b": 1, "a": 2})
    b = canonicalize_payload({"a": 2, "b": 1})
    assert a == b


def test_empty_chain_is_valid():
    result = verify_chain([])
    assert result.is_valid is True
    assert result.total_records == 0


def test_single_valid_link_verifies():
    link = _link(1, GENESIS_HASH, {"action": "TEST"})
    result = verify_chain([link])
    assert result.is_valid is True
    assert result.total_records == 1


def test_multi_link_chain_verifies():
    link1 = _link(1, GENESIS_HASH, {"action": "FIRST"})
    link2 = _link(2, link1.current_hash, {"action": "SECOND"})
    link3 = _link(3, link2.current_hash, {"action": "THIRD"})
    result = verify_chain([link1, link2, link3])
    assert result.is_valid is True
    assert result.total_records == 3


class TestTamperDetection:
    def test_mutated_payload_is_detected(self):
        """Regression: audit-chain tampering must be detected -- mutating a
        historical record's payload after the fact (without recomputing the
        hash, exactly as an attacker with raw DB access would do) must flip
        verification to invalid."""
        link1 = _link(1, GENESIS_HASH, {"action": "FIRST"})
        link2 = _link(2, link1.current_hash, {"action": "SECOND"})

        tampered_link1 = ChainLink(
            sequence=link1.sequence,
            previous_hash=link1.previous_hash,
            canonical_payload=canonicalize_payload({"action": "TAMPERED"}),  # payload changed...
            current_hash=link1.current_hash,  # ...but the stored hash was NOT recomputed
        )
        result = verify_chain([tampered_link1, link2])
        assert result.is_valid is False
        assert result.first_invalid_sequence == 1
        assert "tampered" in (result.reason or "").lower()

    def test_reordered_sequence_is_detected(self):
        link1 = _link(1, GENESIS_HASH, {"action": "FIRST"})
        link2 = _link(2, link1.current_hash, {"action": "SECOND"})
        result = verify_chain([link2, link1])  # out of order
        assert result.is_valid is False

    def test_sequence_gap_is_detected(self):
        link1 = _link(1, GENESIS_HASH, {"action": "FIRST"})
        link3 = _link(3, link1.current_hash, {"action": "SKIPPED_TWO"})
        result = verify_chain([link1, link3])
        assert result.is_valid is False
        assert result.first_invalid_sequence == 3

    def test_broken_previous_hash_link_is_detected(self):
        link1 = _link(1, GENESIS_HASH, {"action": "FIRST"})
        # link2 claims a previous_hash that doesn't match link1's actual hash.
        link2 = _link(2, "0" * 64, {"action": "SECOND"})
        result = verify_chain([link1, link2])
        assert result.is_valid is False
        assert result.first_invalid_sequence == 2

    def test_deleted_middle_record_breaks_the_chain(self):
        # Deleting a record is indistinguishable from a sequence gap once
        # the remaining records are re-verified -- proving deletion, not
        # just mutation, is detectable.
        link1 = _link(1, GENESIS_HASH, {"action": "FIRST"})
        link2 = _link(2, link1.current_hash, {"action": "SECOND"})
        _link3 = _link(3, link2.current_hash, {"action": "THIRD"})
        link4 = _link(4, _link3.current_hash, {"action": "FOURTH"})
        result = verify_chain([link1, link2, link4])  # link3 "deleted"
        assert result.is_valid is False
        assert result.first_invalid_sequence == 4
