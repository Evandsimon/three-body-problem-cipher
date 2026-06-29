"""Tests for the post-quantum hybrid key agreement (item F).

Auto-skips if `cryptography` has no ML-KEM (needs OpenSSL 3.5+) — same skip-don't-fail rule the Rust
parity tests use, so the suite stays green on older platforms.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pq_keyexchange import (  # noqa: E402
    MLKEM_AVAILABLE,
    HybridInitiator,
    HybridResponder,
    hybrid_agree,
)

pytestmark = pytest.mark.skipif(not MLKEM_AVAILABLE, reason="ML-KEM needs cryptography w/ OpenSSL 3.5+")


def test_hybrid_roundtrip_agrees():
    assert len(hybrid_agree(HybridInitiator(), HybridResponder())) == 32


def test_manual_two_message_flow_agrees():
    alice, bob = HybridInitiator(), HybridResponder()
    kem_ct, key_bob = bob.respond(alice.dh_public, alice.kem_public)
    key_alice = alice.shared_key(bob.dh_public, kem_ct)
    assert key_alice == key_bob


def test_independent_sessions_differ():
    k1 = hybrid_agree(HybridInitiator(), HybridResponder())
    k2 = hybrid_agree(HybridInitiator(), HybridResponder())
    assert k1 != k2                       # fresh DH + fresh ML-KEM each time


def test_info_binding_changes_key():
    alice, bob = HybridInitiator(), HybridResponder()
    kem_ct, key_bob = bob.respond(alice.dh_public, alice.kem_public, info=b"context-A")
    key_alice = alice.shared_key(bob.dh_public, kem_ct, info=b"context-A")
    assert key_alice == key_bob
    # A different info on one side must NOT agree.
    kem_ct2, key_bob2 = bob.respond(alice.dh_public, alice.kem_public, info=b"context-B")
    assert alice.shared_key(bob.dh_public, kem_ct2, info=b"context-A") != key_bob2


def test_tampered_kem_ciphertext_breaks_agreement():
    # Flip a byte of the KEM ciphertext before Alice processes it. ML-KEM's implicit rejection yields
    # a different decapsulated secret, and the transcript differs too -> Alice's key != Bob's.
    alice, bob = HybridInitiator(), HybridResponder()
    kem_ct, key_bob = bob.respond(alice.dh_public, alice.kem_public)
    bad = bytearray(kem_ct)
    bad[0] ^= 0x01
    assert alice.shared_key(bob.dh_public, bytes(bad)) != key_bob


def test_tampered_dh_public_breaks_agreement():
    alice, bob = HybridInitiator(), HybridResponder()
    kem_ct, key_bob = bob.respond(alice.dh_public, alice.kem_public)
    # Alice is fed a DIFFERENT dh_public than Bob actually used -> classical secret + transcript differ.
    other = HybridResponder()
    assert alice.shared_key(other.dh_public, kem_ct) != key_bob


def test_invalid_dh_peer_rejected():
    bob = HybridResponder()
    with pytest.raises(ValueError):
        bob.respond(1, b"\x00" * 1184)    # degenerate DH public (small subgroup)


def test_end_to_end_with_aead():
    from aead import open_, seal
    alice, bob = HybridInitiator(), HybridResponder()
    kem_ct, key_bob = bob.respond(alice.dh_public, alice.kem_public)
    key_alice = alice.shared_key(bob.dh_public, kem_ct)
    blob = seal(key_alice, b"post-quantum protected payload")
    assert open_(key_bob, blob) == b"post-quantum protected payload"
