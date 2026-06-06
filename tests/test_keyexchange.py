"""Tests for the Diffie-Hellman key-exchange layer (keyexchange.py)."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from aead import open_, seal  # noqa: E402
from keyexchange import P, DHParty, agree_key  # noqa: E402


def test_both_parties_derive_same_key():
    alice, bob = DHParty(), DHParty()
    assert alice.shared_key(bob.public) == bob.shared_key(alice.public)


def test_key_is_32_bytes():
    alice, bob = DHParty(), DHParty()
    assert len(alice.shared_key(bob.public)) == 32


def test_independent_runs_differ():
    """Fresh keypairs each time => different shared keys (randomness is live)."""
    k1 = agree_key(DHParty(), DHParty())
    k2 = agree_key(DHParty(), DHParty())
    assert k1 != k2


def test_deterministic_for_fixed_privates():
    """With pinned private exponents the exchange is reproducible (sanity, not for real use)."""
    a = DHParty(private=0xA11CE)
    b = DHParty(private=0xB0B)
    assert agree_key(a, b) == agree_key(DHParty(private=0xA11CE), DHParty(private=0xB0B))


def test_info_binding_changes_key():
    """Different domain-separation `info` yields a different key from the same exchange."""
    a, b = DHParty(private=0xA11CE), DHParty(private=0xB0B)
    assert a.shared_key(b.public, info=b"context-1") != a.shared_key(b.public, info=b"context-2")


def test_end_to_end_with_aead():
    """The whole point: agree a key over the wire, then use it with the chaos AEAD."""
    alice, bob = DHParty(), DHParty()
    key_a = alice.shared_key(bob.public)
    key_b = bob.shared_key(alice.public)
    blob = seal(key_a, b"no secret was pre-shared")
    assert open_(key_b, blob) == b"no secret was pre-shared"


@pytest.mark.parametrize("bad", [0, 1, P - 1, P, P + 1, -5])
def test_peer_validation_rejects_degenerate(bad):
    """Degenerate / out-of-range peer publics (small-subgroup footguns) must be rejected."""
    alice = DHParty()
    with pytest.raises(ValueError):
        alice.shared_key(bad)


def test_private_out_of_range_rejected():
    with pytest.raises(ValueError):
        DHParty(private=1)
    with pytest.raises(ValueError):
        DHParty(private=P)


def test_public_is_in_group():
    """A generated public value lives in the valid range (2 .. p-2)."""
    p = DHParty()
    assert 2 <= p.public <= P - 2
