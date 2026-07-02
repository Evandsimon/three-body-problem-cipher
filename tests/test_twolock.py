"""Tests for the two-lock shell (Phase 6, "Option B") — chaos outer wall over a vetted inner vault."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import cipher.aead as aead  # noqa: E402
from cipher.twolock import (  # noqa: E402
    INNER_NONCE_LEN,
    InvalidTag,
    _derive_keys,
    open_twolock,
    seal_twolock,
)

KEY = b"a shared secret of arbitrary length!!"
MSG = b"the quick brown fox jumps over the lazy dog" * 5
INNERS = ("aes-256-gcm", "chacha20-poly1305")


@pytest.mark.parametrize("inner", INNERS)
def test_roundtrip(inner):
    assert open_twolock(KEY, seal_twolock(KEY, MSG, inner=inner)) == MSG


@pytest.mark.parametrize("inner", INNERS)
def test_empty_message(inner):
    assert open_twolock(KEY, seal_twolock(KEY, b"", inner=inner)) == b""


def test_self_describing_inner():
    # open_twolock must work without being told which inner cipher was used.
    for inner in INNERS:
        assert open_twolock(KEY, seal_twolock(KEY, MSG, inner=inner)) == MSG


def test_fresh_nonces_no_repeat():
    a, b = seal_twolock(KEY, MSG), seal_twolock(KEY, MSG)
    assert a != b
    assert open_twolock(KEY, a) == open_twolock(KEY, b) == MSG


@pytest.mark.parametrize("inner", INNERS)
def test_tamper_anywhere_rejected(inner):
    blob = seal_twolock(KEY, MSG, inner=inner)
    for pos in (0, len(blob) // 2, len(blob) - 1):
        bad = bytearray(blob)
        bad[pos] ^= 0x01
        with pytest.raises(InvalidTag):
            open_twolock(KEY, bytes(bad))


def test_truncation_rejected():
    blob = seal_twolock(KEY, MSG)
    with pytest.raises(InvalidTag):
        open_twolock(KEY, blob[:-1])


def test_wrong_key_rejected():
    blob = seal_twolock(KEY, MSG)
    with pytest.raises(InvalidTag):
        open_twolock(b"a different secret key.............xx", blob)


def test_aad_binding():
    blob = seal_twolock(KEY, MSG, aad=b"context-A")
    assert open_twolock(KEY, blob, aad=b"context-A") == MSG
    with pytest.raises(InvalidTag):
        open_twolock(KEY, blob, aad=b"context-B")


def test_unknown_inner_rejected_on_seal():
    with pytest.raises(ValueError):
        seal_twolock(KEY, MSG, inner="rot13")


def test_master_must_be_bytes():
    with pytest.raises(TypeError):
        seal_twolock("a string key", MSG)


def test_keys_independent_and_separated():
    k_outer, k_inner = _derive_keys(KEY)
    assert k_outer != k_inner
    assert len(k_outer) == len(k_inner) == 32


def test_inner_vault_holds_when_outer_broken():
    # The headline guarantee, as a regression test: grant the attacker the outer key (chaos fully
    # broken). Peeling the outer layer must leave AES-256-GCM that no wrong inner key can open.
    from cryptography.exceptions import InvalidTag as CryptoInvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aad = b"sensitive"
    blob = seal_twolock(KEY, MSG, aad=aad, inner="aes-256-gcm")
    k_outer, k_inner = _derive_keys(KEY)

    inner_blob = aead.open_(k_outer, blob, aad=aad)   # attacker strips the (broken) chaos wall
    assert MSG not in inner_blob                       # plaintext is still AES-encrypted
    inner_nonce = inner_blob[1:1 + INNER_NONCE_LEN]
    inner_ct = inner_blob[1 + INNER_NONCE_LEN:]

    # No wrong inner key opens the vault; only the legitimate one does.
    for g in (os.urandom(32), b"\x00" * 32, k_outer):
        with pytest.raises(CryptoInvalidTag):
            AESGCM(g).decrypt(inner_nonce, inner_ct, aad)
    assert AESGCM(k_inner).decrypt(inner_nonce, inner_ct, aad) == MSG


def test_inner_lock_catches_forgery_with_known_outer_key():
    # Attacker knows the outer key: tamper the protected data, re-seal a valid outer layer.
    # The outer tag passes but the inner vault must still reject.
    aad = b"ctx"
    blob = seal_twolock(KEY, MSG, aad=aad)
    k_outer, _ = _derive_keys(KEY)
    inner_blob = bytearray(aead.open_(k_outer, blob, aad=aad))
    inner_blob[-1] ^= 0x01
    forged = aead.seal(k_outer, bytes(inner_blob), aad=aad)
    # outer alone accepts the forgery...
    assert aead.open_(k_outer, forged, aad=aad) == bytes(inner_blob)
    # ...but the two-lock open rejects it (inner AES-GCM catches the tamper).
    with pytest.raises(InvalidTag):
        open_twolock(KEY, forged, aad=aad)
