"""Tests for the 3-independent-map keystream combiner."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from multimap import MultiMapEngine  # noqa: E402

KEY = b"a shared secret of arbitrary length!!"
NONCE = b"unique-nonce-0001"


def _bit_diff_fraction(a: bytes, b: bytes) -> float:
    diff = sum(bin(x ^ y).count("1") for x, y in zip(a, b))
    return diff / (len(a) * 8)


def test_roundtrip():
    msg = b"three independent chaotic maps" * 8
    ct = MultiMapEngine(KEY, NONCE).encrypt(msg)
    pt = MultiMapEngine(KEY, NONCE).decrypt(ct)
    assert pt == msg and ct != msg


def test_determinism():
    a = MultiMapEngine(KEY, NONCE).keystream(256)
    b = MultiMapEngine(KEY, NONCE).keystream(256)
    assert a == b, "same key+nonce must produce identical combined keystream"


def test_nonce_and_key_separation():
    base = MultiMapEngine(KEY, NONCE).keystream(256)
    assert MultiMapEngine(KEY, b"different-nonce!!").keystream(256) != base
    assert MultiMapEngine(KEY + b"x", NONCE).keystream(256) != base


def test_combined_differs_from_each_submap():
    eng = MultiMapEngine(KEY, NONCE)
    combined = MultiMapEngine(KEY, NONCE).keystream(64)
    for i in range(eng.n_maps):
        sub = MultiMapEngine(KEY, NONCE).engines[i].keystream(64)
        assert sub != combined, f"combined stream must differ from sub-map {i}"


def test_avalanche_near_half():
    base = MultiMapEngine(KEY, NONCE).keystream(2048)
    fracs = []
    for i in range(64):
        flipped_key = bytes([KEY[0] ^ (1 << (i % 8))]) + KEY[1:] if i < 8 else KEY
        flipped_nonce = NONCE if i < 8 else (
            bytes([NONCE[0] ^ (1 << (i % 8))]) + NONCE[1:])
        other = MultiMapEngine(flipped_key, flipped_nonce).keystream(2048)
        fracs.append(_bit_diff_fraction(base, other))
    avg = sum(fracs) / len(fracs)
    assert 0.45 <= avg <= 0.55, f"multimap avalanche {avg:.4f} too far from 0.5"


def test_no_short_cycle_in_sample():
    # Guard against chaos-sync / short period: a 100 KB sample must not contain an obvious
    # short repeating block. (Independent maps shouldn't sync, but verify.)
    ks = MultiMapEngine(KEY, NONCE).keystream(100_000)
    for period in (16, 64, 256, 1024):
        assert ks[:period] != ks[period:2 * period], f"keystream repeats at period {period}"


def test_default_is_three_maps():
    assert MultiMapEngine(KEY, NONCE).n_maps == 3
