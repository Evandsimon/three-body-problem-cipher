"""Tests for the forward-secret session AEAD (item A wired into the shell).

Covers the ordinary AEAD guarantees per message PLUS the forward-secrecy behaviour: a session that
has advanced past a message has burned its key and cannot reopen it.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from aead import InvalidTag  # noqa: E402
from ratchet_aead import ReceiverSession, SenderSession  # noqa: E402

MASTER = b"a forward-secret session master key!!"
NONCE = b"session-nonce-aaaa"
CONVO = [b"hello", b"the package is in locker 12", b"", b"code is 4471", b"x" * 500]


def _sender():
    return SenderSession(MASTER, NONCE)


def _receiver():
    return ReceiverSession(MASTER, NONCE)


def test_session_roundtrip_in_order():
    s, r = _sender(), _receiver()
    for m in CONVO:
        assert r.open(s.seal(m)) == m


def test_wrong_master_key_rejected():
    s = _sender()
    wire = s.seal(b"secret")
    bad = ReceiverSession(b"the wrong master key................", NONCE)
    with pytest.raises(InvalidTag):
        bad.open(wire)


def test_wrong_nonce_rejected():
    s = _sender()
    wire = s.seal(b"secret")
    bad = ReceiverSession(MASTER, b"a-different-nonce")
    with pytest.raises(InvalidTag):
        bad.open(wire)


def test_tamper_ciphertext_rejected():
    s, r = _sender(), _receiver()
    wire = bytearray(s.seal(b"the quick brown fox jumps"))
    wire[-1] ^= 0x01                       # flip a tag bit
    with pytest.raises(InvalidTag):
        r.open(bytes(wire))


def test_tamper_wire_index_rejected():
    # The index is sealed into the inner aad; changing it on the wire must fail to open.
    s, r = _sender(), _receiver()
    wire = bytearray(s.seal(b"first message"))
    wire[7] ^= 0x01                        # bump the 8-byte index from 0 to 1
    with pytest.raises((InvalidTag, ValueError)):
        r.open(bytes(wire))


def test_forward_secrecy_past_message_unrecoverable():
    s, r = _sender(), _receiver()
    wires = [s.seal(m) for m in CONVO[:3]]
    r.open(wires[0])
    r.open(wires[1])                       # receiver now poised at index 2; keys 0 and 1 burned
    with pytest.raises(ValueError):
        r.open(wires[0])                   # cannot go back — forward secrecy
    with pytest.raises(ValueError):
        r.open(wires[1])


def test_gap_tolerated_but_skipped_then_unrecoverable():
    s, r = _sender(), _receiver()
    wires = [s.seal(m) for m in CONVO[:3]]
    assert r.open(wires[0]) == CONVO[0]
    assert r.open(wires[2]) == CONVO[2]    # skip index 1: receiver fast-forwards (burns link 1)
    with pytest.raises(ValueError):
        r.open(wires[1])                   # the skipped message is now unrecoverable


def test_aad_carried_by_session():
    s = SenderSession(MASTER, NONCE, aad=b"channel-7")
    r_ok = ReceiverSession(MASTER, NONCE, aad=b"channel-7")
    r_bad = ReceiverSession(MASTER, NONCE, aad=b"channel-9")
    wire = s.seal(b"bound to the channel")
    # A receiver with a different session aad derives the same chain but the inner aad won't match.
    with pytest.raises(InvalidTag):
        r_bad.open(wire)
    assert r_ok.open(wire) == b"bound to the channel"


def test_fresh_receiver_still_has_master():
    # Forward secrecy protects the SESSION STATE, not the master key: a brand-new receiver built from
    # the same master can of course read message 0 (it has not burned anything yet).
    s = _sender()
    wire = s.seal(b"readable by a fresh session")
    assert _receiver().open(wire) == b"readable by a fresh session"
