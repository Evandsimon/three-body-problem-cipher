"""
commit.py — key-commitment for the chaos AEAD shells (#6). RESEARCH ARTIFACT.

THE PROBLEM IT SOLVES
---------------------
A normal AEAD promises two things: a ciphertext opens under the RIGHT key, and tampering is
caught. It does NOT, by itself, promise that a ciphertext opens under only ONE key. For the two
most popular AEADs — AES-GCM and ChaCha20-Poly1305 — that gap is real and has been exploited: an
attacker can craft a SINGLE ciphertext that decrypts cleanly to "pay $10" under Alice's key and to
"pay $10,000" under Bob's key, and BOTH pass the integrity tag. (Their tags use a polynomial /
universal-hash MAC whose key an attacker can solve for.) This breaks any system that assumes a
ciphertext means one fixed thing: abuse-report franking, key-rotation, multi-recipient envelopes,
password-protected archives, "tag = filename" content stores.

A KEY-COMMITTING AEAD closes the gap: it is infeasible to find a single blob that opens under two
different keys. We target CMT-4 (the strongest level): the commitment binds the KEY, the per-message
salt (the random nonce or the synthetic SIV), and the AAD together.

WHERE WE ALREADY STAND (honest)
-------------------------------
Both shells authenticate with HMAC-SHA256, which — unlike GHASH (GCM) or Poly1305 — is a
*committing* MAC, so we very likely already avoid the headline attack. But "very likely" is not
"proven". This module adds an EXPLICIT, collision-resistant commitment so the property holds plainly
and independently of any subtlety in how the MAC key is derived — belt and suspenders, the
recommended fix (Bellare–Hoang, "Efficient Schemes for Committing AE"; Albertini et al., "How to
Abuse and Fix Authenticated Encryption Without Key Commitment", USENIX 2022).

THE CONSTRUCTION
----------------
    K_c = HMAC(master_key, "...|commit-key|v1")        # a dedicated, domain-separated subkey
    C   = HMAC(K_c, salt || len(aad)||aad)             # 32-byte commitment, bound to salt + aad

To make a blob open under a second key k2, an attacker needs C recomputed under k2 to equal the
stored C — an HMAC-SHA256 collision across different keys (~2^128 work by the birthday bound). That
is infeasible. The commitment is verified in constant time on open, alongside the existing tag.

STILL UNVETTED. This adds a real, standard security property to the SHELL; it does not make the
underlying chaos keystream proven-secure. See REPORT.md / THREAT_MODEL.md.
"""
from __future__ import annotations

import hashlib
import hmac

COMMIT_LEN = 32                                  # HMAC-SHA256 output
_COMMIT_KEY_INFO = b"chaos-pwlcm-v1|commit-key|v1"


def key_commitment(master_key: bytes, salt: bytes, aad: bytes) -> bytes:
    """A 32-byte value that binds the master key to (salt, aad).

    Collision-resistant in the key: two different master keys cannot produce the same commitment
    without an HMAC-SHA256 collision (~2^128 work). `salt` is the per-message public value the shell
    already holds — the random nonce (aead.py) or the synthetic IV (siv.py). The aad is
    length-prefixed so an attacker cannot slide the salt|aad boundary."""
    k_c = hmac.new(bytes(master_key), _COMMIT_KEY_INFO, hashlib.sha256).digest()
    m = hmac.new(k_c, digestmod=hashlib.sha256)
    m.update(salt)
    m.update(len(aad).to_bytes(8, "big"))
    m.update(aad)
    return m.digest()


def verify_commitment(master_key: bytes, salt: bytes, aad: bytes, commitment: bytes) -> bool:
    """Recompute the commitment and constant-time compare. True iff `commitment` was produced by
    this master key over (salt, aad)."""
    expected = key_commitment(master_key, salt, aad)
    return hmac.compare_digest(expected, commitment)
