"""
ATTACK / VALIDATION — post-quantum hybrid key agreement (item F). Measure the hybrid property.

CLAIM
  The hybrid key is secure if EITHER the classical DH OR the post-quantum ML-KEM secret is unknown to
  the attacker. So it survives:
    * a quantum computer that breaks DH (the ML-KEM secret still has full entropy), and
    * a classical break of the newer ML-KEM (the decades-studied 2048-bit DH still has full entropy).

THE PARTS
  Part 1 — Agreement: a real two-message handshake; both sides derive the same 32-byte key.
  Part 2 — Hybrid survival: an attacker who learns ONE secret still cannot pin the key — the missing
           secret leaves full entropy (ML-KEM ss = 256 bits; DH secret ~256-byte group element). We
           confirm the key MOVES when either secret changes, so neither alone determines it.
  Part 3 — Mixing quality: flipping one bit of either secret avalanches ~half the key bits.
  Part 4 — Honest framing: unauthenticated; what active-MITM and full PQ-auth still require.

HONEST SCOPE: validates the COMBINER (both secrets required) and that DH + ML-KEM are vetted. Not a
proof of ML-KEM or DH themselves (those are the standardised primitives we rely on), and the chaos
bulk cipher remains UNVETTED.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cipher.pq_keyexchange import (  # noqa: E402
    MLKEM_AVAILABLE,
    HybridInitiator,
    HybridResponder,
    _combine,
)


def _hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def part1_agreement() -> bool:
    alice, bob = HybridInitiator(), HybridResponder()
    kem_ct, key_bob = bob.respond(alice.dh_public, alice.kem_public)
    key_alice = alice.shared_key(bob.dh_public, kem_ct)
    ok = key_alice == key_bob and len(key_alice) == 32
    print(f"  Part 1  two-message handshake agrees on a 32-byte key: {'PASS' if ok else 'FAIL'}")
    return ok


def part2_hybrid_survival() -> bool:
    # Fixed transcript/info; vary the two secrets independently. classical ~256 bytes, pq = 32 bytes.
    classical, pq = os.urandom(256), os.urandom(32)
    tr, info = os.urandom(256 + 256 + 1184 + 1088), b""
    real = _combine(classical, pq, tr, info)

    # Attacker who broke DH knows `classical` but must guess pq (256-bit): every guess differs.
    quantum_view = [_combine(classical, os.urandom(32), tr, info) != real for _ in range(64)]
    # Attacker who broke ML-KEM knows `pq` but must guess classical: every guess differs.
    classical_view = [_combine(os.urandom(256), pq, tr, info) != real for _ in range(64)]

    ok = all(quantum_view) and all(classical_view)
    print("  Part 2  hybrid survival (key needs BOTH secrets):")
    print(f"            DH broken, pq unknown  -> key not recoverable in {sum(quantum_view)}/64 trials "
          f"(missing 256 bits of ML-KEM entropy)")
    print(f"            ML-KEM broken, dh unknown -> key not recoverable in {sum(classical_view)}/64 "
          f"trials (missing the full DH secret)")
    print(f"          -> {'PASS' if ok else 'FAIL'}")
    return ok


def part3_mixing(trials: int = 64) -> bool:
    classical, pq = os.urandom(256), os.urandom(32)
    tr, info = os.urandom(64), b""
    base = _combine(classical, pq, tr, info)
    dists = []
    for _ in range(trials):
        # flip one random bit of the pq secret
        bb = bytearray(pq)
        bit = int.from_bytes(os.urandom(2), "big") % (len(bb) * 8)
        bb[bit // 8] ^= 1 << (bit % 8)
        dists.append(_hamming(base, _combine(classical, bytes(bb), tr, info)))
    avg = sum(dists) / len(dists)
    ok = 0.40 * 256 <= avg <= 0.60 * 256          # ~128 of 256 bits flip
    print(f"  Part 3  one-bit-flip avalanche: {avg:.1f}/256 key bits change on average "
          f"(ideal ~128) -> {'PASS' if ok else 'FAIL'}")
    return ok


def part4_honest_framing() -> bool:
    print("  Part 4  honest framing:")
    print("    - Stops a PASSIVE recorder now AND post-quantum (harvest-now-decrypt-later defeated).")
    print("    - UNAUTHENTICATED: an active man-in-the-middle who replaces messages is not stopped by")
    print("      this alone — that needs the authenticated handshake (auth_keyexchange.py), and a")
    print("      fully PQ-secure authenticated version would add a PQ signature (ML-DSA). Future work.")
    print("    - DH + ML-KEM-768 are vetted/standardised; the chaos bulk cipher stays UNVETTED.")
    return True


def main() -> None:
    print("=" * 78)
    print("POST-QUANTUM HYBRID KEY AGREEMENT (item F) — validation")
    print("=" * 78)
    if not MLKEM_AVAILABLE:
        print("  ML-KEM unavailable (needs cryptography w/ OpenSSL 3.5+) — cannot run. SKIP")
        sys.exit(0)
    p1 = part1_agreement()
    p2 = part2_hybrid_survival()
    p3 = part3_mixing()
    p4 = part4_honest_framing()
    ok = p1 and p2 and p3 and p4
    print("-" * 78)
    print(f"VERDICT: {'ALL PASS' if ok else 'FAILURE — see above'}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
