"""
ATTACK / VALIDATION — two locks ("Option B", Phase 6). Measure the guarantee, don't assert it.

THE GUARANTEE WE CLAIM
  The data is wrapped in two independent locks: a VETTED inner vault (AES-256-GCM) inside our
  UNVETTED chaos outer wall. The claim is the whole reason the project exists:

      Even if the chaos cipher is COMPLETELY broken, the plaintext is still fully protected,
      because what's underneath the broken wall is AES-256-GCM.

  So we don't argue "the chaos is secure". We grant the attacker the strongest possible chaos
  break and show the data survives anyway.

THE PARTS (each one a thing an attacker actually tries)
  Part 1 — HEADLINE: hand the attacker the OUTER key (chaos fully broken). They peel the chaos wall
           clean off. Show they're then stuck against AES-256-GCM with no inner key — the plaintext
           is not recoverable; only the legitimate inner key opens the vault.
  Part 2 — The inner lock is REAL, not redundant: still holding the outer key, the attacker tampers
           the protected data and re-seals a perfectly valid outer layer over it. The outer tag
           passes — and the inner AES-GCM tag catches the forgery. We also show the outer-alone
           would have accepted it, proving the inner lock did the catching.
  Part 3 — Key separation, MEASURED: the two locks never share a key; the inner and outer keys look
           independent (≈half their bits differ), and breaking the outer key tells you nothing about
           the inner one (HKDF is one-way).
  Part 4 — Ordinary attacker (no keys): tamper / wrong-key are rejected, both inner ciphers.
  Part 5 — Honest framing of what this does and does not prove.

HONEST SCOPE: this validates the DEPLOYMENT design — that an unvetted outer wall cannot endanger
data sitting behind a vetted inner vault. It does NOT prove the chaos math is secure (it stays
UNVETTED). That is exactly the point: the design is built so the chaos math doesn't have to be.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aead  # noqa: E402
from cryptography.exceptions import InvalidTag as CryptoInvalidTag  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from twolock import (  # noqa: E402
    INNER_NONCE_LEN,
    InvalidTag,
    _derive_keys,
    open_twolock,
    seal_twolock,
)

MSG = b"Wire $4,000,000 to account #7781-44 by 5pm. -- the board"


def _popcount_diff(a: bytes, b: bytes) -> int:
    """Number of differing bits between two equal-length byte strings."""
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def part1_chaos_fully_broken() -> bool:
    """Grant the attacker the outer key (worst case: chaos cipher completely defeated). They peel the
    chaos wall — and hit AES-256-GCM with no inner key. The plaintext must NOT be recoverable."""
    master = b"the-clients-real-master-key"
    aad = b"record:patient-7781"
    blob = seal_twolock(master, MSG, aad=aad, inner="aes-256-gcm")

    k_outer, k_inner = _derive_keys(master)  # the attacker has k_outer; k_inner is the secret vault key

    # 1) Attacker uses the (assumed-broken) chaos to strip the outer wall entirely.
    inner_blob = aead.open_(k_outer, blob, aad=aad)
    inner_nonce = inner_blob[1:1 + INNER_NONCE_LEN]
    inner_ct = inner_blob[1 + INNER_NONCE_LEN:]

    # 2) The plaintext is NOT sitting in the recovered bytes — it's still AES-encrypted.
    leaked = MSG in inner_blob

    # 3) Without the inner key, AES-256-GCM does not open. Try a batch of wrong inner keys.
    wrong_opens = 0
    guesses = [os.urandom(32) for _ in range(64)] + [k_outer, b"\x00" * 32, k_inner[:-1] + b"\x00"]
    for g in guesses:
        try:
            AESGCM(g).decrypt(inner_nonce, inner_ct, aad)
            wrong_opens += 1   # a wrong key opened the vault -> catastrophic
        except CryptoInvalidTag:
            pass

    # 4) Sanity: the LEGITIMATE inner key (which the attacker does not have) does open it.
    legit = AESGCM(k_inner).decrypt(inner_nonce, inner_ct, aad) == MSG

    ok = (not leaked) and wrong_opens == 0 and legit
    print("  Part 1  HEADLINE — chaos wall granted fully broken (attacker holds the outer key):")
    print(f"    outer wall peeled; plaintext present in recovered bytes? {leaked} (must be False)")
    print(f"    AES-256-GCM vault opened by a wrong inner key: {wrong_opens}/{len(guesses)} (must be 0)")
    print(f"    only the legitimate inner key opens the vault: {legit}")
    print(f"    => chaos break leaves the attacker facing AES-256-GCM (~2^128). data safe. "
          f"{'PASS' if ok else 'FAIL'}")
    return ok


def part2_inner_lock_is_real() -> bool:
    """Attacker still holds the outer key. They tamper the data and forge a VALID outer layer over it.
    The outer tag passes; the inner vetted lock must catch the forgery. Prove the inner did the work
    by showing the outer-alone would have accepted the same forged blob."""
    master = b"another-master-key-entirely"
    aad = b"ctx"
    blob = seal_twolock(master, MSG, aad=aad)
    k_outer, _k_inner = _derive_keys(master)

    # Peel, tamper the inner ciphertext, re-seal a perfectly valid outer layer (attacker knows k_outer).
    inner_blob = bytearray(aead.open_(k_outer, blob, aad=aad))
    inner_blob[-1] ^= 0x01                      # flip one bit of the AES-GCM ciphertext+tag
    forged = aead.seal(k_outer, bytes(inner_blob), aad=aad)

    # The OUTER lock alone accepts the forgery (its tag is genuinely valid) ...
    outer_accepts = aead.open_(k_outer, forged, aad=aad) == bytes(inner_blob)
    # ... but the full two-lock open must REJECT it, because the inner AES-GCM tag fails.
    rejected = False
    try:
        open_twolock(master, forged, aad=aad)
    except InvalidTag:
        rejected = True

    ok = outer_accepts and rejected
    print("  Part 2  inner lock is a REAL second lock (not redundant):")
    print(f"    forged blob with a valid outer tag accepted by outer-alone: {outer_accepts}")
    print(f"    full two-lock open rejects it (inner AES-GCM catches the tamper): {rejected}")
    print(f"    => the inner vault independently caught a forgery the outer waved through. "
          f"{'PASS' if ok else 'FAIL'}")
    return ok


def part3_key_separation(trials: int = 2000) -> bool:
    """The two locks never share a key, and the keys look independent. Measure (a) inner != outer
    always, (b) mean bit-difference between inner and outer ≈ 128/256, (c) a one-bit master change
    avalanches both derived keys ≈ half their bits — so the outer key reveals nothing about the inner."""
    same = 0
    cross = []            # bit-distance between k_outer and k_inner for the same master
    aval_outer, aval_inner = [], []
    for _ in range(trials):
        m = os.urandom(32)
        ko, ki = _derive_keys(m)
        if ko == ki:
            same += 1
        cross.append(_popcount_diff(ko, ki))
        m2 = bytearray(m)
        m2[0] ^= 0x01                              # flip one bit of the master
        ko2, ki2 = _derive_keys(bytes(m2))
        aval_outer.append(_popcount_diff(ko, ko2))
        aval_inner.append(_popcount_diff(ki, ki2))

    mean_cross = sum(cross) / len(cross)
    mean_ao = sum(aval_outer) / len(aval_outer)
    mean_ai = sum(aval_inner) / len(aval_inner)
    # 256-bit keys: independent randoms differ in ~128 bits. Accept a tight band around 128.
    ok = same == 0 and 120 <= mean_cross <= 136 and 120 <= mean_ao <= 136 and 120 <= mean_ai <= 136
    print(f"  Part 3  key separation over {trials} random masters:")
    print(f"    inner key ever equals outer key: {same} (must be 0)")
    print(f"    mean bit-difference inner vs outer: {mean_cross:.1f}/256 (independent ≈ 128)")
    print(f"    one-bit master flip avalanches outer {mean_ao:.1f}/256, inner {mean_ai:.1f}/256")
    print(f"    => keys are independent; breaking the outer key leaks nothing about the inner. "
          f"{'PASS' if ok else 'FAIL'}")
    return ok


def part4_ordinary_attacker() -> bool:
    """No keys at all: tamper anywhere and wrong-key must be rejected, for both inner ciphers."""
    master = b"yet-another-master"
    aad = b"envelope"
    rejected = 0
    checks = 0
    for inner in ("aes-256-gcm", "chacha20-poly1305"):
        blob = seal_twolock(master, MSG, aad=aad, inner=inner)
        # legit open works
        assert open_twolock(master, blob, aad=aad) == MSG
        # tamper several positions
        for pos in (0, len(blob) // 2, len(blob) - 1):
            bad = bytearray(blob)
            bad[pos] ^= 0x80
            checks += 1
            try:
                open_twolock(master, bytes(bad), aad=aad)
            except InvalidTag:
                rejected += 1
        # wrong key
        checks += 1
        try:
            open_twolock(b"completely-different-master", blob, aad=aad)
        except InvalidTag:
            rejected += 1
        # wrong aad
        checks += 1
        try:
            open_twolock(master, blob, aad=b"different-context")
        except InvalidTag:
            rejected += 1

    ok = rejected == checks
    print(f"  Part 4  ordinary attacker (no keys): {rejected}/{checks} tamper/wrong-key/wrong-aad "
          f"rejected across both inner ciphers -> {'PASS' if ok else 'FAIL'}")
    return ok


def part5_honest_framing() -> bool:
    print("  Part 5  honest framing:")
    print("    - This proves the DEPLOYMENT is safe: an unvetted outer wall cannot endanger data that")
    print("      sits behind a vetted inner vault (AES-256-GCM). Confidentiality + integrity rest on")
    print("      the vetted lock; the chaos lock is a sacrificial, exposed extra barrier.")
    print("    - It does NOT prove the chaos keystream is secure — it stays UNVETTED. The design is")
    print("      built precisely so the chaos math never has to be trusted on its own.")
    return True


def main() -> None:
    print("=" * 78)
    print("TWO LOCKS (Option B, Phase 6) — validation")
    print("=" * 78)
    results = [
        part1_chaos_fully_broken(),
        part2_inner_lock_is_real(),
        part3_key_separation(),
        part4_ordinary_attacker(),
        part5_honest_framing(),
    ]
    print("-" * 78)
    ok = all(results)
    print(f"VERDICT: {'ALL PASS' if ok else 'FAILURE — see above'}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
