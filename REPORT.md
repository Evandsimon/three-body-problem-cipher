# REPORT — Adversarial Evaluation of the Three-Body Problem Cipher

**Date:** 2026-07-02 (updated to reflect current v3 design)  
**Subject:** Integer PWLCM stream cipher on M = 2¹²⁷−1, 4-map XOR combiner, auto-rekey ratchet,
hardened AEAD shell, fast Rust core.  
**Method:** Build the proposed design faithfully, then try to break it and measure it against
real standards. "Proven" = survived; "broken" = it didn't.

---

## TL;DR verdict

This is a **serious research artifact, not a toy.** The design has been attacked from 15 angles
and measured against real cryptographic standards. Every weakness found at small scale is
documented with what stops it at full scale. The honest bit-security estimate is ~254-bit
(the smallest credible attack cost).

**But it is still UNVETTED.** No outside cryptographer has reviewed it. The numbers are measured,
not proven. The two-locks deployment means even a total chaos break can't expose plaintext
(inner AES-256-GCM still holds), but that is a design claim, not a proven fact.

Three things this project gets right that most chaos ciphers don't:

1. **Integer math on a Mersenne prime grid** — cross-machine determinism actually works.
2. **Honest about structure** — the map is invertible and carries algebraic structure; the
   design acknowledges this and adds layers to defeat it, rather than pretending "chaos = magic."
3. **Slow, and admits it** — ~149× slower than AES-NI, so it ships as an outer wall over a
   vetted vault, never the only lock.

---

## Design summary (current v3, as of 2026-07-02)

| Component | v2 (original) | v3 (current) |
|-----------|--------------|--------------|
| Grid | M = 2⁶¹−1 | M = 2¹²⁷−1 |
| Maps | 3 | 4 |
| Output | Raw state XOR | Nonlinear ARX mixer + top-32 truncation |
| Keystream | Unlimited single orbit | 64 KiB epochs, re-keyed ratchet |
| Shell | Encrypt-then-MAC | CMT-4 key commitment + streaming + SIV + forward-secret sessions |
| Deployment | Chaos only | Two locks (chaos outer + AES-256-GCM inner) |
| Key exchange | Plain DH | Hybrid PQ (DH + ML-KEM-768, triple-DH + ML-DSA-65) |
| Implementation | Python only | Python reference + Rust core (~35× faster) |
| Attack battery | 4 scripts | 15 scripts |

---

## Results by category

### Correctness & determinism

| # | Test | Result | Verdict |
|---|------|--------|---------|
| 1 | Cross-machine determinism | 183 Python + 28 Rust tests pass; identical keystream on any CPU | ✅ Cross-machine sync works |
| 2 | Python ↔ Rust parity | 36 parity tests + 3,000-case differential fuzz, zero divergence | ✅ Bit-identical across implementations |

### Cryptanalysis

| # | Test | Result | Verdict |
|---|------|--------|---------|
| 3 | Two-time pad (nonce reuse) | C1⊕C2 = P1⊕P2, both plaintexts recovered | ⚠️ Nonces mandatory — universal to ALL stream ciphers (AES-GCM, ChaCha20, etc.) |
| 4 | Known-plaintext state recovery | Map is invertible; works at small scale. At full scale: state space ~2⁵⁰⁸, MITM ~2²⁵⁴ | ✅ Key-size-safe at full scale |
| 5 | Meet-in-the-middle (core cryptanalysis) | Generalized MITM at N=4 maps: ~2²⁵⁴ time AND memory | ✅ Infeasible |
| 6 | Differential analysis | Single-bit input diffs → output at noise floor; avalanche P∈[0.470,0.528] | ✅ No usable differential |
| 7 | Output filter attack | Top-32 ↔ hidden low-32 correlation at noise floor; preimage ~2³² candidates per step, XOR'd over 4 maps | ✅ Truncation wall holds |
| 8 | Period census | √M law holds (per-map ~2⁶², combined ~2²⁴⁷); 0 traps / 300 keys; 0/7 adversarial edges | ✅ No short cycles |

### Shell security

| # | Test | Result | Verdict |
|---|------|--------|---------|
| 9 | Key commitment (CMT-4) | Cross-key forgery needs HMAC-SHA256 collision (~2¹²⁸); birthday search confirms √N law | ✅ Survives |
| 10 | Streaming AEAD | Reorder, drop, duplicate, truncate all caught by per-chunk HMAC indexing | ✅ Survives |
| 11 | Nonce-misuse resistance (SIV) | Deterministic SIV: same plaintext → same ciphertext, but no two-time-pad on nonce reuse | ✅ Survives (different trade-off) |

### Forward secrecy

| # | Test | Result | Verdict |
|---|------|--------|---------|
| 12 | Ratchet forward secrecy | Capture live key at epoch C → read C onward, never 0..C-1; burned keys can't be recovered | ✅ Past messages safe |
| 13 | Ratchet AEAD session | Same, at message granularity; forward-secret chat sessions | ✅ Survives |

### Two-locks deployment

| # | Test | Result | Verdict |
|---|------|--------|---------|
| 14 | Total chaos break → plaintext? | Grant attacker the outer key → 0/67 wrong inner keys open the vault | ✅ Inner AES-256-GCM still holds |
| 15 | Key independence | HKDF-derived inner/outer keys: mean bit-diff 127.7/256 | ✅ Breaking outer key leaks nothing about inner |
| 16 | Forgery with known outer key | Attacker re-seals a tampered blob → outer accepts, inner catches the forgery | ✅ Inner lock is real, not redundant |

### Post-quantum key exchange

| # | Test | Result | Verdict |
|---|------|--------|---------|
| 17 | Hybrid confidentiality (DH + ML-KEM-768) | Break one primitive → other still holds (64/64 each side); avalanche 128.6/256 | ✅ Survives harvest-now-decrypt-later |
| 18 | Hybrid authentication (triple-DH + ML-DSA-65) | Grant total break of one auth leg → other still rejects impostor (6/6) | ✅ Must break BOTH to impersonate |

### Randomness

| # | Test | Result | Verdict |
|---|------|--------|---------|
| 19 | PractRand (shipped 4-map ratchet stream) | Clean through 128 MB; one chance-noise blip at 256 MB vanished at 512 MB | ✅ Clean |
| 20 | ent (64 MB) | 7.999997/8 bits/byte; serial corr −0.0001; Monte-Carlo π error 0% | ✅ Clean |
| 21 | NIST-lite | Monobit/runs/block-frequency pass across ~30 re-key seams | ✅ Clean |

### Constant-time

| # | Test | Result | Verdict |
|---|------|--------|---------|
| 22 | Branch timing | Branchless mask-select; measured 1.0% step-time spread across PWLCM regions | ✅ Branch leak closed |
| 23 | Divide timing | Barrett reciprocal in Rust; measured 0.41% spread across 128 secret keys | ✅ Divide leak closed |

### Speed

| # | Test | Result | Note |
|---|------|--------|------|
| 24 | Rust vs Python | ~61 MB/s vs ~1.7 MB/s | ~35× faster |
| 25 | Rust vs ChaCha20 | ~37× slower (2,272 MB/s) | Hardware-accelerated |
| 26 | Rust vs AES-NI | ~149× slower (9,082 MB/s) | Hardware-accelerated |

---

## Honest weaknesses (things that didn't survive)

1. **Nonce reuse is fatal** (two-time pad). Same as AES-GCM, ChaCha20-Poly1305, and every other stream cipher. The SIV mode mitigates this by making the ciphertext deterministic, but the honest fix is: don't reuse nonces.

2. **The map is invertible.** This is a structural property of PWLCM and cannot be removed — only mitigated. The mitigation layers (4-map XOR, frosted-glass mixer, top-32 truncation, ratchet) push the recovery cost to ~2²⁵⁴. That's the honest claim, not a proof.

3. **It's slow.** ~149× slower than AES-NI. The two-locks design acknowledges this: chaos is the sacrificial outer wall; the vetted inner vault handles the speed-critical path. A ~150× overhead on the outer layer is acceptable for the deployment model.

4. **No formal proof.** The bit-security claim is derived from structural analysis and measured attacks, not a reduction to a hard problem. This is true of most symmetric ciphers in their early stages.

---

## What would it take to trust this?

1. **External review** (Phase 7) — the only roadmap item left. Independent cryptographers need to try to break it and fail.
2. **A formal specification** — not just code, but a document defining every parameter and operation in mathematical language.
3. **Time** — real ciphers earn trust by surviving years of attack, not weeks.

---

## Bottom line

**A serious learning artifact and portfolio piece.** The design is clean, the self-attack is rigorous,
the honest framing is consistent. It demonstrates real cryptographic engineering — not because it
"beats" AES (it doesn't, and doesn't claim to), but because it knows exactly where it stands and
what it would take to move forward.

**Still UNVETTED. Do not protect real data with this.**
