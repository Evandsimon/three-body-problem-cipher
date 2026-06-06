# Chaos Cipher (Progress)

Last updated: 2026-06-06 | Branch: multi-map | Status: v3 multi-map proven (branch, pre-merge)

## 🎯 Goal
Build and **rigorously prove/disprove** a chaos-based stream cipher (integer PWLCM keystream)
as a research/learning project. "Prove it works" = try hard to break it and measure it against
real standards. Engine-first; any real application is deferred until the evidence justifies it
(and even then, only as a layer over a vetted primitive).

## ⏭️ NEXT
- [ ] **Merge `multi-map` → `main`** when ready (branch 1 proven; awaiting go-ahead).
- [ ] **Branch 2 — CTR-style seekable mode**: keystream addressable by counter for random-access.
- [ ] **Branch 3 — Key-exchange layer**: let Alice & Bob agree a key without pre-sharing.
- [ ] Install `ent` + `dieharder` (`brew install ent dieharder`) and run the full randomness battery on ≥100 MB.

✅ Branch 1 (combine multiple chaotic maps) — DONE, see below.

## What It Does
Pure-integer PWLCM (modulus `M = 2^61 - 1`) generates a deterministic, cross-machine keystream;
XOR encrypts. An AEAD shell (`aead.py`) wraps it with a fresh random nonce per message +
encrypt-then-MAC (HMAC-SHA256) so tampering/wrong-keys are rejected. Simple interface:
`seal(key, msg)` / `open_(key, blob)`.

## Stack
Python 3.14, stdlib only for the engine (no numpy). `pytest` for tests, `cryptography` for the
speed-benchmark baselines (AES-256-CTR, ChaCha20). Optional `ent`/`dieharder` via Homebrew.

## Repo / Deployment
- GitHub: **`Evansimon77/chaos-cipher`** (private). Local: `Projects/chaos-cipher/`.
- Not deployed anywhere — research artifact only.

## Architecture
- `engine.py` — chaotic core: PWLCM, weak-parameter rejection, `from_master()` hash KDF.
- `aead.py` — safe shell: `seal()`/`open_()`, random nonce, encrypt-then-MAC, AAD, constant-time verify.
- `tests/` — correctness, period (Brent), avalanche, AEAD auth.
- `attacks/` — two-time-pad break, known-plaintext state recovery (+ invertibility proof).
- `bench/` — NIST-lite randomness, `randomness.sh` (ent/dieharder), speed vs AES/ChaCha.
- `REPORT.md` — honest verdict. `README.md` — usage.

## Key Findings (see REPORT.md)
- ✅ Integer-math determinism (cross-machine sync) **works** — the one original claim that holds.
- ✅ Avalanche ≈ 0.5000; passes NIST-lite randomness screen; 18/18 tests green.
- ❌ "Unhackable / no-structure / quantum-proof" claims are **false**: map is invertible;
  two-time-pad breaks it on nonce reuse; weak-key class existed (now rejected).
- ⚠️ ~700–800× slower than AES/ChaCha. **Still UNVETTED** — not for real data.

## Recent Work

### ✅ DONE 2026-06-06: Branch 1 — multi-map (3 independent PWLCMs) — weak spot fixed & PROVEN
> Implemented the "three-body" idea as **3 independent PWLCM maps XOR-combined** (`multimap.py`,
> `MultiMapEngine`); `aead.py` `seal()/open_()` now uses it by default. Maps are independent
> (uncoupled) → hides each map's invertibility footprint + avoids chaos-sync. **Proof:**
> `attacks/known_plaintext.py` Part C re-runs the exact Part-B attack vs 3 maps — at M=2²⁰ and
> M=2²⁴ it can **no longer predict future keystream** (it broke the single map at those scales);
> naive joint brute-force ~2^159. 25/25 tests pass (new `test_multimap.py`; AEAD still green).
> Cost: 3-map ≈ 3.3× slower than 1-map (~0.8 MB/s). Still UNVETTED (beats *this* attack, not a
> proof). On branch `multi-map`, pre-merge. Decided against nesting/N>3 (cost+complexity+sync,
> no real gain past brute-force wall).

### ✅ DONE 2026-06-06: Decoupled tests from the "save" command
> Clarified the workflow per user: **save = exactly three steps** (commit+push → Obsidian log →
> PROGRESS.md update). Running `pytest` is now a **separate** action, done only on request or when
> verifying work on its own — never bundled into or gating `save`. Updated project `CLAUDE.md` +
> the `chaos-cipher-save-workflow` memory.

### ✅ DONE 2026-06-06: v2 AEAD shell + GitHub + three-pillar workflow
> Added weak-parameter **rejection** (`MIN_P` band) + `from_master()` hash KDF (no weak key
> reachable; the old `key=1,ctrl=1`→period-1 collapse is gone). Added **authentication** via a
> `seal()`/`open_()` AEAD shell (`aead.py`): fresh random nonce per message (kills two-time-pad
> in practice) + encrypt-then-MAC (HMAC-SHA256), constant-time verify, AAD binding. 18/18 tests
> pass (10 new in `test_aead.py`: tamper/truncation/wrong-key/AAD all rejected). Pushed to private
> repo `Evansimon77/chaos-cipher`; folder renamed `chaos-engine`→`chaos-cipher`. Established the
> GitHub/Obsidian/PROGRESS three-pillar workflow + the "save" command.

### ✅ DONE 2026-06-06: v1 engine + adversarial harness + honest REPORT
> Built faithful pure-integer PWLCM cipher + full attack/test harness (period via Brent,
> avalanche, NIST-lite, two-time-pad, known-plaintext state recovery, speed bench). Verdict in
> `REPORT.md`: the core idea synchronizes across machines, but the strong "unhackable" claims
> don't survive contact with real attacks. Decision: engine-first, app deferred, evidence-driven.
