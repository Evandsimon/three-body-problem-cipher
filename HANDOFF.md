# HANDOFF — chaos-cipher · 2026-06-29
project: /Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher

## Resume in one move
Start building **Phase 4 Stage B**: replace the Stage-A big-int division in `rust/src/lib.rs`
(`fn div_step`, currently `ruint` U256) with a hand-rolled **constant-time precomputed reciprocal**
(Möller-Granlund 2-by-1). First action: open `rust/src/lib.rs` and read `div_step` + `next_state`.

## Goal
Make the chaos cipher fast enough to be usable (the speed blocker) AND constant-time, by porting the
hot loop to Rust. The cipher stays an UNVETTED research artifact — never used on real data; the eventual
deployment is only as the OUTER wall over a vetted vault ("Option B"). Standing directive: best/most
secure version, not whatever's easiest. Every roadmap item is BUILT **and** attacked/measured.

## State
- **Done:** Phases 0–3 complete. Phase 4 **Stage A** complete + saved (commit `55309fa`): `rust/`
  crate (`chaos_core`) ports the per-byte engine — init avalanche, PWLCM step, `finalize` mixer,
  4-byte output buffer. **Bit-identical to the frozen KAT** (3/3 `engine_raw` vectors incl. all-zero-key
  edge + max-ish) and **~43× faster** (74.3 vs 1.74 MB/s). 88/88 Python tests pass.
- **In flight:** nothing half-edited — Stage A was saved at a clean stop. The PWLCM step is ALREADY
  written in the Stage-B shape: ONE division per step (`div_step(num, den)`) on a constant-time-masked
  numerator/divisor select (`next_state` in `rust/src/lib.rs`). Stage B only swaps the *guts* of
  `div_step` — the call site doesn't change.
- **Blocked / open:** the divide-by-secret **timing leak #2 is still OPEN** by design — Stage A still
  divides by the secret (same status as Python). Stage B is exactly where it closes.

## Next steps
1. Implement a constant-time `div_step(num, den)` = `floor(M*num/den)` with NO hardware divide on the
   secret in the hot loop. Algorithm: Möller-Granlund "Improved division by invariant integers" —
   normalize the divisor, precompute a 128-bit reciprocal ONCE at key setup (per `p` and per `HALF-p`),
   then per-step do a 2-by-1 division (multiply-high + small correction). Precondition holds: `num <= den`
   for the selected candidate, so quotient < ~2M < 2^128.
2. **Verify hard before trusting it:** add a Rust test that compares the new `div_step` against `ruint`
   (keep ruint as a reference ORACLE) over millions of random `(num, den)` pairs with `num <= den`.
3. Re-run `cargo test --release` (incl. existing `div_step_invariant_holds`) and the KAT parity:
   `python3 -m pytest tests/test_rust_parity.py -v` — must stay bit-identical.
4. Re-benchmark (`chaos_core bench 64`) to confirm more speed once `ruint` is out of the hot loop.
5. Update `CONSTANT_TIME.md` (mark the divide leak CLOSED, with the new timing measurement) and
   `THREAT_MODEL.md` §4. Then `/save`.
6. Later in Phase 4: parallel maps + CTR; port multimap/ratchet (needs SHA-512/HMAC in Rust) and extend
   KAT parity to those layers; differential fuzz Rust==KAT; benchmark vs AES/ChaCha.

## Key files
- `PROGRESS.md` — living compass; read first. Roadmap + dated DONE log (newest = Phase 4 Stage A).
- `rust/src/lib.rs` — the Rust core. `div_step` (the thing to replace), `next_state` (the masked select),
  `finalize`, `ChaosEngine::new` (init avalanche). Constants M/HALF/MIN_P/DEAD_STATE_FIX mirror engine.py.
- `rust/src/main.rs` — CLI: `chaos_core ks <seed> <control> <nonce> <n>` (hex out) and `chaos_core bench <MB>`.
- `engine.py` — the Python reference the Rust port must match (PWLCM + finalize + init avalanche).
- `kat/vectors.json` — frozen known-answer vectors (the contract). `kat/generate_kat.py` regenerates with `--write`.
- `tests/test_rust_parity.py` — runs the Rust binary vs the KAT; auto-skips if the binary isn't built.
- `tests/test_kat.py` — Python-side KAT regression guard.
- `CONSTANT_TIME.md`, `THREAT_MODEL.md` — the Phase-3 contract docs to update after Stage B.

## Don't-trip wires
- **Rust is NOT on PATH** (installed with `--no-modify-path`). Prefix every cargo/rust command with
  `. "$HOME/.cargo/env" &&`. Rust 1.96, toolchain at `~/.cargo` + `~/.rustup`.
- **`rust/target/` is gitignored** (large). `Cargo.lock` IS committed (reproducible builds). Tracked rust
  files: `Cargo.toml`, `Cargo.lock`, `src/lib.rs`, `src/main.rs`.
- **`docs/` is gitignored** — it holds a real Spanish N.I.E. Never put specs/output there; never commit it.
- **`/save` guard:** KAT material trips the secret-scanner (high-entropy hex, fields named "key"). Already
  allowlisted: `kat/vectors.json` in `~/.claude/skills/save/gitleaks.toml`, and a `# gitleaks:allow` on the
  `_KEY_INT` line in `kat/generate_kat.py`. If you add new KAT files, expect the same and allowlist them.
- **Only the SELECTED PWLCM candidate must be correct** — off-region candidates are masked to 0, so
  `div_step`'s `num <= den` precondition only needs to hold for the selected one (it always does). Don't
  "fix" the wrapping_sub in `next_state` — the wraps are intentional and harmless (multiplied by mask 0).
- **`finalize(0) == 0`** and one KAT finalize input folds to exactly 0 (`z ^ (z>>64)` cancels) — that's a
  real, correct answer, not a bug.
- Tests are NOT part of `/save` here — run pytest separately.

## Run / verify
```bash
. "$HOME/.cargo/env"
cd "/Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher/rust"
cargo build --release && cargo test --release        # Rust unit tests
cd ..
python3 -m pytest tests/ -q                           # full Python suite (88 pass; parity needs the build)
rust/target/release/chaos_core bench 64               # throughput (Stage A: ~74 MB/s)
# KAT parity (the correctness gate):
python3 -m pytest tests/test_rust_parity.py -v        # must be bit-identical, 3/3
```
