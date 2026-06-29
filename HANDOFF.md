# HANDOFF — chaos-cipher · 2026-06-29
project: /Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher

## Resume in one move
Start **Phase 8.6 — port the AUTHENTICATED post-quantum handshake to Rust** (`auth_pq_keyexchange.py`).
This is the LAST port. Working tree is clean and everything is saved/pushed on branch `phase6-two-locks`
(8.5 = commit `ac0fa4a`). First confirm green with the "Run / verify" block, then build 8.6 the same way
8.1–8.5 were built (port → KAT vector → parity + interop → full verify, zero new clippy).

## Goal
Build the most-secure version of an UNVETTED research chaos stream cipher, deployed only as the OUTER
wall over a vetted vault ("Option B"). Standing rule: best/most-secure path, never the easy one; every
feature is BUILT **and** attacked/measured. The user wants the system **complete, extensible, and fast**,
and asked to implement ALL the remaining technologies. Current big effort: **Phase 8 — finish the fast
Rust core so it mirrors every Python capability**, in value-order. After 8.6, Phase 7 (external review)
is the only roadmap item left.

## State
- **Saved & pushed (branch `phase6-two-locks`):**
  - Phase 6 two-locks (`twolock.py`) — `912202c`/`e9a4fb6`. Authenticated PQ handshake in **Python**
    (`auth_pq_keyexchange.py`) — `93b63bc` (this is the module 8.6 ports to Rust).
  - **Phase 8.1** AEAD + **8.2** streaming AEAD — `ff9ab1e`. **8.3** ratchet session AEAD — `5057d54`.
    **8.4** two-locks wrapper — `d4994b6`.
  - **Phase 8.5 key agreement** — code commit **`ac0fa4a`**, docs commit follows. Classical 2048-bit DH
    (reuses `ruint`, byte-identical to Python `pow`) + ML-KEM-768 hybrid handshake (new vetted crate
    `ml-kem`, default features only — NO getrandom, caller owns all randomness). Lib: `dh_public`/
    `dh_raw_shared`/`dh_shared_key`, `mlkem_ek_from_seed`/`mlkem_encapsulate`/`mlkem_decapsulate`,
    `hybrid_combine`/`hybrid_respond`/`hybrid_initiator_key`. 9 new CLI modes. KAT vectors **11
    keyexchange + 12 pq_hybrid**. Parity + interop both directions.
- **In flight:** nothing half-edited. Clean stop right after the save. **Next concrete task = 8.6.**
- **Verified at save:** Rust **17/17**; Python suite **176**; parity/kat/fuzz **34**; all 6 attack scripts
  PASS; ruff clean; **zero NEW clippy** (only the 2 documented cosmetic notes at lib.rs:149 + main.rs:21);
  KAT diff proved only the two new blocks were added (every keystream vector byte-identical → contract
  intact); Python↔Rust interop works for DH, ML-KEM, and the full hybrid handshake (both directions).
- **Blocked / open:** none technical. The cipher stays UNVETTED by design (Phase 7 = external review).

## Next steps (Phase 8 remaining)
1. **8.6 authenticated PQ handshake** — port `auth_pq_keyexchange.py` to Rust. It adds AUTHENTICATION on
   top of 8.5's confidentiality: hybrid auth = triple-DH static-key binding AND ML-DSA-65 signatures (so a
   man-in-the-middle is caught, not just a passive eavesdropper). Needs an **ML-DSA crate** — RustCrypto
   `ml-dsa` (the sibling of the `ml-kem` crate just added; check it's FIPS 204 final and that its keygen-
   from-seed / sign match Python's `cryptography` OpenSSL ML-DSA-65 the same way `ml-kem` did). Determinism
   for the KAT: ML-DSA signing CAN be deterministic (hedged vs deterministic mode) — pin it; ML-DSA keygen
   is seed-deterministic like ML-KEM. Add KAT vector 13, CLI modes, parity + interop. Completeness, not
   speed (handshakes run once per session). Then Phase 7 (external review) is the only roadmap item left.

## Key files
- `PROGRESS.md` — living compass; read first. Roadmap + dated DONE log folded into the top status line
  (newest = Phase 8.5).
- `rust/src/lib.rs` — Rust core. Sections in order near the end: aead / stream / ratchet_aead / twolock /
  **key agreement (8.5)**, then `#[cfg(test)] mod tests`. 8.6 goes in a new "authenticated handshake"
  section after key agreement; mirror the 8.5 layout (deterministic fns, caller owns randomness).
- `rust/src/main.rs` — CLI bridge; add new modes here (pattern: parse hex args → call lib → print hex).
  The 8.5 `dh_*`/`mlkem_*`/`hybrid_*` arms are the latest template.
- `rust/Cargo.toml` — deps. 8.5 added `ml-kem` (features = ["zeroize"], default features = no getrandom).
  8.6 adds an ML-DSA crate the same way.
- `kat/generate_kat.py` — recomputes ALL KAT vectors; add the new vector here, then regenerate with
  `python3 kat/generate_kat.py --write`. The docstring "covered" list goes 1–12 now (keyexchange = 11,
  pq_hybrid = 12); add 13 for the authenticated handshake. NOTE the 8.5 pattern: ML-KEM encaps is
  randomised in Python, so the ciphertext is a FROZEN constant in this generator (self-checked when the
  ML-KEM backend is present). ML-DSA signing can be made deterministic, so 8.6 may not need that trick —
  pin the signing randomness if the crate/Python API allow it; otherwise freeze the signature like the ct.
- `kat/vectors.json` — frozen contract. Keystream blocks must stay byte-identical when you add a new one.
- `tests/test_rust_parity.py` — add parity + Python↔Rust interop tests for each ported layer. The 8.5
  block at the end (DH, mlkem_decapsulate, hybrid_combine + the two `@_needs_mlkem` interop tests) is the
  latest template; reuse the `_needs_mlkem` skip pattern for an `_needs_mldsa` gate.
- Python sources being ported: all DONE through `auth_pq_keyexchange.py` is the ONLY remaining one (8.6).
- `THREAT_MODEL.md` — threat table; update when a phase adds/closes a property.

## Don't-trip wires
- **Cipher is UNVETTED** — never on real data. Every new file says so; keep that framing. The shells ride
  vetted HMAC/SHA/AES/ChaCha/HKDF/ML-KEM/(ML-DSA next); only the chaos keystream is hand-rolled.
- **KAT discipline (critical):** snapshot `vectors.json` BEFORE regenerating, then DIFF to prove ONLY the
  intended new block was added and every keystream vector is byte-identical. One-liner:
  `python3 -c "import json;a=json.load(open('/tmp/before.json'));b=json.load(open('kat/vectors.json'));print([k for k in a if a[k]!=b.get(k)], [k for k in b if k not in a])"`
- **Determinism for KAT:** the Python shells use random nonces/seeds/ephemerals. The Rust core takes them
  explicitly (caller owns randomness) so the KAT can pin them — the same rule as twolock's nonces and 8.5's
  DH exponent + ML-KEM seed + encaps message. For 8.5, ML-KEM encaps could NOT be pinned in Python's API,
  so the ciphertext is frozen as public test data (like NIST ML-KEM KATs) and both sides decapsulate it.
- **ML-KEM cross-impl proof (8.5):** RustCrypto `ml-kem` `from_seed(64-byte d‖z)` produces the SAME
  encapsulation key as OpenSSL `from_seed_bytes`; cross-decapsulation matches. Expect the same pattern for
  ML-DSA in 8.6 — but VERIFY it with a throwaway spike before committing (that is exactly how 8.5 was
  de-risked: a tiny scratch cargo project compared Rust vs Python reference values first).
- **ML-KEM private key in Python `cryptography` 49.0.0 is the 64-byte SEED** (`private_bytes_raw()` = seed,
  `from_seed_bytes(seed)`), NOT the expanded 2400-byte dk. RustCrypto regenerates from the same seed.
- **Rust is NOT on PATH** (installed `--no-modify-path`). Prefix cargo with `. "$HOME/.cargo/env" &&`.
- **`rust/target/` and `docs/` are gitignored** (`docs/` holds a real N.I.E. — never commit it).
- **Two pre-existing cosmetic clippy notes** (lib.rs:149 RangeInclusive::contains, main.rs:21 is_multiple_of)
  — documented as left-as-is. Don't let them read as new. Introduce ZERO new clippy warnings.
- **Save = decide-and-do** (the global smart-checkpoint skill). The project's `save` = 3 pillars: git
  commit+push (a CODE commit then a DOCS commit referencing the hash, the established pattern) → prepend a
  dated `## 📜 Build Log` entry in `~/Documents/Cursor Code/Obsidian Vault/Vault/Chaos Cipher.md` (this is
  OUTSIDE the repo, not committed) → fold the DONE update into PROGRESS.md's top status line. Refresh
  HANDOFF.md only if a fresh session is likely next. Tests are NOT part of save.
- **`cryptography` 49.0.0 + OpenSSL 3.5** provide ML-KEM + ML-DSA in Python; PQ tests auto-skip if absent.
- The user prefers plain, no-jargon, SHORT reports (explain like to a smart non-programmer; one picture
  for hard ideas). Recommend honestly even when told "do it all"; flag deviations from the plan.

## Run / verify
```bash
cd "/Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher"
. "$HOME/.cargo/env" && (cd rust && cargo build --release && cargo test --release)   # Rust 17/17
python3 -m pytest tests/ -q                                                          # Python 176 pass
for a in commitment streaming ratchet_aead pq_hybrid twolock auth_pq; do echo -n "$a: "; python3 attacks/${a}_attack.py | tail -1; done
python3 -m ruff check .                                                              # clean
. "$HOME/.cargo/env" && (cd rust && cargo clippy --release --all-targets)            # only the 2 old notes
# KAT contract + parity + interop:
python3 -m pytest tests/test_rust_parity.py tests/test_kat.py tests/test_rust_fuzz.py -q
```
