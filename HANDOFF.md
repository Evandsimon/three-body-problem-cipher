# HANDOFF — chaos-cipher · 2026-06-29
project: /Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher

## Resume in one move
**Phase 8 is COMPLETE — the Rust core now mirrors every Python capability.** The only roadmap item
left is **Phase 7 — external review** (let outside cryptographers attack the finalized design). There
is no more code to port. First confirm everything is still green with the "Run / verify" block below,
then open the "Phase 7" discussion: decide HOW to seek external review (write-up, where to post,
what to ask reviewers to focus on). This is a STRATEGY/communication step, not a build step — talk it
through with the user before producing anything. Working tree is clean; everything saved & pushed on
branch `phase6-two-locks` (8.6 = code commit `a377050`, docs commit follows).

## Goal
Build the most-secure version of an UNVETTED research chaos stream cipher, deployed only as the OUTER
wall over a vetted vault ("Option B"). Standing rule: best/most-secure path, never the easy one; every
feature is BUILT **and** attacked/measured. The user wanted the system **complete, extensible, and
fast**, and to implement ALL the remaining technologies. **That is now done: Phase 8 (the fast Rust
core) mirrors every Python capability.** Only Phase 7 (external review) remains.

## State
- **Saved & pushed (branch `phase6-two-locks`):** Phases 8.1–8.6 of the Rust core are all done.
  - 8.1 AEAD + 8.2 streaming AEAD `ff9ab1e`; 8.3 ratchet AEAD `5057d54`; 8.4 two-locks `d4994b6`;
    8.5 key agreement (DH + ML-KEM-768 hybrid) `ac0fa4a`.
  - **8.6 authenticated PQ handshake — code commit `a377050`** (the LAST port). Ports
    `auth_pq_keyexchange.py`: triple-DH static binding AND ML-DSA-65 signatures over the transcript →
    mutual authentication that survives a quantum break of either axis. New vetted crate `ml-dsa`
    0.1.1 (RustCrypto), `default-features = false` (NO getrandom) — only `from_seed` +
    `sign_deterministic` + `verify_with_context`, so the caller owns all randomness. Lib fns:
    `mldsa_public_from_seed`/`mldsa_sign`/`mldsa_verify`, `auth_fingerprint`, `auth_transcript`,
    `auth_combine`, `auth_responder_respond`/`auth_initiator_finish`/`auth_responder_confirm`. 9 new
    CLI modes. KAT **vector 13 (auth_pq)**. Parity + interop both directions.
- **In flight:** nothing half-edited. Clean stop right after the save. **Next = Phase 7 (external review).**
- **Verified at save:** Rust **19/19**; Python suite **183**; parity/kat/fuzz **41**; all **6** attack
  scripts PASS (incl. `auth_pq`); ruff clean; **zero NEW clippy** (only the 2 documented cosmetic notes
  at lib.rs:149 + main.rs:21); KAT diff proved ONLY the `auth_pq` block was added (every prior keystream
  vector byte-identical → contract intact); Python↔Rust interop works for ML-DSA sign/verify and the
  full authenticated handshake (both directions).
- **Blocked / open:** none technical. The cipher stays UNVETTED by design — Phase 7 is exactly the step
  that addresses that (external eyes), and it never makes the chaos layer "trusted" on its own.

## Next steps (Phase 7 — external review)
1. **Decide the review goal & venue with the user first.** Options to discuss: a clean write-up of the
   design + threat model for a forum (e.g. crypto Stack Exchange, a mailing list), a request for paid
   review, or posting the repo for comment. This is a judgment/positioning call — do NOT just produce a
   document unprompted.
2. **Prepare the review packet** once the venue is chosen: distil `REPORT.md` + `THREAT_MODEL.md` into a
   reviewer-facing summary — what's hand-rolled (ONLY the chaos keystream) vs vetted (everything else),
   the "Option B" two-locks framing, the honest ceiling, and the specific questions to pressure-test.
3. Keep the standing rule: never present the chaos layer as trustworthy on its own; the ask is "find the
   break," not "bless it."

## Key files
- `PROGRESS.md` — living compass; read first. Roadmap + dated DONE log in the top status line (newest =
  Phase 8 COMPLETE).
- `REPORT.md` — the honest self-evaluation (what works, what doesn't). The seed for the Phase 7 packet.
- `THREAT_MODEL.md` — threat table; the other seed for the review packet. (Phase 8.6 did not change the
  cipher's properties — the Python auth handshake already closed the active-MITM gap; 8.6 only brought
  Rust to parity, so no threat-model edit was needed.)
- `rust/src/lib.rs` — Rust core. Sections in order near the end: aead / stream / ratchet_aead / twolock /
  key agreement (8.5) / **authenticated handshake (8.6)**, then `#[cfg(test)] mod tests`.
- `rust/src/main.rs` — CLI bridge (every lib fn has a hex-in/hex-out mode; 49+ modes).
- `rust/Cargo.toml` — deps. 8.5 added `ml-kem`; 8.6 added `ml-dsa` (default-features=false, features
  alloc+zeroize → no getrandom).
- `kat/generate_kat.py` + `kat/vectors.json` — frozen contract (13 vectors). ML-KEM ct AND ML-DSA pubs
  are pinned as frozen public test data with seed self-checks (both PQ backends are randomised/deterministic
  in ways that make the seed the portable contract); keystream blocks stay byte-identical when a vector is added.
- `tests/test_rust_parity.py` — Rust parity + Python↔Rust interop. The 8.6 block (mldsa sign/verify,
  auth_transcript/combine/fingerprint, full-handshake roundtrip, `_needs_mldsa` interop both ways) is the latest.
- Python sources: ALL ported. There is no remaining Python module to port — Phase 8 is feature-complete.

## Don't-trip wires
- **Cipher is UNVETTED** — never on real data. Every new file says so; keep that framing. The shells ride
  vetted HMAC/SHA/AES/ChaCha/HKDF/ML-KEM/ML-DSA; only the chaos keystream is hand-rolled.
- **KAT discipline (critical):** if you ever regenerate, snapshot `vectors.json` BEFORE, then DIFF to prove
  ONLY the intended block changed and every keystream vector is byte-identical. One-liner:
  `python3 -c "import json;a=json.load(open('/tmp/before.json'));b=json.load(open('kat/vectors.json'));print([k for k in a if a[k]!=b.get(k)], [k for k in b if k not in a])"`
- **ML-DSA signatures are NOT in the KAT (deliberate):** Python signs hedged (randomised), Rust signs
  deterministically; both VERIFY but neither is a fixed value, and the signature never enters the session
  key. So vector 13 pins the verifying keys + transcript + key (all deterministic); the round-trip/interop
  tests cover signing. Same spirit as 8.5's frozen ML-KEM ciphertext, but cleaner (sig isn't a derived output).
- **PQ from-seed is the portable private key:** RustCrypto `ml-dsa` `from_seed(32B)` produces the SAME 1952B
  verifying key as OpenSSL `from_seed_bytes`; signatures cross-verify both directions (de-risked with a spike
  before any real code — repeat that pattern for any future PQ primitive).
- **`cryptography` 49.0.0 + OpenSSL 3.5** provide ML-KEM + ML-DSA in Python; PQ tests auto-skip if absent
  (`_needs_mlkem` / `_needs_mldsa`). ML-DSA seed = 32B `private_bytes_raw()`; ML-DSA `.sign(data)` uses an
  EMPTY context — the Rust side matches with an empty `verify_with_context` context.
- **Rust is NOT on PATH** (installed `--no-modify-path`). Prefix cargo with `. "$HOME/.cargo/env" &&`.
- **`rust/target/` and `docs/` are gitignored** (`docs/` holds a real N.I.E. — never commit it).
- **Two pre-existing cosmetic clippy notes** (lib.rs:149 RangeInclusive::contains, main.rs:21 is_multiple_of)
  — documented as left-as-is. Don't let them read as new. Introduce ZERO new clippy warnings.
- **Save = the project's 3 pillars:** git commit+push (a CODE commit then a DOCS commit referencing the hash)
  → prepend a dated `## 📜 Build Log` entry in `~/Documents/Cursor Code/Obsidian Vault/Vault/Chaos Cipher.md`
  (OUTSIDE the repo, not committed) → fold the DONE update into PROGRESS.md's top status line. Tests are NOT
  part of save. Refresh this HANDOFF only if a fresh session is likely next.
- The user prefers plain, no-jargon, SHORT reports (explain like to a smart non-programmer; one picture for
  hard ideas). Recommend honestly even when told "do it all"; flag deviations from the plan.

## Run / verify
```bash
cd "/Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher"
. "$HOME/.cargo/env" && (cd rust && cargo build --release && cargo test --release)   # Rust 19/19
python3 -m pytest tests/ -q                                                          # Python 183 pass
for a in commitment streaming ratchet_aead pq_hybrid twolock auth_pq; do echo -n "$a: "; python3 attacks/${a}_attack.py | tail -1; done
python3 -m ruff check .                                                              # clean
. "$HOME/.cargo/env" && (cd rust && cargo clippy --release --all-targets)            # only the 2 old notes
# KAT contract + parity + interop:
python3 -m pytest tests/test_rust_parity.py tests/test_kat.py tests/test_rust_fuzz.py -q   # 41 pass
```
