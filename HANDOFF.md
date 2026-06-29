# HANDOFF — chaos-cipher · 2026-06-29
project: /Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher

## Resume in one move
Phase 5 (harden the shell) is **COMPLETE and saved** — there is no half-done work. The first move is a
DECISION: pick the next direction (see "Next steps"). To confirm the green state, run the block under
"Run / verify".

## Goal
Build the most-secure version of an UNVETTED research chaos stream cipher, then deploy it only as the
OUTER wall over a vetted vault ("Option B"). Standing rule: best/most-secure path, never the easy one;
every roadmap item is BUILT **and** attacked/measured. Phases done: 0–5. Remaining: 6 (two locks), 7
(external review).

## State
- **Phase 5 DONE — branch `phase5-aead-harden` (off `branchless-core`), all saved/pushed.** Four shell
  features, each built AND attacked, all riding vetted HMAC/SHA/ML-KEM (chaos keystream stays UNVETTED):
  - **#6 key-commitment** (`commit.py` → `aead.py`/`siv.py`): CMT-4 commitment binds each blob to one
    key; closes the AES-GCM/ChaCha20-Poly1305 key-confusion attack. `attacks/commitment_attack.py`
    measures ~2^128 forge cost (birthday exponent 0.467).
  - **B. streaming AEAD** (`streaming.py`): chunk-by-chunk; per-chunk HMAC binds index + `final` flag →
    defeats reorder/drop/duplicate/truncate. `attacks/streaming_attack.py` + 16 tests.
  - **A. forward-secret session** (`ratchet_aead.py`): per-message one-way burned key chain over the
    committing AEAD → past messages safe after a key leak. `attacks/ratchet_aead_attack.py` + 9 tests.
  - **F. post-quantum hybrid KEX** (`pq_keyexchange.py`): classical DH + **vetted ML-KEM-768** (FIPS
    203, via `cryptography`/OpenSSL 3.5 — NOT hand-rolled) through a transcript-bound combiner; safe if
    EITHER holds. `attacks/pq_hybrid_attack.py` (survival 64/64, avalanche 128.6/256) + 8 tests.
- **In flight:** nothing half-edited. Clean stop after the Phase 5 save.
- **Verified at save:** full suite **129 pass** (was 93); all 4 new attack scripts PASS; ruff clean;
  THREAT_MODEL.md updated; SIV KAT regenerated with ONLY the `siv` vector changed (engine/keystream
  vectors byte-identical) and Rust parity+fuzz re-run green → **Phase-4 Rust contract intact**.
- **Blocked / open:** no technical blockers. The one real gap is **no external review** (Phase 7) — by
  design this stays unvetted; deployment is only ever Option B.

## Next steps (pick one — a fork, not a queue)
1. **Phase 6 — two locks (the stated security goal):** integrate the chaos cipher as the OUTER layer
   over a vetted inner vault (AES-256-GCM or XChaCha20-Poly1305); specify where chaos sits + the order
   of operations ("Option B"). This is the natural next big rock.
2. **Authenticated PQ handshake:** combine `pq_keyexchange.py` (hybrid) with `auth_keyexchange.py`
   (triple-DH) + a PQ signature (ML-DSA) for a fully PQ-secure *authenticated* exchange. Closes the
   "unauthenticated" caveat on item F.
3. **Port the Phase-5 shell to Rust:** the shell (commit/streaming/ratchet_aead/pq) is Python-only; the
   Rust core covers only the keystream. A real deployment would port + KAT-freeze these too.
4. **Parked: AsturAI "Option-B" bridge** — where the chaos layer sits over a vetted AEAD in AsturAI.
   Deferred at the user's request; pick up when they say so.

## Key files
- `PROGRESS.md` — living compass; read first. Roadmap + dated DONE log (newest = Phase 5).
- `commit.py` — key-commitment primitive (`key_commitment`, `verify_commitment`); used by aead/siv/streaming.
- `aead.py` / `siv.py` — the two AEAD shells; now carry a 32-byte commitment field (wire format changed).
- `streaming.py` — chunked AEAD: `StreamSealer`/`StreamOpener` + `seal_stream`/`open_stream`.
- `ratchet_aead.py` — forward-secret session: `SenderSession`/`ReceiverSession`.
- `pq_keyexchange.py` — hybrid KEX: `HybridInitiator`/`HybridResponder`/`hybrid_agree` (needs ML-KEM).
- `attacks/{commitment,streaming,ratchet_aead,pq_hybrid}_attack.py` — the four Phase-5 validations.
- `tests/test_{aead,siv,streaming,ratchet_aead,pq_keyexchange}.py` — the Phase-5 tests.
- `THREAT_MODEL.md` — threat table + bit-security claim (now incl. key-confusion, stream-manipulation, quantum rows).
- `ratchet.py` / `multimap.py` / `engine.py` — the keystream the Rust core mirrors (UNCHANGED in Phase 5).
- `kat/vectors.json` — frozen contract. Only the `siv` block moved in Phase 5; the keystream vectors are the Rust contract — DON'T regenerate casually.

## Don't-trip wires
- **Cipher is UNVETTED** — never on real data. Phase 5 added real SHELL security (on vetted HMAC/SHA/
  ML-KEM), NOT a proof of the chaos math. Every new file says so; keep that framing.
- **`aead.py` and `siv.py` each define their OWN `InvalidTag` class** — catch BOTH when handling either.
- **ML-KEM needs `cryptography` + OpenSSL 3.5+** (have it: cryptography 49.0.0). `pq_keyexchange` and its
  tests guard/skip if absent. `cryptography` is now a FUNCTIONAL dep (was benchmark-only).
- **Rust is NOT on PATH** (installed `--no-modify-path`). Prefix cargo/rust with `. "$HOME/.cargo/env" &&`.
- **`rust/target/` and `docs/` are gitignored** (`docs/` holds a real N.I.E. — never commit it). `Cargo.lock` IS committed.
- **Save = 3 steps** (project CLAUDE.md), ONLY when the user says "save": git commit+push → prepend a
  dated Obsidian `## 📜 Build Log` entry in `~/Documents/Cursor Code/Obsidian Vault/Vault/Chaos Cipher.md`
  → update `PROGRESS.md`. **Tests are NOT part of save** — run pytest separately.
- **KAT discipline:** if you change a deterministic shell path, regenerate then DIFF vectors.json to
  prove ONLY the intended block moved and the engine/keystream vectors stay byte-identical (Rust contract).

## Run / verify
```bash
cd "/Users/evansimonenko/Documents/Cursor Code/Projects/chaos-cipher"
python3 -m pytest tests/ -q                                  # full suite (129 pass)
for a in commitment streaming ratchet_aead pq_hybrid; do python3 attacks/${a}_attack.py | tail -1; done   # 4× ALL PASS
ruff check .                                                 # analyzer clean
# Rust contract still intact (needs the built binary):
. "$HOME/.cargo/env" && python3 -m pytest tests/test_rust_parity.py tests/test_rust_fuzz.py -q
```
