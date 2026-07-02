# Project Status

**Current:** Phase 8 of 8 complete. Code-design grade: **90/100 (Elite).**

Only Phase 7 (external review) remains on the roadmap.

## Tests

| Suite | Count | Status |
|-------|-------|--------|
| Python | 183 | ✅ |
| Rust | 28 | ✅ |
| Parity (Python ↔ Rust) | 36 | ✅ |
| KAT vectors | 4 | ✅ |
| Attack scripts | 15 | All survive at full scale |

## What's in the box

Python reference implementation + fast Rust core (~61 MB/s), bit-identical and cross-tested. Both halves cover the full stack: chaos engine, multi-map combiner, ratchet, AEAD, streaming AEAD, forward-secret sessions, SIV, two-locks deployment, and authenticated post-quantum key exchange.

## Honest numbers

| Metric | Value |
|--------|-------|
| Bit-security claim | ~254-bit |
| Rust speed | ~61 MB/s (4-map) |
| vs AES-NI | ~149× slower |
| Keystream period | ~2²⁴⁷ (before ratchet; ratchet dissolves the limit) |
| Forward secrecy | Yes (64 KiB epochs) |
| Constant-time | Yes (measured 0.41% spread) |

## Roadmap

- [x] Phase 0 — Branchless constant-time map
- [x] Phase 1 — Finalize core design
- [x] Phase 2 — Attack own design hard
- [x] Phase 3 — Freeze & write the contract
- [x] Phase 4 — Rust core
- [x] Phase 5 — Harden the shell
- [x] Phase 6 — Two-locks (THE security goal)
- [x] Phase 8 — Complete fast Rust core (mirrors every Python capability)
- [ ] Phase 7 — External review (the only item left)

The full build log with every design decision is in [`docs/build-log.md`](docs/build-log.md).
