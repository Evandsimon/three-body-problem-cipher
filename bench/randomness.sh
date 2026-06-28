#!/usr/bin/env bash
# Heavy randomness battery on the SHIPPED keystream (Phase 2 #7).
# Always runs the zero-dep NIST-lite screen; adds ent / PractRand / dieharder when installed.
#
#   bash bench/randomness.sh [path] [MB]
#     path : ratchet (default, the real shipped stream) | multimap (raw 4-map combiner)
#     MB   : size for the file-based tests (ent/dieharder) and the PractRand cap. Default 64.
#
# PractRand is the gold-standard, most sensitive suite; it STREAMS (no giant temp file) and reports
# at every power-of-two checkpoint. Point the script at it via the PRACTRAND env var, e.g.:
#   PRACTRAND=/path/to/RNG_test bash bench/randomness.sh ratchet 256
set -euo pipefail
cd "$(dirname "$0")/.."

PATHSEL="${1:-ratchet}"
MB="${2:-64}"
OUT="/tmp/chaos_keystream_${PATHSEL}.bin"
RNG_TEST="${PRACTRAND:-$(command -v RNG_test || true)}"

echo "==> Keystream path: ${PATHSEL}  (size for file tests / PractRand cap: ${MB} MB)"

echo; echo "==> Pure-Python NIST-lite screen (zero deps) on the shipped stream"
python3 bench/nist_lite.py $((MB * 1024 * 1024 / 8 < 4000000 ? 4000000 : 8000000)) || true

echo; echo "==> PractRand (the strong one) — streaming, capped at ${MB} MB"
if [ -n "$RNG_TEST" ] && [ -x "$RNG_TEST" ]; then
  python3 bench/stream_keystream.py "$PATHSEL" "$MB" | "$RNG_TEST" stdin -tlmax "${MB}MB" || true
else
  echo "   PractRand RNG_test not found. Build it from https://pracrand.sourceforge.net then"
  echo "   re-run with:  PRACTRAND=/path/to/RNG_test bash bench/randomness.sh ${PATHSEL} ${MB}"
fi

echo; echo "==> Dumping ${MB} MB to ${OUT} for the file-based tools (ent/dieharder)"
python3 bench/stream_keystream.py "$PATHSEL" "$MB" > "$OUT"
echo "   done ($(wc -c < "$OUT") bytes)"

echo; echo "==> ent (if installed)"
if command -v ent >/dev/null 2>&1; then ent "$OUT"; else echo "   ent not found (brew install ent)"; fi

echo; echo "==> dieharder (if installed; slow, wants >=100MB)"
if command -v dieharder >/dev/null 2>&1; then
  dieharder -a -g 201 -f "$OUT" || true
else
  echo "   dieharder not found (not in Homebrew core; PractRand above supersedes it)"
fi
