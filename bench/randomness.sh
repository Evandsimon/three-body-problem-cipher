#!/usr/bin/env bash
# Dump keystream to a file and run external randomness batteries if installed.
# Always runs the pure-Python NIST-lite screen (zero deps).
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="${1:-/tmp/chaos_keystream.bin}"
MB="${2:-10}"

echo "==> Dumping ${MB} MB of the SHIPPED 3-map keystream to ${OUT}"
python3 - "$OUT" "$MB" <<'PY'
import sys
from multimap import MultiMapEngine   # the shipped default keystream (3 independent PWLCMs)
out, mb = sys.argv[1], int(sys.argv[2])
eng = MultiMapEngine(b"randomness-battery-key", b"randomness-battery-nonce", n_maps=3)
total = mb * 1024 * 1024
with open(out, "wb") as f:
    written = 0
    while written < total:
        n = min(65536, total - written)
        f.write(eng.keystream(n))
        written += n
print(f"   done ({written} bytes)")
PY

echo; echo "==> Pure-Python NIST-lite screen"
python3 bench/nist_lite.py

echo; echo "==> ent (if installed)"
if command -v ent >/dev/null 2>&1; then ent "$OUT"; else echo "   ent not found (brew install ent)"; fi

echo; echo "==> dieharder (if installed; slow, needs >100MB ideally)"
if command -v dieharder >/dev/null 2>&1; then
  dieharder -a -g 201 -f "$OUT" || true
else
  echo "   dieharder not found (brew install dieharder)"
fi
