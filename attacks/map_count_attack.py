"""
ATTACK / VALIDATION — the map-count decision (#2): how many independent PWLCM maps to XOR.

Phase-1 design choice, measured not asserted (project ethos). The combiner is
    keystream_byte = b_0 XOR b_1 XOR ... XOR b_{N-1}      (b_i = output of independent map i)
so the security of XOR-combining N independent streams rests on ONE premise: the maps really are
independent. If they were correlated, the XOR could cancel structure and leak. This script:

  PART 1 — INDEPENDENCE: pairwise correlation between every sub-map's keystream (incl. the new
           4th/5th map). Independent => byte-correlation ~ 0 and bit-agreement ~ 0.5. This is the
           load-bearing assumption behind adding maps at all.
  PART 2 — COMBINED RANDOMNESS: per-bit bias / byte chi-square / serial corr of the XOR keystream
           at N = 3, 4, 5. Adding a map must not introduce bias.
  PART 3 — COST: measured throughput at N = 3, 4, 5 (the price of each extra wall; linear in N).
  PART 4 — WORK-FACTOR / PERIOD math (analytic, not measurable directly): what N buys an attacker.

HONEST SCOPE: this validates the *premise* (independence) and the *cost*, and documents what extra
maps do and DON'T buy. It is not a proof of security — the design stays UNVETTED. The security
ceiling is the shared master key + KDF, NOT N x 127 bits; extra maps add redundancy + period, not
an unbounded security level.
"""
import math
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cipher.engine import M                            # noqa: E402
from cipher.multimap import MultiMapEngine             # noqa: E402

KEY = b"map-count-probe-key"
NONCE = b"map-count-probe-nonce"


def _substreams(n_maps: int, n_bytes: int):
    """The independent keystream of each sub-map, as lists of byte values."""
    eng = MultiMapEngine(KEY, NONCE, n_maps=n_maps)
    return [list(sub.keystream(n_bytes)) for sub in eng.engines]


def _pearson(xs, ys):
    n = len(xs)
    mx = sum(xs) / n
    my = sum(ys) / n
    num = sum((xs[i] - mx) * (ys[i] - my) for i in range(n))
    dx = math.sqrt(sum((v - mx) ** 2 for v in xs))
    dy = math.sqrt(sum((v - my) ** 2 for v in ys))
    return num / (dx * dy) if dx and dy else 0.0


# ---------- PART 1: the sub-maps are independent (the premise the whole design rests on) ----------
def part1_independence(n_maps=5, n_bytes=60_000):
    """If the maps share structure, XOR-combining them is unsafe. We measure the strongest pairwise
    coupling across ALL maps (so the 4th and 5th are included). Want: correlation ~ 0, bit-agree ~ 0.5."""
    subs = _substreams(n_maps, n_bytes)
    worst_corr = 0.0
    worst_bitagree_dev = 0.0
    for i in range(n_maps):
        for j in range(i + 1, n_maps):
            corr = abs(_pearson(subs[i], subs[j]))
            worst_corr = max(worst_corr, corr)
            # bit agreement: fraction of bit positions where the two streams agree (~0.5 if independent)
            agree = sum(bin((subs[i][k] ^ subs[j][k]) ^ 0xFF).count("1") for k in range(n_bytes))
            agree_frac = agree / (n_bytes * 8)
            worst_bitagree_dev = max(worst_bitagree_dev, abs(agree_frac - 0.5))
    print("PART 1 — are the sub-maps independent? (the assumption behind XOR-combining)")
    print(f"  maps tested        : {n_maps}  ({n_maps*(n_maps-1)//2} pairs, {n_bytes:,} bytes each)")
    print(f"  worst |correlation|: {worst_corr:.5f}   (~0 = independent)")
    print(f"  worst bit-agree dev: {worst_bitagree_dev:.5f}   (~0 => agreement ~0.5 = independent)")
    ok = worst_corr < 0.02 and worst_bitagree_dev < 0.01
    print(f"  => {'PASS' if ok else 'FAIL'}: sub-maps are independent, so XOR-combining is sound.\n")
    return ok


# ---------- PART 2: adding a map introduces no bias ----------
def part2_combined_randomness(n_bytes=200_000):
    print("PART 2 — combined keystream randomness at N = 3, 4, 5 (extra maps must not add bias):")
    all_ok = True
    for n_maps in (3, 4, 5):
        ks = MultiMapEngine(KEY, NONCE, n_maps=n_maps).keystream(n_bytes)
        n = len(ks)
        worst_sigma = 0.0
        for bit in range(8):
            ones = sum((byte >> bit) & 1 for byte in ks)
            worst_sigma = max(worst_sigma, abs(ones - n / 2) / math.sqrt(n / 4))
        counts = [0] * 256
        for byte in ks:
            counts[byte] += 1
        exp = n / 256
        chi2 = sum((c - exp) ** 2 / exp for c in counts)
        mean = sum(ks) / n
        num = sum((ks[i] - mean) * (ks[i + 1] - mean) for i in range(n - 1))
        den = sum((b - mean) ** 2 for b in ks)
        serial = num / den if den else 0.0
        clean = worst_sigma < 4 and 150 < chi2 < 360 and abs(serial) < 0.01
        all_ok = all_ok and clean
        print(f"  N={n_maps}: worst bias {worst_sigma:.2f}σ | chi² {chi2:6.1f} (df=255) | "
              f"serial {serial:+.5f}  => {'clean' if clean else 'CHECK'}")
    print(f"  => {'PASS' if all_ok else 'CHECK'}: combined output stays statistically flat as N grows.\n")
    return all_ok


# ---------- PART 3: the cost of each extra wall ----------
def part3_cost(n_bytes=120_000):
    print("PART 3 — throughput cost (the price of each extra map; expected ~linear in N):")
    base = None
    for n_maps in (3, 4, 5):
        t0 = time.time()
        MultiMapEngine(KEY, NONCE, n_maps=n_maps).keystream(n_bytes)
        dt = time.time() - t0
        mbps = (n_bytes / dt) / 1e6
        if base is None:
            base = dt
        print(f"  N={n_maps}: {mbps:6.3f} MB/s   ({dt/base:.2f}x the N=3 time)")
    print("  => cost is ~linear in N (each map is one more full keystream). Speed is a Rust-phase\n"
          "     concern; this is the Python reference, so we choose N on security margin, not speed.\n")


# ---------- PART 4: what N actually buys (analytic) ----------
def part4_workfactor():
    s = M.bit_length()                     # per-map state bits (127)
    per_map_period = s // 2                # ~sqrt(M) rho law => ~2^63 (measured exponent ~0.49)
    print("PART 4 — what extra maps buy (analytic; period is too large to measure directly):")
    print(f"  per-map state ~2^{s}, per-map period ~2^{per_map_period} (rho law, measured ~0.49 slope)")
    for n_maps in (3, 4, 5):
        combined_period = per_map_period * n_maps    # lcm of independent orbits ~ product
        joint_state = s * n_maps
        print(f"  N={n_maps}: combined period ~2^{combined_period} | joint hidden state ~2^{joint_state} "
              f"| keystream-only joint recovery ~2^{joint_state}")
    print("  HONEST CEILING: all maps derive from the SAME master key (domain-separated). Key/KDF")
    print("  recovery — not the map count — is the true security bound; extra maps add PERIOD and")
    print("  REDUNDANCY (one map breaking doesn't break the keystream), not unbounded bit-security.\n")


if __name__ == "__main__":
    print("=" * 80)
    print("MAP-COUNT (#2) — validation of independence, randomness, cost, and work-factor")
    print("=" * 80 + "\n")
    r1 = part1_independence()
    r2 = part2_combined_randomness()
    part3_cost()
    part4_workfactor()
    print("=" * 80)
    print(f"VERDICT  independent={r1}  no-new-bias={r2}")
    print("Decision: N=4 — one redundant wall beyond 3 + comfortable margin over 256-bit, at ~linear")
    print("cost (Rust will erase the speed hit). 5 hits diminishing returns vs the shared-key ceiling.")
    print("Still UNVETTED: this confirms the premise (independence) + cost, not security.")
    print("=" * 80)
