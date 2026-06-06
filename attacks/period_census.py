"""
PERIOD CENSUS — the "drop thousands of marbles" experiment (REPORT §period-guarantee).

The veteran's make-or-break question for ANY discretized chaotic map:

    "Chaos lives in the infinite reals; you built it in finite integers. What is the
     GUARANTEED shortest cycle over EVERY key — not the one orbit you measured with Brent?"

A deterministic map on a finite state set is eventually periodic (pigeonhole). Each starting
state (= key) flows down a 'tail' into exactly one 'cycle'. If a cycle is tiny — or worse a
fixed point (x -> x) — the keystream repeats almost immediately and the cipher collapses to a
many-time pad. test_period.py measured FOUR hand-picked orbits. That is one marble. This file
answers the real question two ways:

  PART A — FULL CENSUS at small scale. At small moduli M = 2**k - 1 we can build the ENTIRE
           functional graph (every state's successor) and compute the COMPLETE truth: every
           cycle, every fixed point, and what fraction of ALL states drain into a short cycle.
           This is "checking every marble", not sampling. We sweep k to see the SCALING trend
           (do short-cycle basins shrink as the grid grows?) and sweep the break-point p
           (including the rejected edge band) to see which p are dangerous.

  PART B — TRAP HUNT at the real M = 2**61 - 1. We cannot census 2**61 states, but we can drop
           thousands of PRODUCTION-style keys (seeded exactly like the real cipher, via the
           SHA-512 KDF) and run Brent with a modest budget. Any key that completes a cycle
           within the budget has a DANGEROUSLY short period = a trap. Expected good outcome:
           zero traps (evidence, not proof, that real keys avoid short cycles).

  PART C — ADVERSARIAL EDGES. The nastiest hand-picked inputs (key/ctrl = 0, 1; p at the band
           edges; the documented period-1 weak class) to confirm the rejection + warm-up +
           DEAD_STATE_FIX actually prevent fixed-point capture.

Run:  python3 attacks/period_census.py all
      python3 attacks/period_census.py census           # Part A only
      python3 attacks/period_census.py hunt [K] [budget] # Part B only
      python3 attacks/period_census.py edges            # Part C only
"""
from __future__ import annotations

import os
import sys
from array import array

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import DiscreteChaoticEngine, M as REAL_M, HALF as REAL_HALF, DEAD_STATE_FIX  # noqa: E402


def _p(msg=""):
    print(msg, flush=True)


# --------------------------------------------------------------------------------------
# The map, parameterised by modulus so we can run it at ANY scale (small census or real).
# This mirrors engine.py::_next_state EXACTLY (same four branches + the x==0 escape edge).
# --------------------------------------------------------------------------------------
def step(x: int, p: int, M: int, HALF: int, dead: int) -> int:
    if 0 < x < p:
        return (M * x) // p
    elif p <= x < HALF:
        return (M * (x - p)) // (HALF - p)
    elif HALF <= x < M - p:
        return (M * (M - p - x)) // (HALF - p)
    elif M - p <= x < M:
        return (M * (M - x)) // p
    else:                              # x == 0, or transient overflow (>= M): escape to dead
        return dead


# ======================================================================================
# PART A — FULL FUNCTIONAL-GRAPH CENSUS (every marble, small scale)
# ======================================================================================
def full_census(k: int, p: int):
    """Build the entire functional graph for M = 2**k - 1 and break-point p.

    Returns a dict of the security-relevant facts:
      n_states, n_cycles, n_fixed_points,
      max_cycle, max_cycle_basin_frac,           # the big healthy attractor
      states_in_tiny_cycles_frac (cycle len <= 16),
      worst: smallest cycle length and how many states drain to a cycle <= that.
    """
    M = (1 << k) - 1
    HALF = M // 2
    dead = DEAD_STATE_FIX % M
    N = M  # states are 0 .. M-1 (we include 0; its successor is the escape value)

    # successor of every state. A few branch outputs transiently exceed M-1; the real engine
    # catches those on the NEXT step (else -> dead). In the finite census we collapse that one
    # step (out-of-range output -> dead) — faithful for cycle/basin structure.
    succ = array("q", bytes(8 * N))           # zero-filled
    for x in range(N):
        y = step(x, p, M, HALF, dead)
        succ[x] = y if 0 <= y < N else dead

    # find every cycle via a coloured walk (each node visited once, amortised O(N))
    color = bytearray(N)                       # 0=white 1=gray 2=black
    cid = array("q", [-1]) * N                 # cycle id per node (-1 = not yet assigned)
    cyc_len: list[int] = []                    # cyc_len[id] = length of that cycle
    for s in range(N):
        if color[s]:
            continue
        path = []
        pos = {}
        x = s
        while color[x] == 0:
            color[x] = 1
            pos[x] = len(path)
            path.append(x)
            x = succ[x]
        if color[x] == 1:                      # closed a brand-new cycle
            i = pos[x]
            cyc = path[i:]
            this_id = len(cyc_len)
            cyc_len.append(len(cyc))
            for c in cyc:
                cid[c] = this_id
        for node in path:                      # retire the whole walk
            color[node] = 2

    # propagate cycle-id down every tail (each node ends in exactly one cycle)
    for s in range(N):
        if cid[s] != -1:
            continue
        chain = []
        x = s
        while cid[x] == -1:
            chain.append(x)
            x = succ[x]
        val = cid[x]
        for node in chain:
            cid[node] = val

    # basin size per cycle
    basin = [0] * len(cyc_len)
    for x in range(N):
        basin[cid[x]] += 1

    n_cycles = len(cyc_len)
    n_fixed = sum(1 for L in cyc_len if L == 1)
    big_id = max(range(n_cycles), key=lambda i: cyc_len[i])
    max_cycle = cyc_len[big_id]
    max_cycle_basin_frac = basin[big_id] / N

    tiny_states = sum(basin[i] for i in range(n_cycles) if cyc_len[i] <= 16)
    smallest_cycle = min(cyc_len)
    states_to_smallest = sum(basin[i] for i in range(n_cycles) if cyc_len[i] == smallest_cycle)

    return {
        "M": M, "N": N, "p": p,
        "n_cycles": n_cycles,
        "n_fixed_points": n_fixed,
        "max_cycle": max_cycle,
        "max_cycle_basin_frac": max_cycle_basin_frac,
        "tiny_states_frac": tiny_states / N,
        "smallest_cycle": smallest_cycle,
        "states_to_smallest_frac": states_to_smallest / N,
    }


def run_census():
    _p("=" * 86)
    _p("PART A — FULL CENSUS (every state mapped) at small scale, swept across grid size & p")
    _p("=" * 86)
    _p("Reading: 'max cycle covers X% of states' = the big healthy loop. We WANT that near 100%.")
    _p("         'states draining to tiny (<=16) cycles' = traps. We WANT that at/near 0%.\n")

    import random
    rng = random.Random(20260606)

    # (k, how many random p to try). Bigger grids cost more, so fewer p there.
    plan = [(13, 8), (15, 8), (17, 6), (19, 4), (21, 3)]

    worst_tiny = 0.0
    worst_fixed_capture = 0.0
    for k, n_p in plan:
        M = (1 << k) - 1
        HALF = M // 2
        MINP = max(1, HALF >> 20)              # mirror MIN_P = HALF/2**20 relative band
        _p(f"--- grid M = 2^{k}-1 = {M:,} states ---")
        # production-style p (uniform in the accepted band) + two rejected-edge p to contrast
        ps = [rng.randrange(MINP, HALF - MINP) for _ in range(n_p)]
        edge_ps = [1, HALF - 1]                # deliberately INSIDE the rejected zone
        for p, tag in [(pp, "ok-band") for pp in ps] + [(pp, "EDGE!!") for pp in edge_ps]:
            r = full_census(k, p)
            worst_tiny = max(worst_tiny, r["tiny_states_frac"])
            if r["smallest_cycle"] == 1:
                worst_fixed_capture = max(worst_fixed_capture, r["states_to_smallest_frac"])
            _p(
                f"  p={p:<11,} [{tag}]  cycles={r['n_cycles']:<5} "
                f"fixed_pts={r['n_fixed_points']:<3} "
                f"big_loop={r['max_cycle']:>10,} ({r['max_cycle_basin_frac']*100:5.1f}% of states)  "
                f"smallest={r['smallest_cycle']:<7,} "
                f"tiny(<=16)basin={r['tiny_states_frac']*100:6.3f}%"
            )
        _p("")

    _p("CENSUS SUMMARY")
    _p(f"  worst tiny-cycle basin seen (any p, any grid): {worst_tiny*100:.4f}% of states")
    _p(f"  worst fixed-point capture seen:                {worst_fixed_capture*100:.4f}% of states")
    _p("  (Edge p values are the ones the real cipher REJECTS via the MIN_P band.)\n")


# ======================================================================================
# PART B — TRAP HUNT at the real 2^61-1 grid, over many production-style keys
# ======================================================================================
def brent_lambda(x0: int, p: int, budget: int):
    """Brent cycle detection on the REAL map from start x0. Returns cycle length lam if a
    cycle is completed within `budget` steps, else None (= period longer than budget = good)."""
    M, HALF = REAL_M, REAL_HALF
    dead = DEAD_STATE_FIX
    power = lam = 1
    t = x0
    h = step(x0, p, M, HALF, dead)
    steps = 0
    while t != h:
        if power == lam:
            t = h
            power *= 2
            lam = 0
        h = step(h, p, M, HALF, dead)
        lam += 1
        steps += 1
        if steps > budget:
            return None
    return lam


def run_hunt(n_keys: int = 800, budget: int = 250_000):
    _p("=" * 86)
    _p(f"PART B — TRAP HUNT on the REAL grid M = 2^61-1, {n_keys:,} production-seeded keys")
    _p("=" * 86)
    _p(f"Each key is seeded EXACTLY like the real cipher (SHA-512 KDF, weak-band rejected,")
    _p(f"16-step warm-up). Budget = {budget:,} steps. A cycle found within budget = a TRAP")
    _p(f"(period < {budget:,} << any real message). Expected good result: ZERO traps.\n")

    import secrets

    traps = []
    shortest = None
    report_every = max(1, n_keys // 20)
    for i in range(n_keys):
        mk = secrets.token_bytes(32)
        nonce = secrets.token_bytes(16)
        eng = DiscreteChaoticEngine.from_master(mk, nonce)   # real production path
        lam = brent_lambda(eng.x, eng.p, budget)
        if lam is not None:
            traps.append((mk.hex(), nonce.hex(), lam))
            if shortest is None or lam < shortest:
                shortest = lam
        if (i + 1) % report_every == 0:
            _p(f"  ...{i+1:>5,}/{n_keys:,} keys checked   traps so far: {len(traps)}")

    _p("")
    _p("TRAP HUNT RESULT")
    _p(f"  keys tested:        {n_keys:,}")
    _p(f"  budget per key:     {budget:,} steps")
    _p(f"  traps (short cyc):  {len(traps)}")
    if traps:
        _p(f"  shortest period:    {shortest:,}  <-- INVESTIGATE")
        for mk, nc, lam in traps[:5]:
            _p(f"    key={mk[:16]}... nonce={nc[:12]}... period={lam:,}")
    else:
        _p(f"  -> No production key fell into a cycle shorter than {budget:,} steps.")
        _p(f"     Every orbit's period exceeds the budget (good — no reachable repeat).")
    _p("")
    return len(traps)


# ======================================================================================
# PART C — ADVERSARIAL EDGES (confirm rejection / warm-up / escape defend the corners)
# ======================================================================================
def run_edges():
    _p("=" * 86)
    _p("PART C — ADVERSARIAL EDGE INPUTS on the real grid (do the defences hold the corners?)")
    _p("=" * 86)
    _p("These are the nastiest hand-picked keys. We check the resulting p (after weak-band")
    _p("rejection) and run a short Brent. None should yield a short cycle.\n")

    budget = 2_000_000
    cases = [
        ("key=0,  ctrl=0",            0, 0),
        ("key=1,  ctrl=1",            1, 1),
        ("key=0,  ctrl=1",            0, 1),
        ("ctrl just below HALF",      123456789, REAL_HALF - 1),
        ("ctrl = HALF (folds to 0)",  987654321, REAL_HALF),
        ("ctrl tiny (in reject band)", 555, 7),
        ("big realistic",             987654321012345987654321, 333333333333333222111),
    ]
    bad = 0
    for label, key, ctrl in cases:
        eng = DiscreteChaoticEngine(key, ctrl, nonce=0)
        # confirm p landed inside the accepted band
        in_band = eng.MIN_P <= eng.p <= REAL_HALF - eng.MIN_P
        lam = brent_lambda(eng.x, eng.p, budget)
        verdict = "GOOD (no short cycle)" if lam is None else f"SHORT CYCLE {lam:,} <-- BAD"
        if lam is not None:
            bad += 1
        _p(f"  {label:30s} p_in_band={in_band!s:5}  x0={eng.x:>19,}  {verdict}")
    _p("")
    _p(f"EDGE RESULT: {bad} of {len(cases)} adversarial inputs produced a short cycle "
       f"(want 0).\n")
    return bad


# ======================================================================================
# PART D — PERIOD SCALING LAW (how does typical period grow with grid size?)
# ======================================================================================
def brent_lambda_at(x0: int, p: int, M: int, HALF: int, budget: int):
    """Brent on an arbitrary-modulus map. Returns exact period lam, or None past budget."""
    dead = DEAD_STATE_FIX % M
    power = lam = 1
    t = x0
    h = step(x0, p, M, HALF, dead)
    steps = 0
    while t != h:
        if power == lam:
            t = h
            power *= 2
            lam = 0
        h = step(h, p, M, HALF, dead)
        lam += 1
        steps += 1
        if steps > budget:
            return None
    return lam


def run_scaling():
    import math
    import random
    rng = random.Random(424242)

    _p("=" * 86)
    _p("PART D — PERIOD SCALING LAW (random production-style starts, exact Brent period)")
    _p("=" * 86)
    _p("If the map were a permutation, period ~ grid size N. If it behaves like a RANDOM")
    _p("FUNCTION (merging tails), period ~ sqrt(N) (the 'rho'/birthday law). We measure the")
    _p("median period at growing N and read off the exponent.\n")
    _p(f"  {'grid':>8} {'N=2^k':>8} {'keys':>5} {'sqrt(N)=2^':>11} {'median period':>16} "
       f"{'=2^':>7} {'period/sqrt(N)':>15}")

    ks = [21, 25, 29, 33, 37]
    keys = 120
    pts = []
    for k in ks:
        M = (1 << k) - 1
        HALF = M // 2
        MINP = max(1, HALF >> 20)
        budget = int(40 * math.isqrt(M)) + 100_000
        periods = []
        for _ in range(keys):
            p = rng.randrange(MINP, HALF - MINP)
            x0 = rng.randrange(1, M)
            lam = brent_lambda_at(x0, p, M, HALF, budget)
            if lam:
                periods.append(lam)
        periods.sort()
        med = periods[len(periods) // 2] if periods else None
        sqrtN_log = 0.5 * k
        if med:
            med_log = math.log2(med)
            ratio = med / math.sqrt(M)
            pts.append((k, med_log))
            _p(f"  2^{k:<6} {k:>8} {len(periods):>5} {sqrtN_log:>11.2f} {med:>16,} "
               f"{med_log:>7.2f} {ratio:>15.3f}")
        else:
            _p(f"  2^{k:<6} {k:>8} {0:>5}  (no periods found within budget)")

    _p("")
    if len(pts) >= 2:
        # linear fit median_log2 = a + b*k ; b should be ~0.5 for the sqrt(N) law
        n = len(pts)
        sx = sum(k for k, _ in pts)
        sy = sum(v for _, v in pts)
        sxx = sum(k * k for k, _ in pts)
        sxy = sum(k * v for k, v in pts)
        b = (n * sxy - sx * sy) / (n * sxx - sx * sx)
        a = (sy - b * sx) / n
        _p(f"  FIT: log2(median period) ~= {a:.2f} + {b:.3f} * k")
        _p(f"       exponent b = {b:.3f}  (0.50 = pure sqrt(N) random-function law)")
        extrap = a + b * 61
        _p(f"  EXTRAPOLATION to the real grid k=61:  median period ~= 2^{extrap:.1f} "
           f"(~{2**extrap:.2e})")
        _p("")
        _p("  MEANING: a single sub-map's keystream period is ~2^30-ish, NOT ~2^61. That is")
        _p("  astronomically shorter than 'the whole grid'. It is still ~1 billion bytes, but")
        _p("  the honest number to publish is sqrt(M), not M. The 3-map XOR keystream repeats")
        _p("  only at lcm of the three (~2^90, safe); CTR mode (ctr.py) avoids orbit length")
        _p("  entirely (each block is a fresh short orbit). See REPORT period section.\n")


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"
    if cmd == "scaling":
        run_scaling()
        return
    if cmd in ("census", "all"):
        run_census()
    if cmd in ("edges", "all"):
        run_edges()
    if cmd in ("hunt", "all"):
        k = int(sys.argv[2]) if len(sys.argv) > 2 else 800
        b = int(sys.argv[3]) if len(sys.argv) > 3 else 250_000
        run_hunt(k, b)
    if cmd in ("scaling", "all"):
        run_scaling()


if __name__ == "__main__":
    main()
