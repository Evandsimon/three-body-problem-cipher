"""
THE most important test for any discretized chaotic map.

A continuous chaotic system is non-periodic. Its INTEGER approximation lives on a finite
set of states, so by the pigeonhole principle it MUST eventually cycle. If that cycle is
short, the keystream repeats -> the cipher is catastrophically broken (repeating keystream
= many-time pad).

We use Brent's cycle-detection algorithm on the raw 61-bit state (not the output byte),
which finds the period (lambda) and the tail length (mu) without storing the whole orbit.

v9 NOTE — "one marble" is not a guarantee. The old test measured FOUR hand-picked orbits.
attacks/period_census.py drops thousands of production keys and establishes the honest law:
the map behaves like a RANDOM FUNCTION, so the period scales as sqrt(M) ~ 2^30 (NOT 2^61).
That is huge but finite; the 3-map combiner (lcm ~2^90) and CTR mode neutralise it, and a
per-key data limit handles the single-map mode. What this file now guards is the FATAL case:
no PRODUCTION key may fall into a *short* cycle. See REPORT.md "v9 update".

Run directly to print a measurement, or via pytest for the multi-key regression guard.
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import DiscreteChaoticEngine, M, HALF, DEAD_STATE_FIX  # noqa: E402


def _advance(eng):
    eng._next_state()
    return eng.x


def brent_period(seed_key, ctrl, nonce, max_steps=5_000_000):
    """Brent's algorithm. Returns (lam, mu) or (None, None) if no cycle within max_steps."""
    def fresh():
        return DiscreteChaoticEngine(seed_key, ctrl, nonce)

    # find lambda (cycle length)
    power = lam = 1
    tortoise = fresh()
    t_val = tortoise.x
    hare = fresh()
    h_val = _advance(hare)
    steps = 0
    while t_val != h_val:
        if power == lam:
            t_val = h_val
            power *= 2
            lam = 0
        h_val = _advance(hare)
        lam += 1
        steps += 1
        if steps > max_steps:
            return None, None

    # find mu (tail length before entering the cycle)
    tortoise = fresh()
    hare = fresh()
    t_val = tortoise.x
    h_val = hare.x
    for _ in range(lam):
        h_val = _advance(hare)
    mu = 0
    while t_val != h_val:
        t_val = _advance(tortoise)
        h_val = _advance(hare)
        mu += 1
        if mu > max_steps:
            return lam, None
    return lam, mu


# --- fast inline path for the many-marble guard: step once from a captured (x0, p) ---
def _step(x, p):
    if 0 < x < p:
        return (M * x) // p
    elif p <= x < HALF:
        return (M * (x - p)) // (HALF - p)
    elif HALF <= x < M - p:
        return (M * (M - p - x)) // (HALF - p)
    elif M - p <= x < M:
        return (M * (M - x)) // p
    else:
        return DEAD_STATE_FIX


def _brent_lambda(x0, p, budget):
    """Cycle length from start (x0, p), or None if no cycle completes within budget."""
    power = lam = 1
    t = x0
    h = _step(x0, p)
    steps = 0
    while t != h:
        if power == lam:
            t = h
            power *= 2
            lam = 0
        h = _step(h, p)
        lam += 1
        steps += 1
        if steps > budget:
            return None
    return lam


def measure(label, key, ctrl, nonce, max_steps=2_000_000):
    lam, mu = brent_period(key, ctrl, nonce, max_steps)
    if lam is None:
        print(f"  {label:18s}: period > {max_steps:,} (no cycle found in budget) — GOOD")
    else:
        verdict = "FATAL" if lam < 1_000_000 else "concerning" if lam < 100_000_000 else "ok-ish"
        print(f"  {label:18s}: period(lambda)={lam:,}  tail(mu)={mu}  -> {verdict}")
    return lam


def test_period_not_trivially_short():
    # A short cycle within a tiny budget would be an immediate disqualifier (the old smoke test).
    lam, _ = brent_period(987654321012345987654321, 333333333333333222111, 42,
                          max_steps=500_000)
    assert lam is None or lam > 4096, f"Keystream cycles after only {lam} states — broken"


def test_no_short_cycle_over_many_production_keys():
    """v9 regression guard — drop MANY production-seeded marbles, not one.

    Seeds each engine exactly like the real cipher (SHA-512 KDF via from_master, which applies
    weak-band rejection + warm-up), then runs Brent from the post-warm-up state. The honest
    typical period is ~2^30, far past the budget, so the EXPECTED result is that no key completes
    a cycle within budget. A regression that reintroduces a short-cycle / fixed-point class would
    trip this. Deterministic RNG so any failure reproduces.
    """
    rng = random.Random(20260606)
    n_keys = 120
    budget = 60_000
    offenders = []
    for _ in range(n_keys):
        mk = rng.randbytes(32)
        nonce = rng.randbytes(16)
        eng = DiscreteChaoticEngine.from_master(mk, nonce)
        lam = _brent_lambda(eng.x, eng.p, budget)
        if lam is not None:
            offenders.append((mk.hex()[:16], lam))
    assert not offenders, (
        f"{len(offenders)}/{n_keys} production keys fell into a cycle shorter than {budget:,} "
        f"steps — short-cycle class regressed: {offenders[:5]}"
    )


if __name__ == "__main__":
    print("Period / cycle detection (Brent's algorithm) on the 127-bit state:\n")
    measure("default key", 987654321012345987654321, 333333333333333222111, 42)
    measure("small key/ctrl", 12345, 67891, 1)
    measure("key=1 ctrl=1", 1, 1, 0)
    measure("alt nonce", 987654321012345987654321, 333333333333333222111, 99999)
    print("\nNote: integer maps ALWAYS cycle eventually. By the random-function 'rho' law the honest")
    print("per-map period is ~sqrt(M); at the new grid M=2^127-1 that is ~2^63 (was ~2^30 at 2^61).")
    print("This is a PREDICTION from the law, not a direct measure (2^63 is too large). Census with:")
    print("    python3 attacks/period_census.py all")
