"""
ATTACK / VALIDATION — forward-secret session AEAD (item A wired into the shell). Measure it.

CLAIM
  FORWARD SECRECY at message granularity: capturing the live session state just after message C lets
  an attacker read message C onward (that is the live state) but NOT any message before C. The earlier
  per-message keys were burned and the chain is one-way (HMAC-SHA256), so they cannot be recomputed.

THE PARTS
  Part 1 — Forward secrecy: from a capture at message C, the FUTURE opens, the PAST is refused, and the
           contrast proof — a capture ONE message earlier WOULD have read message C-1, so only the
           burned key protected it.
  Part 2 — Honest framing: what this gives and what it does not (no future-secrecy after a live capture
           — that needs the asymmetric / PQ ratchet, item F).

HONEST SCOPE: validates the symmetric forward-secret chain wired onto the committing AEAD. Not a proof
the chaos keystream is secure — that stays UNVETTED. The chain + per-message AEAD ride vetted HMAC.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ratchet_aead import ReceiverSession, SenderSession  # noqa: E402

MASTER = b"ratchet-aead-attack-master-key"
NONCE = b"ratchet-aead-attack-nonce"
CONVO = [f"message #{i}: the secret of the day is {1000 + i}".encode() for i in range(8)]


def _receiver_advanced_to(index: int) -> ReceiverSession:
    """A receiver that has opened messages 0..index-1 — i.e. its live chain is now chain_`index`,
    exactly what a memory capture at that point would hold. (Re-seals locally to feed it.)"""
    s, r = SenderSession(MASTER, NONCE), ReceiverSession(MASTER, NONCE)
    for i in range(index):
        r.open(s.seal(CONVO[i]))
    return r


def part1_forward_secrecy(C: int = 5, lookahead: int = 2) -> bool:
    sender = SenderSession(MASTER, NONCE)
    wires = [sender.seal(m) for m in CONVO]

    captured = _receiver_advanced_to(C)              # live chain == chain_C
    # FUTURE: from the capture, messages C..C+lookahead-1 open correctly.
    future_ok = all(captured.open(wires[C + k]) == CONVO[C + k] for k in range(lookahead))

    # PAST: the same captured state refuses every earlier message (key burned).
    past_protected = True
    for j in range(C):
        try:
            ReceiverSession.open(_receiver_advanced_to(C), wires[j])
            past_protected = False
        except ValueError:
            pass

    # CONTRAST: a capture ONE message earlier COULD read message C-1 — proving only the burn protected it.
    earlier = _receiver_advanced_to(C - 1)
    contrast = earlier.open(wires[C - 1]) == CONVO[C - 1]

    ok = future_ok and past_protected and contrast
    print(f"  Part 1  capture at message C={C}:")
    print(f"            FUTURE (C..C+{lookahead - 1}) reproduces: {future_ok}")
    print(f"            PAST (0..C-1) refused (keys burned):   {past_protected}")
    print(f"            contrast — capture at C-1 reads C-1:    {contrast}")
    print(f"          -> {'PASS' if ok else 'FAIL'}")
    return ok


def part2_honest_framing() -> bool:
    print("  Part 2  honest framing:")
    print("    - Gives PAST-secrecy after a key leak (forward secrecy). Each message's key is burned.")
    print("    - Does NOT give FUTURE-secrecy after a LIVE capture: holding chain_C, the attacker can")
    print("      follow the conversation forward. Healing that needs new entropy mixed in per step —")
    print("      the asymmetric / post-quantum ratchet (item F).")
    print("    - Forward-secret chain + per-message AEAD both ride vetted HMAC-SHA256; keystream UNVETTED.")
    return True


def main() -> None:
    print("=" * 78)
    print("FORWARD-SECRET SESSION AEAD (item A) — validation")
    print("=" * 78)
    p1 = part1_forward_secrecy()
    p2 = part2_honest_framing()
    print("-" * 78)
    print(f"VERDICT: {'ALL PASS' if (p1 and p2) else 'FAILURE — see above'}")
    sys.exit(0 if (p1 and p2) else 1)


if __name__ == "__main__":
    main()
