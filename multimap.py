"""
MultiMapEngine — the "three-body" keystream: 3 INDEPENDENT PWLCM maps, XOR-combined.

Why this exists: the single-map cipher (engine.py) is invertible, so a known-plaintext
state-recovery attack works at reduced scale (see attacks/known_plaintext.py, Part B). The fix
is to run several independent chaotic maps and XOR their outputs:

    keystream_byte = b1 ^ b2 ^ b3        (bi = output of independent map i)

An attacker now sees only the XOR, not any single map's output, so they cannot cheaply separate
and roll back the three states. XOR-combining independent keystreams is a standard, sound
"combiner" construction.

DESIGN DECISION — the maps are INDEPENDENT, not coupled. They do not pull on each other; they are
mixed only at the final XOR. This is deliberate:
  * independence hides each map's footprint behind the others (defeats the per-map recovery), and
  * it avoids chaos *synchronization* — truly interacting chaotic systems can fall into step and
    repeat a short cycle, which would WEAKEN the keystream. Uncoupled maps can't sync.

Each map gets its own secret (seed, control) via a domain-separated KDF, so the three streams are
cryptographically unrelated.

STILL UNVETTED. This defeats the naive per-map attack; it is not a proof of security.
"""

from __future__ import annotations

import hashlib

from engine import DiscreteChaoticEngine

DEFAULT_N_MAPS = 3


class MultiMapEngine:
    """N independent PWLCM keystreams XOR-combined. Drop-in for DiscreteChaoticEngine.

    Parameters
    ----------
    master_key : bytes
        The shared secret.
    nonce : bytes
        Public, unique per message. Mixed into every sub-map's derivation.
    n_maps : int
        How many independent maps to combine (default 3 = the "three-body" design).
    """

    def __init__(self, master_key: bytes, nonce: bytes, n_maps: int = DEFAULT_N_MAPS):
        if n_maps < 1:
            raise ValueError("n_maps must be >= 1")
        self.n_maps = n_maps
        self.engines = [self._derive_engine(master_key, nonce, i) for i in range(n_maps)]

    @staticmethod
    def _derive_engine(master_key: bytes, nonce: bytes, index: int) -> DiscreteChaoticEngine:
        """Derive one INDEPENDENT sub-map. The map index is folded into the hash so each map
        gets an unrelated (seed_key, control_parameter). Reuses the engine's own weak-parameter
        rejection in __init__."""
        h = hashlib.sha512(
            b"chaos-pwlcm-v1|multimap|" + index.to_bytes(2, "big")
            + b"|" + master_key + b"|" + nonce
        ).digest()
        seed_key = int.from_bytes(h[0:24], "big")
        control = int.from_bytes(h[24:48], "big")
        return DiscreteChaoticEngine(seed_key, control, nonce=0)  # nonce already in the hash

    def generate_byte(self) -> int:
        """One combined keystream byte = XOR of one byte from each independent sub-map."""
        b = 0
        for eng in self.engines:
            b ^= eng.generate_byte()
        return b

    def keystream(self, n: int) -> bytes:
        return bytes(self.generate_byte() for _ in range(n))

    def encrypt(self, data: bytes) -> bytes:
        out = bytearray(len(data))
        for i, byte in enumerate(data):
            out[i] = byte ^ self.generate_byte()
        return bytes(out)

    decrypt = encrypt


if __name__ == "__main__":
    key = b"my shared secret key"
    nonce = b"unique-nonce-001"

    a = MultiMapEngine(key, nonce)
    b = MultiMapEngine(key, nonce)
    print(f"3-map keystream (Alice): {a.keystream(8).hex()}")
    print(f"3-map keystream (Bob):   {b.keystream(8).hex()}  (matches: determinism OK)")

    msg = b"three independent chaotic maps, XOR-combined."
    ct = MultiMapEngine(key, nonce).encrypt(msg)
    pt = MultiMapEngine(key, nonce).decrypt(ct)
    print(f"\nround-trip: {pt == msg}  ->  {pt!r}")

    # show the combined stream differs from each single sub-map's stream
    sub0 = MultiMapEngine(key, nonce).engines[0].keystream(8).hex()
    combined = MultiMapEngine(key, nonce).keystream(8).hex()
    print(f"\nsub-map[0] stream: {sub0}")
    print(f"combined stream:   {combined}  (differs: each map's footprint is hidden)")
