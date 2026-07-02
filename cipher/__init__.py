"""Three-Body Problem Cipher — public API.

A research chaos-based stream cipher: integer PWLCM keystream under a
4-map multi-map combiner, frosted-glass output filter, auto-rekey ratchet,
committing AEAD, two-locks deployment, and authenticated post-quantum key
exchange.  Python reference + fast Rust core, bit-identical and cross-tested.

UNVETTED — never use for real data.
"""

from cipher.aead import NONCE_LEN, TAG_LEN, InvalidTag, open_, seal
from cipher.engine import DiscreteChaoticEngine

__all__ = [
    "DiscreteChaoticEngine",
    "InvalidTag",
    "NONCE_LEN",
    "TAG_LEN",
    "open_",
    "seal",
]
