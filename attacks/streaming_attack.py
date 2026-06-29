"""
ATTACK / VALIDATION — streaming AEAD (item B). Show the four stream attacks are caught, don't assert it.

A naive "AEAD each chunk separately" stops byte-level tampering but leaves the SEQUENCE unprotected:
an attacker who cannot read or forge a single chunk can still REORDER, DROP, DUPLICATE, or TRUNCATE
the chunks and change the meaning of the whole message. This script plays each manipulation against
streaming.py and confirms every one is rejected, while the honest stream still round-trips.

HONEST SCOPE: validates the framing (index + final-flag binding under HMAC-SHA256). Not a proof the
chaos keystream is secure — that stays UNVETTED; this is a SHELL property on vetted HMAC.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from streaming import HEADER_LEN, InvalidTag, open_stream, seal_stream  # noqa: E402

KEY = b"streaming-attack-master-key"
PARTS = [b"move the gold to vault 1. ", b"hold position. ", b"await my signal. ", b"END"]


def _split(blob):
    header, frames, pos = blob[:HEADER_LEN], [], HEADER_LEN
    while pos < len(blob):
        flen = int.from_bytes(blob[pos:pos + 4], "big")
        pos += 4
        frames.append(blob[pos:pos + flen])
        pos += flen
    return header, frames


def _join(header, frames):
    out = bytearray(header)
    for f in frames:
        out += len(f).to_bytes(4, "big") + f
    return bytes(out)


def _rejected(blob) -> bool:
    try:
        open_stream(KEY, blob)
        return False
    except InvalidTag:
        return True


def main() -> None:
    print("=" * 78)
    print("STREAMING AEAD (item B) — manipulation validation")
    print("=" * 78)
    honest = seal_stream(KEY, PARTS)
    header, frames = _split(honest)

    rt = open_stream(KEY, honest) == b"".join(PARTS)
    print(f"  honest stream round-trips: {'PASS' if rt else 'FAIL'}")

    reorder = _join(header, [frames[1], frames[0]] + frames[2:])
    drop = _join(header, frames[:1] + frames[2:])
    dup = _join(header, frames[:2] + [frames[1]] + frames[2:])
    truncate = _join(header, frames[:-1])
    tamper = bytearray(honest); tamper[HEADER_LEN + 6] ^= 0x01

    checks = {
        "REORDER   (swap chunk 0 and 1)": _rejected(reorder),
        "DROP      (delete middle chunk)": _rejected(drop),
        "DUPLICATE (replay a chunk)": _rejected(dup),
        "TRUNCATE  (cut off the final chunk)": _rejected(truncate),
        "TAMPER    (flip a ciphertext bit)": _rejected(bytes(tamper)),
    }
    for name, ok in checks.items():
        print(f"  {name:38s} -> {'rejected (PASS)' if ok else 'ACCEPTED  <-- FAIL'}")

    all_ok = rt and all(checks.values())
    print("-" * 78)
    print(f"VERDICT: {'ALL PASS' if all_ok else 'FAILURE — see above'}")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
