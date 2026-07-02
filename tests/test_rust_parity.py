"""
Rust-port parity (Phase 4) — the Rust core must reproduce the frozen KAT byte-for-byte.

This is the port oracle: it runs the compiled Rust binary on the same fixed inputs as the
`engine_raw` vectors in kat/vectors.json and asserts the keystream matches exactly. If the
binary isn't built, the test SKIPS (never errors) — same philosophy as /check, so CI/other
machines without a Rust toolchain still pass the Python suite.

Build the binary first:  cd rust && cargo build --release
"""
import json
import os
import subprocess

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_BIN = os.path.join(_ROOT, "rust", "target", "release", "chaos_core")
_VECTORS = os.path.join(_ROOT, "kat", "vectors.json")


def _have_binary() -> bool:
    return os.path.isfile(_BIN) and os.access(_BIN, os.X_OK)


pytestmark = pytest.mark.skipif(
    not _have_binary(),
    reason="Rust core not built — run `cd rust && cargo build --release` to enable parity tests",
)


def _frozen(key):
    with open(_VECTORS) as f:
        return json.load(f)[key]


def _frozen_engine_raw():
    return _frozen("engine_raw") if _have_binary() else []


def _frozen_multimap():
    return _frozen("multimap") if _have_binary() else []


def _rust(*cli_args) -> str:
    out = subprocess.run(
        [_BIN, *[str(a) for a in cli_args]],
        capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


@pytest.mark.parametrize("case", _frozen_engine_raw(), ids=lambda c: c["label"])
def test_rust_matches_kat_engine_raw(case):
    n = len(bytes.fromhex(case["keystream"]))
    got = _rust("ks", case["seed"], case["control"], case["nonce"], n)
    assert got == case["keystream"], (
        f"Rust core diverged from the frozen KAT for case '{case['label']}'. "
        "The port is NOT bit-identical."
    )


def test_rust_matches_kat_from_master():
    """The seed KDF (SHA-512 -> seed/control, reduced mod M / HALF) + single engine."""
    case = _frozen("from_master")
    n = len(bytes.fromhex(case["keystream"]))
    got = _rust("from_master", case["key"], case["nonce"], n)
    assert got == case["keystream"], "Rust from_master KDF diverged from the frozen KAT."


@pytest.mark.parametrize("case", _frozen_multimap(), ids=lambda c: f"n_maps={c['n_maps']}")
def test_rust_matches_kat_multimap(case):
    """The shipped keystream: N independent maps (multimap KDF, index-folded) XOR-combined."""
    n = len(bytes.fromhex(case["keystream"]))
    got = _rust("multimap", case["key"], case["nonce"], case["n_maps"], n)
    assert got == case["keystream"], (
        f"Rust multimap (n_maps={case['n_maps']}) diverged from the frozen KAT."
    )


def test_rust_matches_kat_ratchet():
    """The forward-secret stream: a one-way HMAC-SHA256 key chain re-keying every `epoch_bytes`.
    The KAT length spans several epochs (80 bytes over 32-byte epochs), so this exercises >=2 re-key
    seams — if the chain step or the epoch nonce diverged by a byte, the keystream would break here."""
    case = _frozen("ratchet")
    n = case["length"]
    got = _rust("ratchet", case["key"], case["nonce"], case["epoch_bytes"], n)
    assert got == case["keystream"], "Rust ratchet diverged from the frozen KAT (chain or epoch seam)."


def test_rust_matches_kat_aead_seal():
    """The committing AEAD (Phase 8.1): Rust seal of the fixed (key, nonce, aad, plaintext) must equal
    the frozen blob byte-for-byte (nonce || commit || ciphertext || tag) — proves the HMAC tag, the
    key-commitment, and the keystream XOR all match Python."""
    c = _frozen("aead")
    got = _rust("aead_seal", c["key"], c["nonce"], c["aad"], c["plaintext"], c["n_maps"])
    assert got == c["blob"], "Rust aead_seal diverged from the frozen KAT blob."


def test_rust_aead_open_roundtrip():
    """Rust open of the frozen blob returns the original plaintext."""
    c = _frozen("aead")
    got = _rust("aead_open", c["key"], c["aad"], c["blob"], c["n_maps"])
    assert got == c["plaintext"], "Rust aead_open did not recover the plaintext."


def test_rust_aead_open_rejects_tamper():
    """A flipped ciphertext byte must make Rust open fail closed (prints INVALID, no plaintext)."""
    c = _frozen("aead")
    blob = bytearray(bytes.fromhex(c["blob"]))
    blob[16 + 32 + 1] ^= 0x01           # flip a ciphertext byte (past nonce + commitment)
    got = _rust("aead_open", c["key"], c["aad"], blob.hex(), c["n_maps"])
    assert got == "INVALID", "Rust aead_open accepted a tampered blob."


def test_python_opens_rust_sealed_blob():
    """Real interop: a blob SEALED by the Rust core must OPEN under the Python shell (and vice versa is
    covered by test_rust_aead_open_roundtrip on the Python-generated KAT blob). This proves the two
    implementations are wire-compatible, not just internally self-consistent."""
    import sys
    sys.path.insert(0, _ROOT)
    from cipher.aead import open_  # noqa: E402

    c = _frozen("aead")
    rust_blob = bytes.fromhex(_rust("aead_seal", c["key"], c["nonce"], c["aad"],
                                    c["plaintext"], c["n_maps"]))
    opened = open_(bytes.fromhex(c["key"]), rust_blob, aad=bytes.fromhex(c["aad"]),
                   n_maps=c["n_maps"])
    assert opened == bytes.fromhex(c["plaintext"]), "Python could not open the Rust-sealed blob."


def test_rust_matches_kat_stream_seal():
    """The streaming AEAD (Phase 8.2): Rust seal of the fixed (key, salt, aad, chunks) must equal the
    frozen blob — proves header, per-chunk framing, nonces, tags and the final-flag all match Python."""
    c = _frozen("stream")
    got = _rust("stream_seal", c["key"], c["salt"], c["aad"], c["n_maps"], *c["chunks"])
    assert got == c["blob"], "Rust stream_seal diverged from the frozen KAT blob."


def test_rust_stream_open_roundtrip():
    c = _frozen("stream")
    got = _rust("stream_open", c["key"], c["aad"], c["n_maps"], c["blob"])
    assert got == c["plaintext"], "Rust stream_open did not recover the concatenated plaintext."


def test_rust_stream_open_rejects_tamper():
    c = _frozen("stream")
    blob = bytearray(bytes.fromhex(c["blob"]))
    blob[16 + 32 + 4 + 1] ^= 0x01        # flip a byte in the first chunk's ciphertext
    got = _rust("stream_open", c["key"], c["aad"], c["n_maps"], blob.hex())
    assert got == "INVALID", "Rust stream_open accepted a tampered stream."


def test_python_opens_rust_sealed_stream():
    """Interop: a stream sealed by Rust must open under the Python streaming shell."""
    import sys
    sys.path.insert(0, _ROOT)
    from cipher.streaming import open_stream  # noqa: E402

    c = _frozen("stream")
    rust_blob = bytes.fromhex(_rust("stream_seal", c["key"], c["salt"], c["aad"],
                                    c["n_maps"], *c["chunks"]))
    opened = open_stream(bytes.fromhex(c["key"]), rust_blob, aad=bytes.fromhex(c["aad"]),
                         n_maps=c["n_maps"])
    assert opened == bytes.fromhex(c["plaintext"]), "Python could not open the Rust-sealed stream."


def test_rust_matches_kat_ratchet_aead_seal():
    """The ratchet session AEAD (Phase 8.3): driving a Rust sender session through the 3 KAT messages
    (with the pinned per-message inner nonces) must reproduce all 3 frozen wires byte-for-byte —
    proves the one-way chain, per-message key derivation, index-bound aad and inner blob all match
    Python across two chain seams (index 0->1->2)."""
    c = _frozen("ratchet_aead")
    pairs = [x for pair in zip(c["inner_nonces"], c["plaintexts"]) for x in pair]
    got = _rust("ratchet_aead_seal", c["master"], c["nonce"], c["aad"], c["n_maps"], *pairs)
    assert got == " ".join(c["wires"]), "Rust ratchet_aead_seal diverged from the frozen KAT wires."


def test_rust_ratchet_aead_open_roundtrip():
    c = _frozen("ratchet_aead")
    got = _rust("ratchet_aead_open", c["master"], c["nonce"], c["aad"], c["n_maps"], *c["wires"])
    assert got == " ".join(c["plaintexts"]), "Rust ratchet_aead_open did not recover the plaintexts."


def test_rust_ratchet_aead_open_rejects_tamper():
    """Flip a byte in the first wire's inner ciphertext: the inner committing AEAD must reject it,
    so the whole run reports INVALID."""
    c = _frozen("ratchet_aead")
    wires = list(c["wires"])
    bad = bytearray(bytes.fromhex(wires[0]))
    bad[8 + 16 + 32 + 1] ^= 0x01     # index(8) || nonce(16) || commit(32) || [ct...] — flip first ct byte
    wires[0] = bad.hex()
    got = _rust("ratchet_aead_open", c["master"], c["nonce"], c["aad"], c["n_maps"], *wires)
    assert got == "INVALID", "Rust ratchet_aead_open accepted a tampered session message."


def test_rust_ratchet_aead_open_rejects_wire_index_tamper():
    """The message index is sealed into the inner aad; bumping it on the wire must fail to open."""
    c = _frozen("ratchet_aead")
    wires = list(c["wires"])
    bad = bytearray(bytes.fromhex(wires[0]))
    bad[7] ^= 0x01                   # bump the 8-byte index from 0 to 1
    wires[0] = bad.hex()
    got = _rust("ratchet_aead_open", c["master"], c["nonce"], c["aad"], c["n_maps"], *wires)
    assert got == "INVALID", "Rust ratchet_aead_open accepted a tampered wire index."


def test_python_opens_rust_sealed_ratchet_aead():
    """Interop: a session sealed by the Rust core must open, in order, under the Python session shell."""
    import sys
    sys.path.insert(0, _ROOT)
    from cipher.ratchet_aead import ReceiverSession  # noqa: E402

    c = _frozen("ratchet_aead")
    pairs = [x for pair in zip(c["inner_nonces"], c["plaintexts"]) for x in pair]
    rust_wires = _rust("ratchet_aead_seal", c["master"], c["nonce"], c["aad"],
                       c["n_maps"], *pairs).split()
    rx = ReceiverSession(bytes.fromhex(c["master"]), bytes.fromhex(c["nonce"]),
                         aad=bytes.fromhex(c["aad"]))
    opened = [rx.open(bytes.fromhex(w)) for w in rust_wires]
    assert opened == [bytes.fromhex(p) for p in c["plaintexts"]], \
        "Python could not open the Rust-sealed session."


def test_rust_matches_kat_twolock_seal():
    """Two-locks (Phase 8.4): for each inner cipher, Rust seal of the fixed (master, nonces, aad, pt)
    must equal the frozen blob byte-for-byte — proves the HKDF key-split, the vetted inner vault
    (AES-256-GCM / ChaCha20-Poly1305), and the outer chaos wall all match Python."""
    c = _frozen("twolock")
    for alg, blob in c["blobs"].items():
        got = _rust("twolock_seal", c["master"], c["outer_nonce"], c["inner_nonce"],
                    c["aad"], c["plaintext"], alg, c["n_maps"])
        assert got == blob, f"Rust twolock_seal ({alg}) diverged from the frozen KAT blob."


def test_rust_twolock_open_roundtrip():
    """Rust open of each frozen two-locks blob returns the original plaintext (peels chaos, then vault)."""
    c = _frozen("twolock")
    for blob in c["blobs"].values():
        got = _rust("twolock_open", c["master"], c["aad"], blob, c["n_maps"])
        assert got == c["plaintext"], "Rust twolock_open did not recover the plaintext."


def test_rust_twolock_rejects_tamper():
    """A flipped outer-ciphertext byte must make Rust two-locks open fail closed (INVALID, no plaintext)."""
    c = _frozen("twolock")
    blob = bytearray(bytes.fromhex(c["blobs"]["aes-256-gcm"]))
    blob[16 + 32 + 1] ^= 0x01           # flip an outer-wall ciphertext byte (past nonce + commitment)
    got = _rust("twolock_open", c["master"], c["aad"], blob.hex(), c["n_maps"])
    assert got == "INVALID", "Rust twolock_open accepted a tampered blob."


def test_python_opens_rust_sealed_twolock():
    """Real interop: a two-locks blob SEALED by the Rust core must OPEN under the Python shell, for BOTH
    inner ciphers. This is what proves Rust's HKDF + AES-GCM/ChaCha + chaos wall are wire-compatible with
    Python's `cryptography` library, not just internally self-consistent."""
    import sys
    sys.path.insert(0, _ROOT)
    from cipher.twolock import open_twolock  # noqa: E402

    c = _frozen("twolock")
    for alg in c["blobs"]:
        rust_blob = bytes.fromhex(_rust("twolock_seal", c["master"], c["outer_nonce"],
                                        c["inner_nonce"], c["aad"], c["plaintext"], alg, c["n_maps"]))
        opened = open_twolock(bytes.fromhex(c["master"]), rust_blob, aad=bytes.fromhex(c["aad"]))
        assert opened == bytes.fromhex(c["plaintext"]), \
            f"Python could not open the Rust-sealed two-locks blob ({alg})."


# --- Phase 8.5 key agreement: classical DH + post-quantum hybrid ---

try:
    from cryptography.hazmat.primitives.asymmetric import mlkem as _mlkem  # noqa: E402
    _HAVE_MLKEM = True
except Exception:                                    # pragma: no cover - platform dependent
    _HAVE_MLKEM = False

_needs_mlkem = pytest.mark.skipif(
    not _HAVE_MLKEM, reason="ML-KEM backend (cryptography on OpenSSL 3.5+) unavailable"
)


def test_rust_matches_kat_dh():
    """Classical DH (Phase 8.5): Rust reproduces the frozen public values, the raw shared element, and the
    SHA-512-derived key for BOTH parties — proves the 2048-bit modular exponentiation and KDF match Python."""
    c = _frozen("keyexchange")
    assert _rust("dh_public", c["private_a"]) == c["public_a"]
    assert _rust("dh_public", c["private_b"]) == c["public_b"]
    # both directions of the exchange land on the same raw secret and the same derived key
    assert _rust("dh_raw_shared", c["private_a"], c["public_b"]) == c["raw_shared"]
    assert _rust("dh_raw_shared", c["private_b"], c["public_a"]) == c["raw_shared"]
    assert _rust("dh_shared_key", c["private_a"], c["public_b"], c["info"]) == c["shared_key"]
    assert _rust("dh_shared_key", c["private_b"], c["public_a"], c["info"]) == c["shared_key"]


def test_rust_matches_kat_mlkem_decapsulate():
    """ML-KEM-768 (Phase 8.5): Rust regenerates the encapsulation key from the frozen seed and decapsulates
    the frozen ciphertext to the frozen secret — proves RustCrypto's `ml-kem` matches the pinned vector
    (and, via the generator's self-check, OpenSSL). No Python ML-KEM backend needed here."""
    c = _frozen("pq_hybrid")
    assert _rust("mlkem_ek", c["seed"]) == c["ek"]
    assert _rust("mlkem_decapsulate", c["seed"], c["ct"]) == c["pq_secret"]


def test_rust_matches_kat_hybrid_combine():
    """Hybrid combiner (Phase 8.5): Rust's SP 800-56C combiner over the frozen (classical, pq, info,
    transcript) reproduces the frozen session key byte-for-byte — proves the transcript build + the
    length-prefixed SHA-512 mix match pq_keyexchange.py. Pure hashing, no ML-KEM backend needed."""
    c = _frozen("pq_hybrid")
    got = _rust("hybrid_combine", c["classical"], c["pq_secret"], c["info"],
                c["dh_a"], c["dh_b"], c["ek"], c["ct"])
    assert got == c["key"], "Rust hybrid_combine diverged from the frozen KAT key."


@_needs_mlkem
def test_rust_python_mlkem_interop_both_ways():
    """Real ML-KEM interop: Rust encapsulates against a Python key and Python decapsulates to the same
    secret, and vice versa. This is what proves RustCrypto and OpenSSL are wire-compatible, not just
    each self-consistent."""
    import os
    # Rust encapsulates -> Python decapsulates
    seed = os.urandom(64)
    py_sk = _mlkem.MLKEM768PrivateKey.from_seed_bytes(seed)
    ek = py_sk.public_key().public_bytes_raw()
    m = os.urandom(32)
    ct_hex, ss_rust = _rust("mlkem_encapsulate", ek.hex(), m.hex()).split()
    assert py_sk.decapsulate(bytes.fromhex(ct_hex)).hex() == ss_rust

    # Python encapsulates -> Rust decapsulates
    ss_py, ct_py = py_sk.public_key().encapsulate()
    assert _rust("mlkem_decapsulate", seed.hex(), ct_py.hex()) == ss_py.hex()


@_needs_mlkem
def test_rust_python_hybrid_handshake_both_ways():
    """Real hybrid-handshake interop: a Rust responder agrees the same session key with a Python initiator,
    and a Python responder agrees with a Rust initiator. Proves the full classical+PQ handshake (DH,
    ML-KEM, transcript, combiner) is wire-compatible end to end across the two implementations."""
    import os
    import sys
    sys.path.insert(0, _ROOT)
    from cipher.keyexchange import P, DHParty  # noqa: E402
    from cipher.pq_keyexchange import _combine, _transcript  # noqa: E402

    info = b"interop"

    # --- Rust RESPONDER  <->  Python INITIATOR ---
    a = int.from_bytes(os.urandom(32), "big")
    seed = os.urandom(64)
    dh_a = DHParty(a)
    py_sk = _mlkem.MLKEM768PrivateKey.from_seed_bytes(seed)
    kem_pk = py_sk.public_key().public_bytes_raw()
    b = int.from_bytes(os.urandom(32), "big")
    m = os.urandom(32)
    dh_b_hex, ct_hex, key_b = _rust("hybrid_respond", format(b, "064x"),
                                    format(dh_a.public, "0512x"), kem_pk.hex(), m.hex(), info.hex()).split()
    classical = dh_a.raw_shared_secret(int(dh_b_hex, 16))
    pq = py_sk.decapsulate(bytes.fromhex(ct_hex))
    tr = _transcript(dh_a.public, int(dh_b_hex, 16), kem_pk, bytes.fromhex(ct_hex))
    key_a = _combine(classical, pq, tr, info).hex()
    assert key_a == key_b, "Rust responder and Python initiator disagreed."

    # --- Python RESPONDER  <->  Rust INITIATOR ---
    a2 = int.from_bytes(os.urandom(32), "big")
    seed2 = os.urandom(64)
    dh_a2 = pow(2, a2, P)
    kem_pk2 = _mlkem.MLKEM768PrivateKey.from_seed_bytes(seed2).public_key().public_bytes_raw()
    dh_b2 = DHParty(int.from_bytes(os.urandom(32), "big"))
    classical2 = dh_b2.raw_shared_secret(dh_a2)
    pq2, ct2 = _mlkem.MLKEM768PublicKey.from_public_bytes(kem_pk2).encapsulate()
    key_b2 = _combine(classical2, pq2, _transcript(dh_a2, dh_b2.public, kem_pk2, ct2), info).hex()
    key_a2 = _rust("hybrid_initiator_key", format(a2, "064x"), seed2.hex(),
                   format(dh_b2.public, "0512x"), ct2.hex(), info.hex())
    assert key_a2 == key_b2, "Python responder and Rust initiator disagreed."


# --- Phase 8.6 authenticated post-quantum handshake: triple-DH static binding + ML-DSA-65 signatures ---

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa  # noqa: E402
    _HAVE_MLDSA = True
except Exception:                                    # pragma: no cover - platform dependent
    _HAVE_MLDSA = False

_needs_mldsa = pytest.mark.skipif(
    not _HAVE_MLDSA, reason="ML-DSA backend (cryptography on OpenSSL 3.5+) unavailable"
)


def test_rust_matches_kat_mldsa_public():
    """ML-DSA-65 keygen (Phase 8.6): Rust regenerates the SAME 1952-byte verifying key from the frozen
    32-byte seed for both identities — proves RustCrypto's `ml-dsa` matches the pinned vector (and, via the
    generator's self-check, OpenSSL). No Python ML-DSA backend needed here."""
    c = _frozen("auth_pq")
    assert _rust("mldsa_public", c["a_sig_seed"]) == c["a_sig_pub"]
    assert _rust("mldsa_public", c["b_sig_seed"]) == c["b_sig_pub"]


def test_rust_matches_kat_auth_fingerprint():
    """Identity fingerprint (Phase 8.6): Rust binds the ML-DSA public + static DH public into the same
    8-byte fingerprint Python prints — proves the sha256 binding matches PublicIdentity.fingerprint."""
    c = _frozen("auth_pq")
    assert _rust("auth_fingerprint", c["a_sig_pub"], c["a_static_pub"]) == c["a_fingerprint"]
    assert _rust("auth_fingerprint", c["b_sig_pub"], c["b_static_pub"]) == c["b_fingerprint"]


def test_rust_matches_kat_auth_transcript():
    """Transcript binding (Phase 8.6): Rust's SHA-512 over both identities + every public value reproduces
    the frozen 64-byte transcript digest — proves the length-prefixed field order matches _transcript."""
    c = _frozen("auth_pq")
    got = _rust("auth_transcript", c["a_sig_pub"], c["a_static_pub"], c["b_sig_pub"], c["b_static_pub"],
                c["dh_i"], c["kem_pk_i"], c["dh_r"], c["kem_ct"])
    assert got == c["transcript"], "Rust auth_transcript diverged from the frozen KAT."


def test_rust_matches_kat_auth_combine():
    """Authenticated combiner (Phase 8.6): Rust mixes the confidentiality secrets (ee, pq) AND the sorted
    static binding terms (es, se) with the transcript to the frozen session key — proves the combiner
    matches _combine byte-for-byte. Pure hashing, no PQ backend needed."""
    c = _frozen("auth_pq")
    got = _rust("auth_combine", c["ee"], c["pq_secret"], c["es"], c["se"], c["transcript"], c["info"])
    assert got == c["key"], "Rust auth_combine diverged from the frozen KAT key."


def test_rust_auth_handshake_roundtrip_matches_kat():
    """Full Rust handshake (Phase 8.6): the Rust responder reproduces the frozen transcript, ciphertext and
    session key from the pinned ephemerals + encaps message, the Rust initiator derives the SAME key after
    verifying the responder, and the responder confirms the initiator. A tampered responder signature makes
    the initiator refuse (no key). Self-contained — no Python PQ backend needed."""
    c = _frozen("auth_pq")
    resp = _rust("auth_responder_respond", c["b_sig_seed"], c["b_static_priv"], c["b_eph_priv"],
                 c["a_sig_pub"], c["a_static_pub"], c["dh_i"], c["kem_pk_i"], c["kem_m"], c["info"])
    dh_r, kem_ct, sig_r, key_b, transcript = resp.split()
    assert dh_r == c["dh_r"], "Rust responder ephemeral DH public diverged from the KAT."
    assert kem_ct == c["kem_ct"], "Rust responder ciphertext diverged from the frozen KAT."
    assert transcript == c["transcript"], "Rust responder transcript diverged from the KAT."
    assert key_b == c["key"], "Rust responder session key diverged from the frozen KAT."

    fin = _rust("auth_initiator_finish", c["a_sig_seed"], c["a_static_priv"], c["a_eph_priv"],
                c["kem_seed"], c["b_sig_pub"], c["b_static_pub"], dh_r, kem_ct, sig_r, c["info"])
    key_a, sig_i = fin.split()
    assert key_a == c["key"], "Rust initiator and the frozen KAT key disagree."
    assert _rust("auth_responder_confirm", transcript, c["a_sig_pub"], sig_i) == "OK"

    # a tampered responder signature -> the initiator refuses, returning INVALID (key never derived)
    bad_sig_r = bytearray.fromhex(sig_r)
    bad_sig_r[200] ^= 0x01
    assert _rust("auth_initiator_finish", c["a_sig_seed"], c["a_static_priv"], c["a_eph_priv"],
                 c["kem_seed"], c["b_sig_pub"], c["b_static_pub"], dh_r, kem_ct,
                 bad_sig_r.hex(), c["info"]) == "INVALID"


@_needs_mldsa
def test_rust_python_mldsa_signature_interop_both_ways():
    """Real ML-DSA interop: Python (OpenSSL, hedged) verifies a Rust deterministic signature, and Rust
    verifies a Python signature — both over the same message under the same seed's key. This is what proves
    RustCrypto and OpenSSL are wire-compatible signatures, not just each self-consistent."""
    import os
    seed = os.urandom(32)
    msg = b"cross-impl authentication"
    py_sk = _mldsa.MLDSA65PrivateKey.from_seed_bytes(seed)
    pub = py_sk.public_key().public_bytes_raw()
    # Rust signs -> Python verifies (raises if invalid)
    rust_sig = bytes.fromhex(_rust("mldsa_sign", seed.hex(), msg.hex()))
    py_sk.public_key().verify(rust_sig, msg)
    # Python signs -> Rust verifies
    py_sig = py_sk.sign(msg)
    assert _rust("mldsa_verify", pub.hex(), msg.hex(), py_sig.hex()) == "OK"


@_needs_mldsa
def test_rust_python_auth_handshake_both_ways():
    """Real authenticated-handshake interop: a Rust responder agrees the same session key with a Python
    initiator (and verifies its signature), and a Python responder agrees with a Rust initiator. Proves the
    full authenticated PQ handshake — DH, ML-KEM, ML-DSA, transcript, combiner — is wire-compatible end to
    end across the two implementations."""
    import os
    import sys
    sys.path.insert(0, _ROOT)
    from cipher.keyexchange import DHParty  # noqa: E402
    from cipher.auth_pq_keyexchange import (  # noqa: E402
        PublicIdentity, _SIG_CTX_INITIATOR, _SIG_CTX_RESPONDER, _combine as _acombine,
        _transcript as _atranscript,
    )

    info = b"auth-interop"

    # DHParty hides its exponent, so generate it as an int (32 bytes, in range like the 8.5 test) and keep
    # both the int (to feed Rust as the private hex) and the party (for Python's .public / shared secrets).
    def _dh():
        x = int.from_bytes(os.urandom(32), "big")
        return x, DHParty(x)

    # ---------- Rust RESPONDER  <->  Python INITIATOR ----------
    a_sig_seed, b_sig_seed = os.urandom(32), os.urandom(32)
    a_static_x, a_static = _dh()
    b_static_x, b_static = _dh()
    a_eph_x, a_eph = _dh()
    b_eph_x, b_eph = _dh()
    a_kem_seed = os.urandom(64)
    a_kem = _mlkem.MLKEM768PrivateKey.from_seed_bytes(a_kem_seed)
    kem_pk_i = a_kem.public_key().public_bytes_raw()
    a_sig_pub = _mldsa.MLDSA65PrivateKey.from_seed_bytes(a_sig_seed).public_key().public_bytes_raw()
    b_sig_pub = _mldsa.MLDSA65PrivateKey.from_seed_bytes(b_sig_seed).public_key().public_bytes_raw()
    alice = PublicIdentity(sig_public=a_sig_pub, static_public=a_static.public)
    bob = PublicIdentity(sig_public=b_sig_pub, static_public=b_static.public)
    kem_m = os.urandom(32)

    resp = _rust("auth_responder_respond", b_sig_seed.hex(), format(b_static_x, "064x"),
                 format(b_eph_x, "064x"), a_sig_pub.hex(), format(a_static.public, "0512x"),
                 format(a_eph.public, "0512x"), kem_pk_i.hex(), kem_m.hex(), info.hex())
    dh_r_hex, ct_hex, sig_r_hex, key_b, _tr_hex = resp.split()
    # Python initiator: build the transcript, verify the responder's signature, derive the key, sign back.
    transcript = _atranscript(alice, bob, a_eph.public, kem_pk_i, int(dh_r_hex, 16), bytes.fromhex(ct_hex))
    _mldsa.MLDSA65PublicKey.from_public_bytes(b_sig_pub).verify(
        bytes.fromhex(sig_r_hex), _SIG_CTX_RESPONDER + transcript)   # raises if Rust's signature is bad
    ee = a_eph.raw_shared_secret(int(dh_r_hex, 16))
    pq = a_kem.decapsulate(bytes.fromhex(ct_hex))
    es = a_eph.raw_shared_secret(bob.static_public)
    se = a_static.raw_shared_secret(int(dh_r_hex, 16))
    key_a = _acombine(ee, pq, es, se, transcript, info).hex()
    assert key_a == key_b, "Rust responder and Python initiator disagreed on the session key."
    sig_i = _mldsa.MLDSA65PrivateKey.from_seed_bytes(a_sig_seed).sign(_SIG_CTX_INITIATOR + transcript)
    assert _rust("auth_responder_confirm", transcript.hex(), a_sig_pub.hex(), sig_i.hex()) == "OK"

    # ---------- Python RESPONDER  <->  Rust INITIATOR ----------
    a_sig_seed2, b_sig_seed2 = os.urandom(32), os.urandom(32)
    a_static2_x, a_static2 = _dh()
    b_static2_x, b_static2 = _dh()
    a_eph2_x, a_eph2 = _dh()
    b_eph2_x, b_eph2 = _dh()
    a_kem_seed2 = os.urandom(64)
    kem_pk_i2 = _mlkem.MLKEM768PrivateKey.from_seed_bytes(a_kem_seed2).public_key().public_bytes_raw()
    a_sig_pub2 = _mldsa.MLDSA65PrivateKey.from_seed_bytes(a_sig_seed2).public_key().public_bytes_raw()
    b_sig_sk2 = _mldsa.MLDSA65PrivateKey.from_seed_bytes(b_sig_seed2)
    b_sig_pub2 = b_sig_sk2.public_key().public_bytes_raw()
    alice2 = PublicIdentity(sig_public=a_sig_pub2, static_public=a_static2.public)
    bob2 = PublicIdentity(sig_public=b_sig_pub2, static_public=b_static2.public)
    # Python responder: encapsulate, derive the key, sign the transcript.
    pq2, ct2 = _mlkem.MLKEM768PublicKey.from_public_bytes(kem_pk_i2).encapsulate()
    transcript2 = _atranscript(alice2, bob2, a_eph2.public, kem_pk_i2, b_eph2.public, ct2)
    ee2 = b_eph2.raw_shared_secret(a_eph2.public)
    es2 = b_static2.raw_shared_secret(a_eph2.public)
    se2 = b_eph2.raw_shared_secret(a_static2.public)
    key_b2 = _acombine(ee2, pq2, es2, se2, transcript2, info).hex()
    sig_r2 = b_sig_sk2.sign(_SIG_CTX_RESPONDER + transcript2)
    # Rust initiator: verify the responder, derive the key, sign back.
    fin = _rust("auth_initiator_finish", a_sig_seed2.hex(), format(a_static2_x, "064x"),
                format(a_eph2_x, "064x"), a_kem_seed2.hex(), b_sig_pub2.hex(),
                format(b_static2.public, "0512x"), format(b_eph2.public, "0512x"), ct2.hex(),
                sig_r2.hex(), info.hex())
    assert fin != "INVALID", "Rust initiator rejected the Python responder's signature."
    key_a2, sig_i2 = fin.split()
    assert key_a2 == key_b2, "Python responder and Rust initiator disagreed on the session key."
    # Python responder confirms the Rust initiator's signature.
    _mldsa.MLDSA65PublicKey.from_public_bytes(a_sig_pub2).verify(
        bytes.fromhex(sig_i2), _SIG_CTX_INITIATOR + transcript2)     # raises if Rust's signature is bad
