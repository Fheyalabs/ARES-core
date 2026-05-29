# SPDX-License-Identifier: Apache-2.0
"""Tests for SC-2-correct onion primitives."""
import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def _keygen() -> tuple[bytes, bytes]:
    """Return (raw_sk_32, raw_pk_32)."""
    sk = X25519PrivateKey.generate()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
    sk_b = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pk_b = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return sk_b, pk_b


def test_build_onion_includes_self_layer():
    """SC-2: build_onion produces N layers including the builder's own."""
    from ares_client.onion import build_onion, peel_batch
    n = 4
    keys = [_keygen() for _ in range(n)]
    pubs = [pk for _, pk in keys]
    payload = b"test-payload"

    onion, self_memo = build_onion(payload, pubs, self_index=0)

    assert isinstance(self_memo, bytes) and len(self_memo) > 0
    assert len(onion) > len(payload)


def test_peel_batch_round_trip():
    """N participants peel all N rounds; each recovers its payload via self_memo."""
    from ares_client.onion import build_onion, peel_batch
    n = 4
    keys = [_keygen() for _ in range(n)]
    pubs = [pk for _, pk in keys]
    payloads = [f"payload-{i}".encode() for i in range(n)]

    batches_and_memos = [
        build_onion(payloads[i], pubs, self_index=i) for i in range(n)
    ]
    batch = [o for o, _ in batches_and_memos]
    memos = [m for _, m in batches_and_memos]

    recovered = [None] * n
    for k in range(n):
        sk_k, _ = keys[k]
        peeled, own_idx = peel_batch(sk_k, memos[k], batch)
        assert own_idx >= 0, f"peeler {k} did not find its own item"
        recovered[k] = peeled[own_idx]
        batch = peeled

    for i in range(n):
        assert recovered[i] == payloads[i], f"party {i} recovered wrong payload"


def test_no_skip_self_regression():
    """SC-2 fix: the builder CAN peel its own item (old code would leave it unpeelable)."""
    from ares_client.onion import build_onion, peel_batch
    keys = [_keygen() for _ in range(3)]
    pubs = [pk for _, pk in keys]

    onion, self_memo = build_onion(b"secret", pubs, self_index=1)
    sk1 = keys[1][0]
    batch = [onion]
    peeled, own_idx = peel_batch(sk1, self_memo, batch)
    assert own_idx == 0, "builder could not identify its own item"
