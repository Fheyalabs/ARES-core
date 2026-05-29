# SPDX-License-Identifier: Apache-2.0
"""SC-2-correct ECIES onion build / peel.

SC-2 fix: the builder always includes its own layer in the onion so it can
identify and peel its own submission by exact ciphertext match (self_memo).
Older code used N-2 layers and relied on "can't decrypt" as a proxy for
self-ownership — that proxy is unsound.  Here every party wraps its payload
under its own key; peel_batch passes through any item whose outer layer does
not belong to the caller (decrypt fails silently), so mixed-key batches work
without coordination.
"""
from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_PUB_LEN = 32
_NONCE_LEN = 12
_HKDF_INFO = b"ares_onion_v1"


def _ecies_encrypt(recipient_pub_bytes: bytes, plaintext: bytes) -> bytes:
    """Encrypt *plaintext* for *recipient_pub_bytes* using ephemeral ECDH + AES-GCM."""
    eph_sk = X25519PrivateKey.generate()
    eph_pk = eph_sk.public_key()
    shared = eph_sk.exchange(X25519PublicKey.from_public_bytes(recipient_pub_bytes))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO).derive(shared)
    nonce = os.urandom(_NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    pub_raw = eph_pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return pub_raw + nonce + ct


def _ecies_decrypt(recipient_sk_bytes: bytes, ciphertext: bytes) -> bytes:
    """Decrypt a ciphertext produced by :func:`_ecies_encrypt`.

    Raises :class:`cryptography.exceptions.InvalidTag` if the key is wrong or
    the ciphertext is not a valid ECIES blob.
    """
    sk = X25519PrivateKey.from_private_bytes(recipient_sk_bytes)
    if len(ciphertext) < _PUB_LEN + _NONCE_LEN + 16:  # 16 = AES-GCM tag
        raise InvalidTag
    eph_pk = X25519PublicKey.from_public_bytes(ciphertext[:_PUB_LEN])
    nonce = ciphertext[_PUB_LEN:_PUB_LEN + _NONCE_LEN]
    ct = ciphertext[_PUB_LEN + _NONCE_LEN:]
    shared = sk.exchange(eph_pk)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO).derive(shared)
    return AESGCM(key).decrypt(nonce, ct, None)


def build_onion(
    payload: bytes,
    peel_order_pubs: list[bytes],
    self_index: int,
) -> tuple[bytes, bytes]:
    """Wrap *payload* under the caller's own ECIES layer (SC-2 correct).

    The caller encrypts *payload* exclusively under
    ``peel_order_pubs[self_index]`` — their own public key.  The returned
    ``self_memo`` is the raw *payload* bytes; :func:`peel_batch` matches the
    decrypted inner value against ``self_memo`` to identify the caller's own
    item without relying on decryption failure as a proxy.

    Args:
        payload: The plaintext to protect.
        peel_order_pubs: Ordered list of raw 32-byte X25519 public keys for
            all N parties in peeling order.
        self_index: The caller's position in *peel_order_pubs*.

    Returns:
        ``(onion, self_memo)`` where *onion* is the ECIES ciphertext and
        *self_memo* is the original *payload* used to identify this item
        in :func:`peel_batch`.
    """
    if not (0 <= self_index < len(peel_order_pubs)):
        raise ValueError(f"self_index {self_index} out of range [0, {len(peel_order_pubs)})")
    onion = _ecies_encrypt(peel_order_pubs[self_index], payload)
    return onion, payload


def peel_batch(
    my_sk_bytes: bytes,
    self_memo: bytes | None,
    onions: list[bytes],
) -> tuple[list[bytes], int]:
    """Peel the caller's ECIES layer from every item in *onions*.

    Items whose outermost layer does not belong to the caller (decrypt raises
    :class:`~cryptography.exceptions.InvalidTag`) are passed through
    unchanged.  The caller's own submission is identified by comparing the
    decrypted plaintext against *self_memo*.

    Args:
        my_sk_bytes: Raw 32-byte X25519 private key.
        self_memo: Expected plaintext after peeling (the ``self_memo`` value
            returned by :func:`build_onion`).  Pass ``None`` to skip
            self-identification.
        onions: Current batch of onion blobs.

    Returns:
        ``(peeled, own_index)`` where *peeled[i]* is the decrypted inner
        blob (or the original blob if decryption failed), and *own_index* is
        the index of the caller's own item (-1 if *self_memo* is ``None``).

    Raises:
        ValueError: If *self_memo* is given but no item in the batch matches
            after attempting decryption.
    """
    peeled: list[bytes] = []
    own_index = -1
    for i, onion in enumerate(onions):
        try:
            inner = _ecies_decrypt(my_sk_bytes, onion)
        except (InvalidTag, ValueError):
            # This layer is not ours; pass the blob through unchanged.
            inner = onion
        if self_memo is not None and inner == self_memo:
            own_index = i
        peeled.append(inner)
    if self_memo is not None and own_index < 0:
        raise ValueError("self_memo did not match any item in batch")
    return peeled, own_index
