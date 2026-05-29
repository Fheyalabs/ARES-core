# SPDX-License-Identifier: Apache-2.0
"""Tests for GossipParticipant — full onion build/peel/submit cycle."""
import json
import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)


def _x25519_keygen() -> tuple[bytes, bytes]:
    sk = X25519PrivateKey.generate()
    sk_b = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pk_b = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return sk_b, pk_b


def test_gossip_participant_full_cycle():
    """N=3 participants: build onions, peel N rounds, each recovers its payload."""
    from ares_client.gossip import GossipParticipant

    n = 3
    session_id = "gossip-test-session"
    keys = [_x25519_keygen() for _ in range(n)]
    pubs = [pk for _, pk in keys]

    participants = [
        GossipParticipant(
            session_id=session_id,
            self_index=i,
            slot_dk_sk=keys[i][0],
            slot_dk_pub=keys[i][1],
        )
        for i in range(n)
    ]

    # Each builds their onion batch
    batches = []
    memos = []
    for i, p in enumerate(participants):
        batch_payload, self_memo = p.build_batch(pubs)
        # batch_payload is a dict {"onions": [<base64>]}
        onions_raw = [
            __import__("base64").b64decode(o) for o in batch_payload["onions"]
        ]
        batches.append(onions_raw)
        memos.append(self_memo)

    # Combine into one shared batch (one onion per sender)
    shared_batch = [batches[i][0] for i in range(n)]

    # Each participant peels the shared batch
    for k in range(n):
        peeled, own_payload = participants[k].peel_round(memos[k], shared_batch)
        assert own_payload is not None, f"participant {k} did not find its own payload"
        slot_data = json.loads(own_payload)
        assert slot_data["slot_index"] == k
        assert slot_data["slot_dk_pub"] == keys[k][1].hex()
        shared_batch = peeled

    # Each builds their slot submission
    for p in participants:
        payload_bytes, node_dict = p.slot_submission()
        assert isinstance(payload_bytes, bytes)
        slot = json.loads(payload_bytes)
        assert "slot_index" in slot
        assert "slot_dk_pub" in slot
        assert node_dict["phase_id"] == "anon-g-verify"
        assert node_dict["role"] == "slot-submission"
        assert node_dict["algorithm"] == "ed25519"
        assert len(node_dict["hash"]) == 64
        assert len(node_dict["signature"]) == 128
