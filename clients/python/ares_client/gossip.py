# SPDX-License-Identifier: Apache-2.0
"""Generic gossip-arc participant, mirroring Go's anon.Participant.

GossipParticipant owns one non-initiator's per-session shuffle state:
its X25519 slot delivery keypair, its position in the peel order
(self_index, which also serves as slot_index), and the session ID for
lineage signing.

Protocol note — variable-depth onions
--------------------------------------
Each participant builds an onion with exactly ``self_index + 1`` layers
(not a flat N-layer onion).  Layer 0 is outermost; layer ``self_index``
is innermost and encrypts the final plaintext.  This means:

- After peel rounds 0 .. self_index-1 strip the outer layers, the item
  arrives at round ``self_index`` as a single ECIES blob (self_memo).
- Participant ``self_index`` decrypts that single layer to recover the
  plaintext directly — no further rounds needed.
- Items from earlier participants (lower self_index) are already plaintext
  by the time later participants peel; the fault-tolerant peel pass-through
  leaves them unchanged.
"""
from __future__ import annotations

import base64
import json

from cryptography.exceptions import InvalidTag

from .lineage import build_slot_node
from .onion import build_onion, _ecies_decrypt


class GossipParticipant:
    """One participant's client-side gossip arc state.

    Args:
        session_id: ARES session identifier (used in lineage node).
        self_index: this participant's position in the peel order (0-based).
                    Also used as slot_index in the slot submission payload.
        slot_dk_sk: raw 32-byte X25519 private key (slot delivery key).
        slot_dk_pub: raw 32-byte X25519 public key.
    """

    def __init__(
        self,
        session_id: str,
        self_index: int,
        slot_dk_sk: bytes,
        slot_dk_pub: bytes,
    ) -> None:
        self._session_id = session_id
        self._self_index = self_index
        self._slot_dk_sk = slot_dk_sk
        self._slot_dk_pub = slot_dk_pub

    def build_batch(self, peer_pubs: list[bytes]) -> tuple[dict, bytes]:
        """Build the initial onion batch payload for onion.batch submission.

        Each participant wraps their slot entry in exactly ``self_index + 1``
        ECIES layers — one per peeler up to and including themselves.  This
        ensures the item is fully decrypted when it reaches the participant's
        own peel round (no residual layers remain after their peel).

        Args:
            peer_pubs: raw X25519 pubkeys of ALL participants in peel order
                       (including self at self_index).

        Returns:
            (batch_payload_dict, self_memo) — batch_payload_dict has key
            "onions" with a list of base64-encoded onion bytes (one entry,
            this participant's onion). self_memo is passed to peel_round
            for self-identification via ciphertext match.
        """
        slot_entry = json.dumps(
            {"slot_index": self._self_index, "slot_dk_pub": self._slot_dk_pub.hex()},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        # Build with only the first (self_index + 1) pubkeys so that the onion
        # is fully unwrapped at round self_index.
        depth_pubs = peer_pubs[: self._self_index + 1]
        onion, self_memo = build_onion(slot_entry, depth_pubs, self._self_index)
        return {"onions": [base64.b64encode(onion).decode()]}, self_memo

    def peel_round(
        self,
        self_memo: bytes,
        onions: list[bytes],
    ) -> tuple[list[bytes], bytes | None]:
        """Peel one ECIES layer from each onion; return forwarded batch and own payload.

        Items that have already been fully decrypted by a prior round (they are
        raw plaintext, not valid ECIES blobs) are passed through unchanged so
        that later peelers do not trip on them.  The caller's own item is
        identified by exact ciphertext match against ``self_memo`` BEFORE
        decryption (SC-2-correct; no decryption-failure side-channel).

        Args:
            self_memo: returned by build_batch; used for ciphertext-match
                       self-identification.
            onions: raw blobs from the server broadcast — may include already-
                    decrypted items from earlier peel rounds.

        Returns:
            (peeled_onions, own_payload) — own_payload is the decrypted
            innermost bytes for this participant's own item (valid plaintext
            JSON), None if not found.
        """
        peeled: list[bytes] = []
        own_payload: bytes | None = None

        for item in onions:
            is_own = item == self_memo
            try:
                inner = _ecies_decrypt(self._slot_dk_sk, item)
            except (InvalidTag, Exception):
                # Item has already been fully decrypted in a prior round;
                # pass it through unchanged.
                inner = item
            if is_own:
                own_payload = inner
            peeled.append(inner)

        return peeled, own_payload

    def slot_submission(self) -> tuple[bytes, dict]:
        """Build the slot.submit payload bytes and signed lineage node.

        Returns:
            (payload_bytes, node_dict) — payload_bytes are the exact bytes
            to send as WSMessage.payload; node_dict is the SC-10 lineage
            DAGNode to attach as WSMessage.lineage.
        """
        payload_bytes = json.dumps(
            {"slot_index": self._self_index, "slot_dk_pub": self._slot_dk_pub.hex()},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        node_dict, _sk, _pk = build_slot_node(
            session_id=self._session_id,
            payload_bytes=payload_bytes,
        )
        return payload_bytes, node_dict
