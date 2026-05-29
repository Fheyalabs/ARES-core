// SPDX-License-Identifier: Apache-2.0

package anon

// Context keys produced/consumed by the shuffle phases.
const (
	// CtxParticipants is the []string of non-initiator participant
	// identifiers (pseudonyms) in the session. Required input.
	CtxParticipants = "anon.participants"

	// CtxPeelRounds is the int count of completed peel-forward rounds.
	// Internal progress marker (not []byte, so not auto-committed).
	CtxPeelRounds = "anon.peel_rounds"

	// CtxAssembledSlotList is the []byte canonical encoding of the
	// ordered slot list (slot_index -> slot_dk_pub) produced by
	// PhaseGVerify. Auto-committed to lineage with the submission
	// nodes as parents.
	CtxAssembledSlotList = "anon.assembled_slot_list"
)

// WebSocket message types the shuffle phases consume.
const (
	// MsgOnionBatch carries a participant's initial onion (built for
	// the full peel order, including self). One per participant.
	MsgOnionBatch = "onion.batch"

	// MsgPeelForward carries a peeler's post-peel, post-shuffle batch
	// forwarded toward the next peeler. One per peeler per round.
	MsgPeelForward = "onion.peel_forward"

	// MsgSlotSubmit carries one participant's (slot_index, slot_dk_pub)
	// submission, signed by that slot's ephemeral key. One per
	// participant.
	MsgSlotSubmit = "slot.submit"
)

// internal accumulation buckets.
const (
	bucketOnions = "anon.bucket.onions"
	bucketPeels  = "anon.bucket.peels"
	bucketSlots  = "anon.bucket.slots"
)
