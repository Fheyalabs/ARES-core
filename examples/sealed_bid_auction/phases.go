package sealedbidauction

import "github.com/Fheyalabs/ares-core/pkg/ares/phase"

// PhaseInvitation opens an auction. The auctioneer picks N bidders
// from the registered pool, pins the CKKS parameters appropriate to
// the argmax scoring circuit (much shallower than Fheya's cosine
// chain), and broadcasts `auction.invitation` to each participant.
//
// Compare to defaults.Phase1aSessionInitiation: same shape (server-
// side decision, no WS in, transitions on acceptance) but the crypto
// contract carries depth=10 instead of depth=30 — the chief
// performance win of moving from a vector cosine circuit to a scalar
// argmax circuit.
type PhaseInvitation struct{}

func NewPhaseInvitation() *PhaseInvitation { return &PhaseInvitation{} }

func (PhaseInvitation) Name() string                                                              { return "auction-invitation" }
func (PhaseInvitation) Lifetime() phase.Lifetime                                                  { return phase.LifetimePerSession }
func (PhaseInvitation) RunsAt() phase.RunsAt                                                      { return phase.RunsAtInline }
func (PhaseInvitation) EntryState() phase.SessionState                                            { return StateAuctionInviting }
func (PhaseInvitation) ExitState() phase.SessionState                                             { return StateAuctionLocked }
func (PhaseInvitation) ConsumedMessageTypes() []string                                            { return nil }
func (PhaseInvitation) InternalStates() []phase.SessionState                                      { return nil }
func (PhaseInvitation) Requires() phase.ContextSchema                                             { return nil }
func (PhaseInvitation) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxAuctionParticipants: {TypeName: "[]string"},
		CtxAuctionCryptoContract: {
			TypeName: "OpenFHEContract",
			Constraints: map[string]any{
				"depth":            10,
				"ring_dim":         2048,
				"scaling_mod_size": 40,
			},
		},
	}
}
func (PhaseInvitation) Enter(*phase.SessionContext) error                                         { return nil }
func (PhaseInvitation) OnMessage(*phase.SessionContext, string, string, []byte) error             { return nil }
func (PhaseInvitation) CheckComplete(*phase.SessionContext) bool                                  { return true }
func (PhaseInvitation) Exit(*phase.SessionContext) error                                          { return nil }

// PhaseKeygen runs the chained N-party threshold CKKS keygen and
// produces the collective public key, the per-bidder secret shares,
// and the joint evaluation keys for the argmax circuit.
//
// Same crypto protocol as defaults.Phase0aThresholdKeygen, but the
// state arc is LOCKED → BIDDING (the auction skips onion shuffle
// and verification entirely). When task #14 lands the non-MPC
// keygen variants, the auction will be able to swap this phase for
// SinglePartyKeygen and run dramatically faster, trading the
// threshold property for an auctioneer-trusted execution model.
type PhaseKeygen struct{}

func NewPhaseKeygen() *PhaseKeygen { return &PhaseKeygen{} }

func (PhaseKeygen) Name() string                   { return "auction-keygen" }
func (PhaseKeygen) Lifetime() phase.Lifetime       { return phase.LifetimePerSession }
func (PhaseKeygen) RunsAt() phase.RunsAt           { return phase.RunsAtInline }
func (PhaseKeygen) EntryState() phase.SessionState { return StateAuctionLocked }
func (PhaseKeygen) ExitState() phase.SessionState  { return StateAuctionBidding }
func (PhaseKeygen) ConsumedMessageTypes() []string             { return []string{"auction.keygen.share"} }
func (PhaseKeygen) InternalStates() []phase.SessionState       { return nil }
func (PhaseKeygen) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxAuctionParticipants:   {TypeName: "[]string", Required: true},
		CtxAuctionCryptoContract: {TypeName: "OpenFHEContract", Required: true, Constraints: map[string]any{"depth_min": 4}},
	}
}
func (PhaseKeygen) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxAuctionCollectivePublicKey: {TypeName: "[]byte"},
		CtxAuctionSecretShares:        {TypeName: "map[string][]byte"},
		CtxAuctionEvalKeys:            {TypeName: "OpenFHEEvalKeys"},
	}
}
func (PhaseKeygen) Enter(*phase.SessionContext) error                       { return nil }
func (PhaseKeygen) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (PhaseKeygen) CheckComplete(*phase.SessionContext) bool                 { return false }
func (PhaseKeygen) Exit(*phase.SessionContext) error                         { return nil }

// PhaseScalarBid collects one encrypted scalar bid from each bidder.
// The wire shape is dramatically smaller than Fheya's Phase 1b:
// instead of a 128-dimensional unit-norm vector plus a quantized
// location plus an initiator winner-package wrap, each bidder
// submits exactly one CKKS-encrypted integer in [0, MAX].
//
// The phase requires no encrypted-input validation beyond
// ciphertext shape — there is no norm proof, no profile-dimension
// check, no winner-package shape. Encrypted-integer schemes can
// validate range bounds via separate ZK proofs of value-in-bounds
// if the application requires sealed-bid integrity guarantees.
type PhaseScalarBid struct{}

func NewPhaseScalarBid() *PhaseScalarBid { return &PhaseScalarBid{} }

func (PhaseScalarBid) Name() string                   { return "auction-scalar-bid" }
func (PhaseScalarBid) Lifetime() phase.Lifetime       { return phase.LifetimePerSession }
func (PhaseScalarBid) RunsAt() phase.RunsAt           { return phase.RunsAtInline }
func (PhaseScalarBid) EntryState() phase.SessionState { return StateAuctionBidding }
func (PhaseScalarBid) ExitState() phase.SessionState  { return StateAuctionScoring }
func (PhaseScalarBid) ConsumedMessageTypes() []string             { return []string{"auction.bid"} }
func (PhaseScalarBid) InternalStates() []phase.SessionState       { return nil }
func (PhaseScalarBid) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxAuctionParticipants:        {TypeName: "[]string", Required: true},
		CtxAuctionCollectivePublicKey: {TypeName: "[]byte", Required: true},
		CtxAuctionCryptoContract:      {TypeName: "OpenFHEContract", Required: true},
	}
}
func (PhaseScalarBid) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxAuctionBids: {TypeName: "map[string][]byte"},
	}
}
func (PhaseScalarBid) Enter(*phase.SessionContext) error                       { return nil }
func (PhaseScalarBid) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (PhaseScalarBid) CheckComplete(*phase.SessionContext) bool                 { return false }
func (PhaseScalarBid) Exit(*phase.SessionContext) error                         { return nil }

// PhaseArgmax runs the encrypted argmax circuit: pairwise comparison
// of N encrypted scalars, building a one-hot mask of the maximum, and
// fusing it with both the bid ciphertexts (to recover the winning
// price) and a one-hot encoding of the bidder pseudonyms (to recover
// the winning identity). The circuit fits comfortably in depth=10,
// vs depth=30 for Fheya's selector chain.
//
// Phase 2 of any ARES app — the scoring circuit — is the
// app-specific heart of the framework. Replacing it is how
// applications redefine "who wins". For Fheya it is cosine
// similarity + location penalty + reputation; here it is plain
// argmax; a weighted-ballot voting app would emit a tally
// ciphertext with no winner selection.
type PhaseArgmax struct{}

func NewPhaseArgmax() *PhaseArgmax { return &PhaseArgmax{} }

func (PhaseArgmax) Name() string                   { return "auction-argmax-scoring" }
func (PhaseArgmax) Lifetime() phase.Lifetime       { return phase.LifetimePerSession }
func (PhaseArgmax) RunsAt() phase.RunsAt           { return phase.RunsAtInline }
func (PhaseArgmax) EntryState() phase.SessionState { return StateAuctionScoring }
func (PhaseArgmax) ExitState() phase.SessionState  { return StateAuctionDecrypting }
func (PhaseArgmax) ConsumedMessageTypes() []string             { return nil }
func (PhaseArgmax) InternalStates() []phase.SessionState       { return nil }
func (PhaseArgmax) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxAuctionParticipants:   {TypeName: "[]string", Required: true},
		CtxAuctionCryptoContract: {TypeName: "OpenFHEContract", Required: true, Constraints: map[string]any{"depth_min": 8}},
		CtxAuctionEvalKeys:       {TypeName: "OpenFHEEvalKeys", Required: true},
		CtxAuctionBids:           {TypeName: "map[string][]byte", Required: true},
	}
}
func (PhaseArgmax) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxAuctionCipherWinnerBid: {TypeName: "[]byte"},
	}
}
func (PhaseArgmax) Enter(*phase.SessionContext) error                       { return nil }
func (PhaseArgmax) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (PhaseArgmax) CheckComplete(*phase.SessionContext) bool                 { return false }
func (PhaseArgmax) Exit(*phase.SessionContext) error                         { return nil }

// PhaseDecrypt runs the threshold partial-decryption of the encrypted
// (winning_bid, winner_id) tuple. Each participant submits a partial
// using its key share from Keygen; the server fuses them to recover
// the cleartext outcome.
//
// Same crypto protocol as defaults.Phase3ThresholdDecrypt, but
// trivially smaller payload — two scalars rather than a 176-byte
// ECIES winner package padded across 1536 bit slots — so the
// recovery logic is a direct read-out instead of bit-slot recovery.
type PhaseDecrypt struct{}

func NewPhaseDecrypt() *PhaseDecrypt { return &PhaseDecrypt{} }

func (PhaseDecrypt) Name() string                   { return "auction-threshold-decrypt" }
func (PhaseDecrypt) Lifetime() phase.Lifetime       { return phase.LifetimePerSession }
func (PhaseDecrypt) RunsAt() phase.RunsAt           { return phase.RunsAtInline }
func (PhaseDecrypt) EntryState() phase.SessionState { return StateAuctionDecrypting }
func (PhaseDecrypt) ExitState() phase.SessionState  { return StateAuctionSettled }
func (PhaseDecrypt) ConsumedMessageTypes() []string             { return []string{"auction.decrypt.partial"} }
func (PhaseDecrypt) InternalStates() []phase.SessionState       { return nil }
func (PhaseDecrypt) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxAuctionParticipants:    {TypeName: "[]string", Required: true},
		CtxAuctionSecretShares:    {TypeName: "map[string][]byte", Required: true},
		CtxAuctionCipherWinnerBid: {TypeName: "[]byte", Required: true},
	}
}
func (PhaseDecrypt) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxAuctionWinnerBid: {TypeName: "WinnerBid"},
	}
}
func (PhaseDecrypt) Enter(*phase.SessionContext) error                       { return nil }
func (PhaseDecrypt) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (PhaseDecrypt) CheckComplete(*phase.SessionContext) bool                 { return false }
func (PhaseDecrypt) Exit(*phase.SessionContext) error                         { return nil }

// PhaseSettlement emits the signed settlement transcript and
// terminates the session. There is no post-result interaction — no
// Phase D back-channel, no winner-to-initiator handshake — because
// the auction outcome is intentionally public. The transcript
// carries (winning_bid, winner_id) plus the auctioneer's signature
// and is the final session artifact.
//
// This phase demonstrates the simplest possible post-result shape:
// a synchronous Enter that does its work and CheckComplete that
// returns true immediately. Apps with richer post-result phases
// (Fheya's Phase D, an on-chain settlement anchor, a ZK-proof of
// correct execution) replace this phase with a more elaborate
// implementation.
type PhaseSettlement struct{}

func NewPhaseSettlement() *PhaseSettlement { return &PhaseSettlement{} }

func (PhaseSettlement) Name() string                   { return "auction-settlement" }
func (PhaseSettlement) Lifetime() phase.Lifetime       { return phase.LifetimePerSession }
func (PhaseSettlement) RunsAt() phase.RunsAt           { return phase.RunsAtInline }
func (PhaseSettlement) EntryState() phase.SessionState { return StateAuctionSettled }
func (PhaseSettlement) ExitState() phase.SessionState  { return phase.StateNone }
func (PhaseSettlement) ConsumedMessageTypes() []string             { return nil }
func (PhaseSettlement) InternalStates() []phase.SessionState       { return nil }
func (PhaseSettlement) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxAuctionWinnerBid: {TypeName: "WinnerBid", Required: true},
	}
}
func (PhaseSettlement) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxAuctionSettlement: {TypeName: "SignedTranscript"},
	}
}
func (PhaseSettlement) Enter(*phase.SessionContext) error                       { return nil }
func (PhaseSettlement) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (PhaseSettlement) CheckComplete(*phase.SessionContext) bool                 { return true }
func (PhaseSettlement) Exit(*phase.SessionContext) error                         { return nil }
