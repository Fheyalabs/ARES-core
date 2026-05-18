// SPDX-License-Identifier: Apache-2.0

package defaults

import "github.com/Fheyalabs/ares-core/pkg/ares/phase"

// Phase2FHEScoring is ARES v2.4 §"Phase 2 — Homomorphic Scoring".
// The server runs the encrypted scoring circuit on the
// participant-submitted profile ciphertexts and emits
// `ct_winner_pkg` — the encrypted, masked winner package that
// threshold decryption will recover in Phase 3.
//
// This is THE app-specific phase. The Fheya scoring circuit is
// cosine similarity plus location penalty plus brownie reputation
// plus the selector-chain product tree producing a one-hot mask
// across N candidates (depth=30, validated by the crypto harness).
// Alternative apps replace Phase2 entirely:
//
//   - SealedBidAuctionScoring: argmax of encrypted scalars, much
//     shallower (depth ~6), no rotation keys needed.
//   - WeightedBallotScoring: encrypted sum-of-weights, no winner
//     selection; emits an aggregated tally ciphertext.
//   - TopKScoring: emits K masks instead of one for top-K queries.
//
// The phase consumes no WebSocket messages — it is driven by
// CheckComplete returning true as soon as Enter has launched the
// scoring goroutine and the goroutine has populated
// CtxCipherWinnerPackage in the context.
type Phase2FHEScoring struct{}

func NewPhase2FHEScoring() *Phase2FHEScoring { return &Phase2FHEScoring{} }

func (Phase2FHEScoring) Name() string                   { return "phase-2-fhe-scoring" }
func (Phase2FHEScoring) Lifetime() phase.Lifetime       { return phase.LifetimePerSession }
func (Phase2FHEScoring) RunsAt() phase.RunsAt           { return phase.RunsAtInline }
func (Phase2FHEScoring) EntryState() phase.SessionState { return StateScoring }
func (Phase2FHEScoring) ExitState() phase.SessionState  { return StateDecrypting }

// ConsumedMessageTypes is empty: Phase 2 is server-side compute.
// Participants neither send nor receive Phase 2 messages until
// `scoring.complete` is broadcast on transition.
func (Phase2FHEScoring) ConsumedMessageTypes() []string       { return nil }
func (Phase2FHEScoring) InternalStates() []phase.SessionState { return nil }

func (Phase2FHEScoring) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants:    {TypeName: "[]string", Required: true},
		CtxCryptoContract:  {TypeName: "OpenFHEContract", Required: true},
		CtxEvalKeys:        {TypeName: "OpenFHEEvalKeys", Required: true},
		CtxEncryptedInputs: {TypeName: "map[string]EncryptedInput", Required: true},
	}
}

func (Phase2FHEScoring) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxCipherWinnerPackage: {TypeName: "[]byte"},
	}
}

func (Phase2FHEScoring) Enter(*phase.SessionContext) error                   { return nil }
func (Phase2FHEScoring) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (Phase2FHEScoring) CheckComplete(*phase.SessionContext) bool             { return false }
func (Phase2FHEScoring) Exit(*phase.SessionContext) error                     { return nil }
