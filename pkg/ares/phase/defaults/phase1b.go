// SPDX-License-Identifier: Apache-2.0

package defaults

import "github.com/Fheyalabs/ares-core/pkg/ares/phase"

// Phase1bEncryptedSubmit is ARES v2.4 §"Phase 1b — Distance,
// Profile, and Winner Package". Each non-initiator submits its
// encrypted profile vector and quantized location; the initiator
// submits the winner-package wrap plus its own encrypted profile.
// The phase owns SUBMITTING → SCORING.
//
// This is the second-most app-specific phase (after Phase2). The
// "encrypted input" shape (e.g., a unit-norm profile vector for a matchmaking app,
// scalar bid for a sealed-bid auction, weighted ballot for a vote —
// is replaced by swapping this phase. Compatibility with Phase2 is
// enforced by the context schema: Phase1b produces
// CtxEncryptedInputs and Phase2 consumes it, with the scorer-side
// expecting a specific encoding declared via the crypto contract.
type Phase1bEncryptedSubmit struct{}

func NewPhase1bEncryptedSubmit() *Phase1bEncryptedSubmit { return &Phase1bEncryptedSubmit{} }

func (Phase1bEncryptedSubmit) Name() string                   { return "phase-1b-encrypted-submit" }
func (Phase1bEncryptedSubmit) Lifetime() phase.Lifetime       { return phase.LifetimePerSession }
func (Phase1bEncryptedSubmit) RunsAt() phase.RunsAt           { return phase.RunsAtInline }
func (Phase1bEncryptedSubmit) EntryState() phase.SessionState { return StateSubmitting }
func (Phase1bEncryptedSubmit) ExitState() phase.SessionState  { return StateScoring }

func (Phase1bEncryptedSubmit) ConsumedMessageTypes() []string {
	return []string{"submit.distance", "submit.initiator"}
}
func (Phase1bEncryptedSubmit) InternalStates() []phase.SessionState { return nil }

func (Phase1bEncryptedSubmit) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants:        {TypeName: "[]string", Required: true},
		CtxCollectivePublicKey: {TypeName: "[]byte", Required: true},
		CtxCryptoContract: {
			TypeName: "OpenFHEContract",
			Required: true,
		},
	}
}

func (Phase1bEncryptedSubmit) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxEncryptedInputs: {TypeName: "map[string]EncryptedInput"},
	}
}

func (Phase1bEncryptedSubmit) Enter(*phase.SessionContext) error                   { return nil }
func (Phase1bEncryptedSubmit) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (Phase1bEncryptedSubmit) CheckComplete(*phase.SessionContext) bool             { return false }
func (Phase1bEncryptedSubmit) Exit(*phase.SessionContext) error                     { return nil }
