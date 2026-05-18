// SPDX-License-Identifier: Apache-2.0

package defaults

import "github.com/Fheyalabs/ares-core/pkg/ares/phase"

// Phase3ThresholdDecrypt is ARES v2.4 §"Phase 3 — Threshold
// Decrypt". Each participant submits a partial decryption of
// `ct_winner_pkg` using its secret share from Phase 0a; the server
// fuses the partials and runs the bit-payload recovery logic from
// crypto-lab finding 2026-04-23 to extract the byte-encoded winner
// package. The phase owns DECRYPTING → BROADCASTING.
//
// Alternative implementations:
//   - Phase3SinglePartyDecrypt: when Phase0a is SinglePartyKeygen,
//     this phase is a no-op — the server decrypts the result with
//     its private key directly.
//   - Phase3PlaintextResolve: when Phase0a is PlaintextKeygen, this
//     phase just signs and broadcasts the cleartext result.
type Phase3ThresholdDecrypt struct{}

func NewPhase3ThresholdDecrypt() *Phase3ThresholdDecrypt { return &Phase3ThresholdDecrypt{} }

func (Phase3ThresholdDecrypt) Name() string                   { return "phase-3-threshold-decrypt" }
func (Phase3ThresholdDecrypt) Lifetime() phase.Lifetime       { return phase.LifetimePerSession }
func (Phase3ThresholdDecrypt) RunsAt() phase.RunsAt           { return phase.RunsAtInline }
func (Phase3ThresholdDecrypt) EntryState() phase.SessionState { return StateDecrypting }
func (Phase3ThresholdDecrypt) ExitState() phase.SessionState  { return StateBroadcasting }

func (Phase3ThresholdDecrypt) ConsumedMessageTypes() []string {
	return []string{"decrypt.partial"}
}
func (Phase3ThresholdDecrypt) InternalStates() []phase.SessionState { return nil }

func (Phase3ThresholdDecrypt) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants:        {TypeName: "[]string", Required: true},
		CtxSecretShares:        {TypeName: "map[string][]byte", Required: true},
		CtxCipherWinnerPackage: {TypeName: "[]byte", Required: true},
	}
}

func (Phase3ThresholdDecrypt) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxWinnerPackage: {TypeName: "[]byte"},
	}
}

func (Phase3ThresholdDecrypt) Enter(*phase.SessionContext) error                   { return nil }
func (Phase3ThresholdDecrypt) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (Phase3ThresholdDecrypt) CheckComplete(*phase.SessionContext) bool             { return false }
func (Phase3ThresholdDecrypt) Exit(*phase.SessionContext) error                     { return nil }
