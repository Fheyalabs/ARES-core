package defaults

import "github.com/fheya/ares/pkg/ares/phase"

// Phase1aSessionInitiation is ARES v2.4 §"Phase 1a — Session
// Initiation". The coordinator selects N eligible participants from
// the queue, builds the session record, emits `session.invitation`
// to each, and waits for the locked acknowledgement before
// transitioning out of INVITING. In the framework the phase owns
// the INVITING → LOCKED arc and produces the participant list plus
// the crypto contract (parameters every later phase needs).
//
// Today's implementation lives in internal/engine/coordinator.go;
// the body of this phase is a placeholder until the logic port.
type Phase1aSessionInitiation struct{}

func NewPhase1aSessionInitiation() *Phase1aSessionInitiation {
	return &Phase1aSessionInitiation{}
}

func (Phase1aSessionInitiation) Name() string                   { return "phase-1a-session-initiation" }
func (Phase1aSessionInitiation) Lifetime() phase.Lifetime       { return phase.LifetimePerSession }
func (Phase1aSessionInitiation) RunsAt() phase.RunsAt           { return phase.RunsAtInline }
func (Phase1aSessionInitiation) EntryState() phase.SessionState { return StateInviting }
func (Phase1aSessionInitiation) ExitState() phase.SessionState  { return StateLocked }

// ConsumedMessageTypes is empty: Phase 1a is server-side. The
// participants reply over HTTP to `session.invitation` (not via WS),
// and the orchestrator transitions the session out of INVITING when
// enough acceptances arrive. The framework registers no WS handler
// here.
func (Phase1aSessionInitiation) ConsumedMessageTypes() []string { return nil }

func (Phase1aSessionInitiation) Requires() phase.ContextSchema { return nil }

func (Phase1aSessionInitiation) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants: {
			TypeName: "[]string",
			Required: false,
		},
		CtxCryptoContract: {
			TypeName: "OpenFHEContract",
			Required: false,
			// Default contract emitted by Phase 1a is depth=30,
			// ring_dim=4096 for the Fheya v2.4 profile. Apps with
			// different scoring circuits override this phase to
			// emit different contract parameters.
			Constraints: map[string]any{
				"depth":            30,
				"ring_dim":         4096,
				"scaling_mod_size": 50,
			},
		},
	}
}

func (Phase1aSessionInitiation) Enter(ctx *phase.SessionContext) error      { return nil }
func (Phase1aSessionInitiation) OnMessage(ctx *phase.SessionContext, msgType, from string, payload []byte) error {
	return nil
}
func (Phase1aSessionInitiation) CheckComplete(ctx *phase.SessionContext) bool { return true }
func (Phase1aSessionInitiation) Exit(ctx *phase.SessionContext) error         { return nil }
