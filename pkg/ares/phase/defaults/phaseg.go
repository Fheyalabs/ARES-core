package defaults

import "github.com/Fheyalabs/ares-core/pkg/ares/phase"

// PhaseGOnionShuffle is ARES v2.4 §"Phase G — Gossip Round". A
// fixed number of onion-shuffle rounds anonymizes the mapping
// between slot index and long-term participant key, so that the
// initiator-facing winner-package fan-out in Phase D cannot be
// correlated to a registered identity by the matchmaker. The phase
// owns GOSSIP → VERIFYING and consumes `gossip.onion_batch`.
//
// The phase is conceptually optional for applications that don't
// need slot-anonymity (for example sealed-bid auctions where the
// winner's identity is intentionally revealed). Such apps register
// a no-op replacement; the runner still requires its Provides
// outputs to flow downstream.
type PhaseGOnionShuffle struct{}

func NewPhaseGOnionShuffle() *PhaseGOnionShuffle { return &PhaseGOnionShuffle{} }

func (PhaseGOnionShuffle) Name() string                     { return "phase-g-onion-shuffle" }
func (PhaseGOnionShuffle) Lifetime() phase.Lifetime         { return phase.LifetimePerSession }
func (PhaseGOnionShuffle) RunsAt() phase.RunsAt             { return phase.RunsAtInline }
func (PhaseGOnionShuffle) EntryState() phase.SessionState   { return StateGossip }
func (PhaseGOnionShuffle) ExitState() phase.SessionState    { return StateVerifying }
func (PhaseGOnionShuffle) ConsumedMessageTypes() []string {
	// gossip.onion_batch is the initial batched onion submission;
	// gossip.peel_forward is each subsequent forwarding step. Both
	// accumulate within the GOSSIP → VERIFYING arc.
	return []string{"gossip.onion_batch", "gossip.peel_forward"}
}
func (PhaseGOnionShuffle) InternalStates() []phase.SessionState { return nil }
func (PhaseGOnionShuffle) Requires() phase.ContextSchema {
	return phase.ContextSchema{CtxParticipants: {TypeName: "[]string", Required: true}}
}
func (PhaseGOnionShuffle) Provides() phase.ContextSchema {
	return phase.ContextSchema{CtxOnionRoundsComplete: {TypeName: "int"}}
}
func (PhaseGOnionShuffle) Enter(*phase.SessionContext) error                   { return nil }
func (PhaseGOnionShuffle) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (PhaseGOnionShuffle) CheckComplete(*phase.SessionContext) bool             { return false }
func (PhaseGOnionShuffle) Exit(*phase.SessionContext) error                     { return nil }
