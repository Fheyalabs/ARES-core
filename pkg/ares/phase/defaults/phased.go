package defaults

import "github.com/fheya/ares/pkg/ares/phase"

// PhaseDAnonymousBroadcast is ARES v2.4 §"Phase D — Anonymous
// All-N Broadcast". The decrypted winner package plus a fixed
// budget of rate-limited fixed-size cover-message slots flow
// through the same all-N broadcast channel for a time-bounded
// window (3 hours default in Fheya). The phase owns BROADCASTING →
// CLOSED and consumes `phased.message`.
//
// This is the most app-specific phase after Phase 2. For apps that
// have no post-result back-channel (sealed-bid auction, weighted
// vote) this phase is replaced with a no-op that emits a single
// signed transcript and transitions immediately.
type PhaseDAnonymousBroadcast struct{}

func NewPhaseDAnonymousBroadcast() *PhaseDAnonymousBroadcast { return &PhaseDAnonymousBroadcast{} }

func (PhaseDAnonymousBroadcast) Name() string                   { return "phase-d-anonymous-broadcast" }
func (PhaseDAnonymousBroadcast) Lifetime() phase.Lifetime       { return phase.LifetimePerSession }
func (PhaseDAnonymousBroadcast) RunsAt() phase.RunsAt           { return phase.RunsAtInline }
func (PhaseDAnonymousBroadcast) EntryState() phase.SessionState { return StateBroadcasting }
func (PhaseDAnonymousBroadcast) ExitState() phase.SessionState  { return StateClosed }

func (PhaseDAnonymousBroadcast) ConsumedMessageTypes() []string {
	// phased.message is the in-window encrypted broadcast frame
	// (winner package fragments and cover traffic). rating.submit
	// is the per-participant rating submitted after the result is
	// known and before the matched / cooldown transition; today's
	// engine accumulates it in StateMatched but the framework
	// folds the rating window into Phase D's exit-state arc
	// because that is where the post-result interaction lives.
	return []string{"phased.message", "rating.submit"}
}

// InternalStates declares the post-Phase-D sub-states the engine
// uses for outcome tracking (CLOSED is the immediate exit; MATCHED
// and COOLDOWN are reached on outcome events; EXPIRED follows
// MATCHED on unmatch/expiry). The framework folds the entire
// post-result outcome window into Phase D so the lifecycle tracker
// stays aligned through the smoke linger period without raising
// drift on these post-keygen states.
func (PhaseDAnonymousBroadcast) InternalStates() []phase.SessionState {
	return []phase.SessionState{
		"CLOSED",
		"MATCHED",
		"COOLDOWN",
		"EXPIRED",
	}
}

func (PhaseDAnonymousBroadcast) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants:  {TypeName: "[]string", Required: true},
		CtxWinnerPackage: {TypeName: "[]byte", Required: true},
		CtxSessionMacKey: {TypeName: "[]byte", Required: true},
	}
}

func (PhaseDAnonymousBroadcast) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxPhaseDSchedule: {TypeName: "[]MessageSchedule"},
	}
}

func (PhaseDAnonymousBroadcast) Enter(*phase.SessionContext) error                   { return nil }
func (PhaseDAnonymousBroadcast) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (PhaseDAnonymousBroadcast) CheckComplete(*phase.SessionContext) bool             { return false }
func (PhaseDAnonymousBroadcast) Exit(*phase.SessionContext) error                     { return nil }
