package defaults

import "github.com/fheya/ares/pkg/ares/phase"

// PhaseG2Verification is ARES v2.4 §"Phase G.2 — Verification
// Round". After onion shuffling, participants exchange contribution
// hashes, MAC seeds, slot-list hashes, and slot submissions so the
// coordinator can verify the shuffle was honest before the encrypted
// inputs are committed. The phase owns VERIFYING → SUBMITTING and
// derives the session MAC key used to authenticate Phase D
// messages.
type PhaseG2Verification struct{}

func NewPhaseG2Verification() *PhaseG2Verification { return &PhaseG2Verification{} }

func (PhaseG2Verification) Name() string                   { return "phase-g2-verification" }
func (PhaseG2Verification) Lifetime() phase.Lifetime       { return phase.LifetimePerSession }
func (PhaseG2Verification) RunsAt() phase.RunsAt           { return phase.RunsAtInline }
func (PhaseG2Verification) EntryState() phase.SessionState { return StateVerifying }
func (PhaseG2Verification) ExitState() phase.SessionState  { return StateSubmitting }

func (PhaseG2Verification) ConsumedMessageTypes() []string {
	return []string{
		"verify.contribution_hash",
		"verify.slot_list_hash",
		"verify.mac_seed",
		"verify.submit_slot",
	}
}
func (PhaseG2Verification) InternalStates() []phase.SessionState { return nil }

func (PhaseG2Verification) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants:        {TypeName: "[]string", Required: true},
		CtxOnionRoundsComplete: {TypeName: "int", Required: true},
	}
}

func (PhaseG2Verification) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxContribHashes: {TypeName: "map[string][]byte"},
		CtxMacSeeds:      {TypeName: "map[string][]byte"},
		CtxSessionMacKey: {TypeName: "[]byte"},
	}
}

func (PhaseG2Verification) Enter(*phase.SessionContext) error                   { return nil }
func (PhaseG2Verification) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (PhaseG2Verification) CheckComplete(*phase.SessionContext) bool             { return false }
func (PhaseG2Verification) Exit(*phase.SessionContext) error                     { return nil }
