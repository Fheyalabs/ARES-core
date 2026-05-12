package defaults

import (
	"testing"

	"github.com/fheya/ares/pkg/ares/phase"
)

// TestNewARESDefaultRunner_BuildsAndConnects verifies that the
// default phase composition is internally consistent: every phase's
// Requires schema is satisfied by some preceding phase's Provides,
// and the inline state chain is connected end to end.
//
// This is the abstraction-validity test for task #11. If a future
// edit to any default phase's Requires or Provides breaks the chain,
// this test fails at registration construction time rather than at
// session runtime.
func TestNewARESDefaultRunner_BuildsAndConnects(t *testing.T) {
	r, err := NewARESDefaultRunner()
	if err != nil {
		t.Fatalf("NewARESDefaultRunner: %v", err)
	}
	if r.InitialState() != StateInviting {
		t.Errorf("InitialState = %q, want %q", r.InitialState(), StateInviting)
	}

	// Walk every expected state and confirm an inline phase claims
	// it. The terminal CLOSED state has no owning phase (it is
	// the session-done sentinel).
	expectStates := []phase.SessionState{
		StateInviting, StateLocked, StateGossip, StateVerifying,
		StateSubmitting, StateScoring, StateDecrypting, StateBroadcasting,
	}
	for _, s := range expectStates {
		p, ok := r.PhaseForState(s)
		if !ok {
			t.Errorf("no phase claims state %q", s)
			continue
		}
		if p.EntryState() != s {
			t.Errorf("phase %q claims state %q via map but EntryState() = %q",
				p.Name(), s, p.EntryState())
		}
	}

	// Confirm CLOSED has no owning phase.
	if _, ok := r.PhaseForState(StateClosed); ok {
		t.Errorf("CLOSED should be the terminal state with no owning phase")
	}
}

// TestNewARESDefaultRunner_PhaseCount confirms the eight inline
// phases plus zero registration-time phases (Phase 0b is
// instantiated separately) are wired through the runner.
func TestNewARESDefaultRunner_PhaseCount(t *testing.T) {
	r, err := NewARESDefaultRunner()
	if err != nil {
		t.Fatalf("NewARESDefaultRunner: %v", err)
	}
	if got := len(r.Phases()); got != 8 {
		t.Errorf("len(Phases()) = %d, want 8", got)
	}
}

// TestNewARESDefaultRunner_ConsumedMessageTypesAreUnique sanity-checks
// that no two phases consume the same WS message type. If they did,
// the dispatcher's "which phase gets this message in this state"
// rule would still resolve them correctly (since only the current
// phase is consulted), but reusing a message type across phases is
// a strong code smell — it usually means a phase is over-eagerly
// scoped or that one phase is doing work that belongs in another.
func TestNewARESDefaultRunner_ConsumedMessageTypesAreUnique(t *testing.T) {
	r, err := NewARESDefaultRunner()
	if err != nil {
		t.Fatalf("NewARESDefaultRunner: %v", err)
	}
	seen := map[string]string{}
	for _, p := range r.Phases() {
		for _, msg := range p.ConsumedMessageTypes() {
			if existing, dup := seen[msg]; dup {
				t.Errorf("message type %q consumed by both %q and %q",
					msg, existing, p.Name())
			}
			seen[msg] = p.Name()
		}
	}
}

// TestNewARESDefaultRunner_ContextChain confirms that every consumed
// context key has at least one preceding producer in the pipeline.
// The SessionRunner constructor enforces this already, but
// asserting it here gives a fast signal during phase-shape edits.
func TestNewARESDefaultRunner_ContextChain(t *testing.T) {
	r, err := NewARESDefaultRunner()
	if err != nil {
		t.Fatalf("NewARESDefaultRunner: %v", err)
	}
	provided := map[string]struct{}{}
	for _, p := range r.Phases() {
		for key, kt := range p.Requires() {
			if _, ok := provided[key]; !ok && kt.Required {
				t.Errorf("phase %q requires %q but no preceding phase provides it", p.Name(), key)
			}
		}
		for key := range p.Provides() {
			provided[key] = struct{}{}
		}
	}
}
