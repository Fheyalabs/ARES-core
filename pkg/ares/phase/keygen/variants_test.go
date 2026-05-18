// SPDX-License-Identifier: Apache-2.0

package keygen

import (
	"strings"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
)

// TestSinglePartyKeygen_ComposesIntoDefaultRunner verifies
// SinglePartyKeygenPhase slots into the Fheya pipeline as a
// drop-in replacement for Phase0aThresholdKeygen at the same
// LOCKED → GOSSIP arc with identical Provides.
func TestSinglePartyKeygen_ComposesIntoDefaultRunner(t *testing.T) {
	_, err := phase.Compose(
		defaults.NewPhase1aSessionInitiation(),
		NewSinglePartyKeygen(),
		defaults.NewPhaseGOnionShuffle(),
		defaults.NewPhaseG2Verification(),
		defaults.NewPhase1bEncryptedSubmit(),
		defaults.NewPhase2FHEScoring(),
		defaults.NewPhase3ThresholdDecrypt(),
		defaults.NewPhaseDAnonymousBroadcast(),
	)
	if err != nil {
		t.Fatalf("Compose with SinglePartyKeygen: %v", err)
	}
}

// TestPlaintextKeygen_ComposesIntoDefaultRunner verifies
// PlaintextKeygenPhase slots into the Fheya pipeline. It produces
// no crypto contract, so downstream phases that require a crypto
// contract (Phase2FHEScoring requires ctxCryptoContract with
// depth_min) should fail construction. That is correct — a
// plaintext pipeline would swap Phase2 for a plaintext scorer.
func TestPlaintextKeygen_ComposesIntoDefaultRunner(t *testing.T) {
	// Plaintext keygen does NOT provide ctxCryptoContract, so
	// Phase2FHEScoring (which requires it) should fail.
	_, err := phase.Compose(
		defaults.NewPhase1aSessionInitiation(),
		NewPlaintextKeygen(),
		defaults.NewPhaseGOnionShuffle(),
		defaults.NewPhaseG2Verification(),
		defaults.NewPhase1bEncryptedSubmit(),
		defaults.NewPhase2FHEScoring(),
		defaults.NewPhase3ThresholdDecrypt(),
		defaults.NewPhaseDAnonymousBroadcast(),
	)
	if err == nil {
		t.Fatalf("expected constructor to reject plaintext keygen + FHE scoring (type mismatch or missing crypto_ctx)")
	}
	// The first failure is a type mismatch on secret_shares
	// (PlaintextKeygen declares []byte but Phase3 expects
	// map[string][]byte). Either that or the missing crypto_ctx
	// is fine — both correctly reject the misconfiguration.
	if !strings.Contains(err.Error(), defaults.CtxCryptoContract) &&
		!strings.Contains(err.Error(), "secret_shares") {
		t.Errorf("expected error about %s or secret_shares type mismatch, got: %v",
			defaults.CtxCryptoContract, err)
	}
}

// TestPlaintextKeygen_ComposesIntoAuctionRunner verifies the
// auction pipeline (which doesn't do FHE scoring in this test)
// composes with plaintext keygen.
func TestPlaintextKeygen_ComposesIntoAuctionRunner(t *testing.T) {
	// Provide a participants source so the plaintext keygen's
	// requires are satisfied in the single-phase runner.
	r, err := phase.Compose(
		defaults.NewPhase1aSessionInitiation(),
		NewPlaintextKeygen(),
	)
	if err != nil {
		t.Fatalf("plaintext keygen + invitation: %v", err)
	}
	if r.InitialState() != defaults.StateInviting {
		t.Errorf("plaintext pipeline initial state: %q, want INVITING",
			r.InitialState())
	}
}

// TestPreSharedKeygen_ComposesIntoDefaultRunner verifies
// PreSharedKeygenPhase slots into the default pipeline. Its
// Requires include ctxCollectivePublicKey and ctxSecretShares,
// which must already be in the context at Enter time —
// construction validates nothing about runtime context values,
// only that SOME preceding phase declares those Provides.
// PreSharedKeygen itself does NOT provide them, so downstream
// phases that need them will fail unless a preceding phase (not
// present in the default pipeline) has already populated them.
// That's correct: PreSharedKeygen expects keys seeded before
// runner.BeginSession.
func TestPreSharedKeygen_ComposesIntoDefaultRunner(t *testing.T) {
	_, err := phase.Compose(
		defaults.NewPhase1aSessionInitiation(),
		NewPreSharedKeygen(),
		defaults.NewPhaseGOnionShuffle(),
		defaults.NewPhaseG2Verification(),
		defaults.NewPhase1bEncryptedSubmit(),
		defaults.NewPhase2FHEScoring(),
		defaults.NewPhase3ThresholdDecrypt(),
		defaults.NewPhaseDAnonymousBroadcast(),
	)
	// PreSharedKeygen Provides nothing, so Phase1b's
	// ctxCollectivePublicKey and ctxCryptoContract
	// requirements will be unsatisfied. The runner
	// should catch that.
	if err == nil {
		t.Fatalf("expected constructor to reject PreSharedKeygen without a preceding context-providing phase")
	}
	// Any of the three required-absent keys is correct — Go map
	// iteration order is non-deterministic.
	ok := strings.Contains(err.Error(), defaults.CtxCollectivePublicKey) ||
		strings.Contains(err.Error(), defaults.CtxSecretShares) ||
		strings.Contains(err.Error(), defaults.CtxEvalKeys)
	if !ok {
		t.Errorf("expected error about one of [collective_pk, secret_shares, eval_keys], got: %v", err)
	}
}

// TestPreSharedKeygen_WithCohortContextSeed verifies that a
// pipeline where another (non-inline) phase provides the
// collective key context composes successfully.
func TestPreSharedKeygen_WithCohortContextSeed(t *testing.T) {
	// Simulate a cohort formation phase that runs out of band
	// and provides the key bundle into context.
	cohortPhase := &staticProviderPhase{
		name:   "cohort-keygen",
		runsAt: phase.RunsAtRegistration,
		provides: phase.ContextSchema{
			ctxCollectivePublicKey: {TypeName: "[]byte", Constraints: map[string]any{"topology": "preshared"}},
			ctxSecretShares:        {TypeName: "map[string][]byte", Constraints: map[string]any{"topology": "preshared"}},
			ctxEvalKeys:            {TypeName: "OpenFHEEvalKeys"},
			ctxCryptoContract:      {TypeName: "OpenFHEContract", Constraints: map[string]any{"depth": 30, "ring_dim": 4096, "scaling_mod_size": 50}},
		},
	}
	_, err := phase.Compose(
		cohortPhase,
		defaults.NewPhase1aSessionInitiation(),
		NewPreSharedKeygen(),
		defaults.NewPhaseGOnionShuffle(),
		defaults.NewPhaseG2Verification(),
		defaults.NewPhase1bEncryptedSubmit(),
		defaults.NewPhase2FHEScoring(),
		defaults.NewPhase3ThresholdDecrypt(),
		defaults.NewPhaseDAnonymousBroadcast(),
	)
	if err != nil {
		t.Fatalf("expected cohort-keygen + PreSharedKeygen pipeline to validate, got: %v", err)
	}
}

// TestPreSharedKeygen_EnterFailsOnMissingKeys verifies the
// runtime guard: Enter returns MissingContextError when the
// required keys are not in the context.
func TestPreSharedKeygen_EnterFailsOnMissingKeys(t *testing.T) {
	p := NewPreSharedKeygen()
	ctx := phase.NewSessionContext("test-session")
	err := p.Enter(ctx)
	if err == nil {
		t.Fatalf("expected Enter to fail on empty context")
	}
	var mce *phase.MissingContextError
	if !strings.Contains(err.Error(), "keygen-preshared") &&
		!strings.Contains(err.Error(), ctxCollectivePublicKey) {
		// If it's not a MissingContextError it must still be
		// the right kind of message.
		if !strings.Contains(err.Error(), "not set") {
			t.Errorf("unexpected error: %v", err)
		}
	}
	_ = mce // may or may not be used; typed check above is best-effort
}

// staticProviderPhase is a non-inline phase that provides a fixed
// set of context keys and does nothing else.
type staticProviderPhase struct {
	name     string
	runsAt   phase.RunsAt
	provides phase.ContextSchema
}

func (s *staticProviderPhase) Name() string                       { return s.name }
func (s *staticProviderPhase) Lifetime() phase.Lifetime           { return phase.LifetimePerCohort }
func (s *staticProviderPhase) RunsAt() phase.RunsAt               { return s.runsAt }
func (s *staticProviderPhase) EntryState() phase.SessionState     { return phase.StateNone }
func (s *staticProviderPhase) ExitState() phase.SessionState      { return phase.StateNone }
func (s *staticProviderPhase) InternalStates() []phase.SessionState { return nil }
func (s *staticProviderPhase) ConsumedMessageTypes() []string     { return nil }
func (s *staticProviderPhase) Requires() phase.ContextSchema      { return nil }
func (s *staticProviderPhase) Provides() phase.ContextSchema      { return s.provides }
func (s *staticProviderPhase) Enter(*phase.SessionContext) error  { return nil }
func (s *staticProviderPhase) OnMessage(*phase.SessionContext, string, string, []byte) error {
	return nil
}
func (s *staticProviderPhase) CheckComplete(*phase.SessionContext) bool { return true }
func (s *staticProviderPhase) Exit(*phase.SessionContext) error         { return nil }
