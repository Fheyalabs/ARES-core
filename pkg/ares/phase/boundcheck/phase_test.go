// SPDX-License-Identifier: Apache-2.0

package boundcheck_test

import (
	"errors"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/boundcheck"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// fakeContextHandle satisfies fhecalib.ContextHandle with canned responses.
// Every method returns the same cannedCT bytes regardless of input — the
// orchestration tests only verify that the check ciphertext map is populated,
// not that the bytes are cryptographically meaningful.
type fakeContextHandle struct {
	cannedCT []byte
}

func (h *fakeContextHandle) Params() helperclient.ContractParams {
	return helperclient.ContractParams{RingDim: 1024, Depth: 2}
}
func (h *fakeContextHandle) EvalMult(ctA, ctB []byte) ([]byte, error) {
	return h.cannedCT, nil
}
func (h *fakeContextHandle) EvalSubConst(ct []byte, vals []float64) ([]byte, error) {
	return h.cannedCT, nil
}
func (h *fakeContextHandle) EvalProductSum(ctLeft, ctRight []byte, nSlots int) ([]byte, error) {
	return h.cannedCT, nil
}

// captureHandler records every OnViolation call for assertions.
type captureHandler struct {
	calls []violationCall
}

type violationCall struct {
	party string
	nu    float64
	sev   boundcheck.Severity
}

func (h *captureHandler) OnViolation(_ *phase.SessionContext, party string, nu float64, sev boundcheck.Severity) error {
	h.calls = append(h.calls, violationCall{party: party, nu: nu, sev: sev})
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newCtx builds a populated SessionContext for the bound-check phase.
func newCtx(parties []string, encInputs map[string][]byte, dim int) *phase.SessionContext {
	ctx := phase.NewSessionContext("test-session")
	ctx.Set(defaults.CtxParticipants, parties)
	ctx.Set(boundcheck.CtxEncryptedInputs, encInputs)
	ctx.Set(boundcheck.CtxInputDim, dim)
	ctx.Set(boundcheck.CtxEvalKeyBundle, []byte("fake-eval-key"))
	ctx.Set(boundcheck.CtxJointPublicKey, []byte("fake-joint-pk"))
	return ctx
}

// newStubPhase returns a stub-mode Phase with nil handle/fuse.
func newStubPhase(circuit boundcheck.BoundCircuit, handler boundcheck.ViolationHandler, p boundcheck.Params) *boundcheck.Phase {
	return boundcheck.NewPhase(circuit, handler, p, defaults.StateScoring, defaults.StateDecrypting)
}

// newRealPhase returns a real-mode Phase wired with the given fake crypto seams.
func newRealPhase(
	circuit boundcheck.BoundCircuit,
	handler boundcheck.ViolationHandler,
	p boundcheck.Params,
	handle *fakeContextHandle,
	fuse func([][]byte, int) ([]float64, error),
) *boundcheck.Phase {
	return boundcheck.NewPhaseWithCrypto(
		circuit, handler, p,
		defaults.StateScoring, defaults.StateDecrypting,
		handle, fuse,
	)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestPhase_Enter_PopulatesBoundCheckCiphers verifies that Enter computes a
// check ciphertext entry for every party in CtxEncryptedInputs and stores
// them all in CtxBoundCheckCiphers (uniform per-party guarantee).
func TestPhase_Enter_PopulatesBoundCheckCiphers(t *testing.T) {
	cannedCT := []byte("fake-check-ct")
	handle := &fakeContextHandle{cannedCT: cannedCT}
	fakeFuse := func(partials [][]byte, nSlots int) ([]float64, error) {
		return []float64{1.0}, nil // irrelevant for Enter test
	}

	circuit := boundcheck.NormCircuit{Eps: 0.01, Dim: 4}
	p := newRealPhase(circuit, nil, boundcheck.DefaultParams(), handle, fakeFuse)

	parties := []string{"alice", "bob", "carol"}
	encInputs := map[string][]byte{
		"alice": []byte("enc-alice"),
		"bob":   []byte("enc-bob"),
		"carol": []byte("enc-carol"),
	}
	ctx := newCtx(parties, encInputs, 4)

	if err := p.Enter(ctx); err != nil {
		t.Fatalf("Enter: %v", err)
	}

	checks, ok := phase.TryGet[map[string][]byte](ctx, boundcheck.CtxBoundCheckCiphers)
	if !ok {
		t.Fatal("CtxBoundCheckCiphers not set after Enter")
	}
	// Assert an entry for every party.
	for _, party := range parties {
		if _, found := checks[party]; !found {
			t.Errorf("CtxBoundCheckCiphers missing entry for party %q", party)
		}
	}
	// No extra entries.
	if len(checks) != len(parties) {
		t.Errorf("CtxBoundCheckCiphers has %d entries, want %d", len(checks), len(parties))
	}
}

// TestPhase_CheckComplete_QuorumGating verifies that CheckComplete is false
// until all N participants have submitted MsgBoundPartial (N-of-N quorum).
func TestPhase_CheckComplete_QuorumGating(t *testing.T) {
	circuit := boundcheck.NormCircuit{Eps: 0.01, Dim: 4}
	p := newStubPhase(circuit, nil, boundcheck.DefaultParams())

	parties := []string{"a", "b"}
	ctx := newCtx(parties, map[string][]byte{"a": []byte("x"), "b": []byte("y")}, 4)

	if p.CheckComplete(ctx) {
		t.Fatal("CheckComplete must be false with 0/2 partials")
	}

	_ = p.OnMessage(ctx, boundcheck.MsgBoundPartial, "a", []byte("partial-a"))
	if p.CheckComplete(ctx) {
		t.Fatal("CheckComplete must be false with 1/2 partials")
	}

	_ = p.OnMessage(ctx, boundcheck.MsgBoundPartial, "b", []byte("partial-b"))
	if !p.CheckComplete(ctx) {
		t.Fatal("CheckComplete must be true with 2/2 partials")
	}
}

// TestPhase_Exit_ViolationCallsHandlerAndAborts checks that when the fake
// fuse returns an out-of-bound value for one party, Exit:
//   - calls the ViolationHandler with that party's name, nu, and sev;
//   - returns an error that errors.Is(err, phase.ErrAppAttributable) == true.
func TestPhase_Exit_ViolationCallsHandlerAndAborts(t *testing.T) {
	violatorParty := "bob"
	inBoundValue := 1.0  // norm 1.0 is within [0.99, 1.01]
	outBoundValue := 5.0 // far outside [0.99, 1.01] -> hard violation

	circuit := boundcheck.NormCircuit{Eps: 0.01, Dim: 4}
	params := boundcheck.DefaultParams()
	handler := &captureHandler{}

	// Fuse discriminates by the first byte of the blob:
	//   'a' prefix -> alice -> in-bound
	//   'v' prefix -> violating -> out-of-bound
	fakeFuse := func(partials [][]byte, nSlots int) ([]float64, error) {
		if len(partials) > 0 && len(partials[0]) > 0 && partials[0][0] == 'v' {
			return []float64{outBoundValue}, nil
		}
		return []float64{inBoundValue}, nil
	}

	handle := &fakeContextHandle{cannedCT: []byte("ct")}
	p := newRealPhase(circuit, handler, params, handle, fakeFuse)

	parties := []string{"alice", violatorParty}
	ctx := newCtx(parties, map[string][]byte{"alice": []byte("x"), violatorParty: []byte("y")}, 4)

	_ = p.Enter(ctx)
	_ = p.OnMessage(ctx, boundcheck.MsgBoundPartial, "alice", []byte("alice-partial"))     // 'a' -> in-bound
	_ = p.OnMessage(ctx, boundcheck.MsgBoundPartial, violatorParty, []byte("violating-partial")) // 'v' -> out-of-bound

	err := p.Exit(ctx)
	if err == nil {
		t.Fatal("Exit must return error on violation")
	}
	if !errors.Is(err, phase.ErrAppAttributable) {
		t.Errorf("Exit error must wrap ErrAppAttributable; got %v", err)
	}

	// Handler must have been called at least once.
	if len(handler.calls) == 0 {
		t.Fatal("ViolationHandler.OnViolation was not called")
	}
	// At least one call must be for the violating party.
	found := false
	for _, c := range handler.calls {
		if c.party == violatorParty {
			found = true
			if c.sev == boundcheck.SeverityOK {
				t.Errorf("handler called with SeverityOK for violating party; sev=%v", c.sev)
			}
		}
	}
	if !found {
		t.Errorf("handler not called for violating party %q; calls = %v", violatorParty, handler.calls)
	}
}

// TestPhase_Exit_AllInBound_NoHandlerNoError verifies that when all parties
// submit in-bound values, Exit returns nil and the ViolationHandler is never
// invoked.
func TestPhase_Exit_AllInBound_NoHandlerNoError(t *testing.T) {
	circuit := boundcheck.NormCircuit{Eps: 0.01, Dim: 4}
	params := boundcheck.DefaultParams()
	handler := &captureHandler{}

	// Fuse always returns in-bound value.
	fakeFuse := func(partials [][]byte, nSlots int) ([]float64, error) {
		return []float64{1.0}, nil // 1.0 is within [0.99, 1.01]
	}

	handle := &fakeContextHandle{cannedCT: []byte("ct")}
	p := newRealPhase(circuit, handler, params, handle, fakeFuse)

	parties := []string{"alice", "bob"}
	ctx := newCtx(parties, map[string][]byte{"alice": []byte("x"), "bob": []byte("y")}, 4)

	_ = p.Enter(ctx)
	_ = p.OnMessage(ctx, boundcheck.MsgBoundPartial, "alice", []byte("partial-a"))
	_ = p.OnMessage(ctx, boundcheck.MsgBoundPartial, "bob", []byte("partial-b"))

	if err := p.Exit(ctx); err != nil {
		t.Fatalf("Exit must return nil for all-in-bound; got %v", err)
	}
	if len(handler.calls) != 0 {
		t.Fatalf("ViolationHandler must not be called on all-in-bound; calls = %v", handler.calls)
	}
}

// TestPhase_Invariant5_DimRefusal checks that Enter returns a non-nil error
// for CtxInputDim == 0 and CtxInputDim == 1 (invariant #5).
func TestPhase_Invariant5_DimRefusal(t *testing.T) {
	circuit := boundcheck.NormCircuit{Eps: 0.01, Dim: 2}
	p := newStubPhase(circuit, nil, boundcheck.DefaultParams())

	for _, dim := range []int{0, 1} {
		ctx := phase.NewSessionContext("dim-test")
		ctx.Set(defaults.CtxParticipants, []string{"a"})
		ctx.Set(boundcheck.CtxEncryptedInputs, map[string][]byte{"a": []byte("x")})
		ctx.Set(boundcheck.CtxInputDim, dim)
		ctx.Set(boundcheck.CtxEvalKeyBundle, []byte("key"))
		ctx.Set(boundcheck.CtxJointPublicKey, []byte("pk"))

		if err := p.Enter(ctx); err == nil {
			t.Errorf("Enter with dim=%d must return error (invariant #5)", dim)
		}
	}
}

// TestPhase_Invariant5_Dim2_OK confirms that dim >= 2 passes Enter without
// error in stub mode.
func TestPhase_Invariant5_Dim2_OK(t *testing.T) {
	circuit := boundcheck.NormCircuit{Eps: 0.01, Dim: 2}
	p := newStubPhase(circuit, nil, boundcheck.DefaultParams())

	ctx := phase.NewSessionContext("dim-ok")
	ctx.Set(defaults.CtxParticipants, []string{"a"})
	ctx.Set(boundcheck.CtxEncryptedInputs, map[string][]byte{"a": []byte("x")})
	ctx.Set(boundcheck.CtxInputDim, 2)
	ctx.Set(boundcheck.CtxEvalKeyBundle, []byte("key"))
	ctx.Set(boundcheck.CtxJointPublicKey, []byte("pk"))

	if err := p.Enter(ctx); err != nil {
		t.Fatalf("Enter with dim=2 must not error; got %v", err)
	}
}

// TestPhase_Invariant2_OneCircuit is a structural (compile-time) test that
// the Phase constructor takes exactly one BoundCircuit. If the constructor
// signature changed to accept multiple circuits, this would fail to compile.
func TestPhase_Invariant2_OneCircuit(t *testing.T) {
	circuit := boundcheck.NormCircuit{Eps: 0.01, Dim: 4}
	p := boundcheck.NewPhase(circuit, nil, boundcheck.DefaultParams(), defaults.StateScoring, defaults.StateDecrypting)
	if p == nil {
		t.Fatal("NewPhase with one BoundCircuit must return non-nil Phase")
	}
	if p.Name() != "bound-check" {
		t.Errorf("Name() = %q, want %q", p.Name(), "bound-check")
	}
}

// TestPhase_Metadata confirms the phase metadata contract.
func TestPhase_Metadata(t *testing.T) {
	circuit := boundcheck.NormCircuit{Eps: 0.01, Dim: 4}
	p := boundcheck.NewPhase(circuit, nil, boundcheck.DefaultParams(), defaults.StateScoring, defaults.StateDecrypting)

	if p.Lifetime() != phase.LifetimePerSession {
		t.Errorf("Lifetime = %v, want LifetimePerSession", p.Lifetime())
	}
	if p.RunsAt() != phase.RunsAtInline {
		t.Errorf("RunsAt = %v, want RunsAtInline", p.RunsAt())
	}
	if p.EntryState() != defaults.StateScoring {
		t.Errorf("EntryState = %q, want SCORING", p.EntryState())
	}
	if p.ExitState() != defaults.StateDecrypting {
		t.Errorf("ExitState = %q, want DECRYPTING", p.ExitState())
	}
	if p.InternalStates() != nil {
		t.Errorf("InternalStates must be nil")
	}
	consumed := p.ConsumedMessageTypes()
	if len(consumed) != 1 || consumed[0] != boundcheck.MsgBoundPartial {
		t.Errorf("ConsumedMessageTypes = %v, want [%q]", consumed, boundcheck.MsgBoundPartial)
	}
}

// TestPhase_StubMode_EnterExitNoop confirms that stub mode (nil handle and
// fuse) leaves CtxBoundCheckCiphers absent and Exit returns nil regardless
// of accumulated partials. This is the compose-time structural test mode.
func TestPhase_StubMode_EnterExitNoop(t *testing.T) {
	circuit := boundcheck.NormCircuit{Eps: 0.01, Dim: 4}
	p := newStubPhase(circuit, nil, boundcheck.DefaultParams())

	parties := []string{"a", "b"}
	ctx := newCtx(parties, map[string][]byte{"a": []byte("x"), "b": []byte("y")}, 4)

	if err := p.Enter(ctx); err != nil {
		t.Fatalf("stub Enter: %v", err)
	}
	// CtxBoundCheckCiphers must NOT be set in stub mode.
	if ctx.Has(boundcheck.CtxBoundCheckCiphers) {
		t.Error("stub Enter must not set CtxBoundCheckCiphers")
	}

	// Accumulate partials to reach quorum.
	_ = p.OnMessage(ctx, boundcheck.MsgBoundPartial, "a", []byte("pa"))
	_ = p.OnMessage(ctx, boundcheck.MsgBoundPartial, "b", []byte("pb"))
	if !p.CheckComplete(ctx) {
		t.Fatal("stub CheckComplete must be true after N-of-N partials")
	}

	if err := p.Exit(ctx); err != nil {
		t.Fatalf("stub Exit must return nil; got %v", err)
	}
}
