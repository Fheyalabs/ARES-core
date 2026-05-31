// SPDX-License-Identifier: Apache-2.0

package boundcheck

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/fhecalib"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
)

// defaultJitter is the maximum random jitter sleep injected before returning
// an abort error from Exit. Kept short (prevents timing oracles without
// adding meaningful latency on the happy path). Callers can override by
// embedding Phase with a different JitterBound.
const defaultJitter = 20 * time.Millisecond

// Phase is the ARES v2.6 Phase-1c bound-check round. One instance is shared
// across every session that uses it; per-session state lives in SessionContext.
//
// Construct via NewPhase (stub mode, no FHE at runtime) or NewPhaseWithCrypto
// (real mode, FHE-backed Enter and Exit).
type Phase struct {
	circuit    BoundCircuit
	handler    ViolationHandler
	params     Params
	entryState phase.SessionState
	exitState  phase.SessionState
	jitter     time.Duration

	// handle is nil in stub mode. Non-nil in real mode: a
	// fhecalib.ContextHandle provisioned with the session's eval keys and
	// joint public key. The consuming application constructs this before
	// starting the session and passes it via NewPhaseWithCrypto.
	handle fhecalib.ContextHandle

	// fuse is nil in stub mode. Non-nil in real mode: fuses the partial-
	// decrypt blobs for one check ciphertext and returns the plaintext
	// values. Signature matches cgo.FuseCKKSPartialsForContract so the
	// real binding is a one-liner; the fake in tests controls output.
	fuse func(partials [][]byte, nSlots int) ([]float64, error)
}

// NewPhase returns a Phase in stub mode (Enter/Exit no-op the FHE path).
// Suitable for compose-time structural tests and pipelines where crypto is
// injected later via NewPhaseWithCrypto.
//
// entryState is the session state that triggers this phase (commonly
// defaults.StateScoring). exitState is the state to transition to on
// completion.
func NewPhase(
	circuit BoundCircuit,
	handler ViolationHandler,
	params Params,
	entryState phase.SessionState,
	exitState phase.SessionState,
) *Phase {
	return &Phase{
		circuit:    circuit,
		handler:    handler,
		params:     params,
		entryState: entryState,
		exitState:  exitState,
		jitter:     defaultJitter,
	}
}

// NewPhaseWithCrypto returns a Phase in real mode. handle is a provisioned
// fhecalib.ContextHandle (e.g. from fhecalib.NewContextHandle); fuse is the
// partial-fusion function (e.g. a closure over cgo.FuseCKKSPartialsForContract
// bound to the session's ContractParams).
//
// Neither handle nor fuse is called on the happy path when no violations occur
// and Enter reaches the no-compute branch — they are invoked only when
// CtxEncryptedInputs is non-empty (Enter) and when partials have been
// accumulated (Exit).
func NewPhaseWithCrypto(
	circuit BoundCircuit,
	handler ViolationHandler,
	params Params,
	entryState phase.SessionState,
	exitState phase.SessionState,
	handle fhecalib.ContextHandle,
	fuse func(partials [][]byte, nSlots int) ([]float64, error),
) *Phase {
	p := NewPhase(circuit, handler, params, entryState, exitState)
	p.handle = handle
	p.fuse = fuse
	return p
}

// --- Phase metadata ---

func (Phase) Name() string { return "bound-check" }

// Lifetime is per-session: check ciphertexts and partial decrypts are not
// reusable across sessions.
func (Phase) Lifetime() phase.Lifetime { return phase.LifetimePerSession }

// RunsAt is inline: the round is triggered by session state and driven by
// inbound MsgBoundPartial messages.
func (Phase) RunsAt() phase.RunsAt { return phase.RunsAtInline }

func (p *Phase) EntryState() phase.SessionState { return p.entryState }
func (p *Phase) ExitState() phase.SessionState  { return p.exitState }

// InternalStates returns nil — the bound-check round has no sub-states.
func (Phase) InternalStates() []phase.SessionState { return nil }

// ConsumedMessageTypes lists the partial-decrypt reply type.
func (Phase) ConsumedMessageTypes() []string { return []string{MsgBoundPartial} }

// Requires declares the SessionContext keys this phase reads from the
// preceding submission phase. The consuming app's submission phase must
// Provide all of these.
//
// Note: CtxSecretShares is deliberately NOT required here. The server does
// not hold individual secret shares; each party's partial-decrypt blob
// already encodes its contribution and FuseCKKSPartialsForContract operates
// directly on the wire blobs.
func (Phase) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxEncryptedInputs: {TypeName: "map[string][]byte", Required: true},
		CtxInputDim:        {TypeName: "int", Required: true},
		CtxEvalKeyBundle:   {TypeName: "[]byte", Required: true},
		CtxJointPublicKey:  {TypeName: "[]byte", Required: true},
		defaults.CtxParticipants: {TypeName: "[]string", Required: true},
	}
}

// Provides declares the SessionContext keys this phase writes. The consuming
// application MUST read CtxBoundCheckCiphers after Enter returns and unicast
// enc_check_i to each participant before their MsgBoundPartial reply is
// expected.
func (Phase) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxBoundCheckCiphers: {TypeName: "map[string][]byte"},
	}
}

// --- Lifecycle hooks ---

// Enter enforces invariant #5 (dim refusal), then computes enc_check_i for
// every party in CtxEncryptedInputs and stores the results in
// CtxBoundCheckCiphers. In stub mode (handle == nil), the FHE compute is
// skipped and CtxBoundCheckCiphers is not set; structural tests that do not
// need real ciphertexts can use stub mode.
//
// The consuming app must read CtxBoundCheckCiphers immediately after Enter
// and unicast each enc_check_i to the corresponding participant.
func (p *Phase) Enter(ctx *phase.SessionContext) error {
	// Invariant #5: dim must be >= 2 (scalar bounds require a Class-2 circuit).
	dim, ok := phase.TryGet[int](ctx, CtxInputDim)
	if !ok {
		return fmt.Errorf("%w: boundcheck: context key %q not set", phase.ErrPermanent, CtxInputDim)
	}
	if dim < 2 {
		return fmt.Errorf("boundcheck: input dim %d < 2; scalar bounds need a Class-2 comparison circuit", dim)
	}

	// Stub mode: skip FHE compute. CtxBoundCheckCiphers is not populated;
	// the app bridge will find an absent key and skip the unicast step.
	if p.handle == nil {
		return nil
	}

	encInputs, ok := phase.TryGet[map[string][]byte](ctx, CtxEncryptedInputs)
	if !ok {
		return fmt.Errorf("%w: boundcheck: context key %q not set", phase.ErrPermanent, CtxEncryptedInputs)
	}

	checks := make(map[string][]byte, len(encInputs))
	for party, encInput := range encInputs {
		encCheck, err := p.circuit.Eval(p.handle, [][]byte{encInput})
		if err != nil {
			return fmt.Errorf("%w: boundcheck: eval circuit for party %s: %w", phase.ErrTransient, party, err)
		}
		// TODO(SP-D-NC-B): emit check_commitment_i = H(serialize(enc_check_i) ‖ H(serialize(enc_x_i)) ‖ session_id)
		// for the app to bind the check ciphertext to the input lineage. This is an app-layer/bridge follow-up
		// and is not a T5 done-criterion; it does not affect the phase-round correctness proven here.
		checks[party] = encCheck
	}
	ctx.Set(CtxBoundCheckCiphers, checks)
	return nil
}

// OnMessage accumulates each party's partial-decrypt map into the internal
// bucket. Each MsgBoundPartial payload is a JSON-serialised map[string][]byte
// keyed by checkedParty → that sender's partial of that check ciphertext.
// Multiple submissions from the same sender overwrite (only the most recent
// map is kept per sender, which is the correct N-of-N pattern).
func (p *Phase) OnMessage(ctx *phase.SessionContext, _ string, from string, payload []byte) error {
	phase.AccumulateMessage(ctx, bucketPartials, from, payload)
	return nil
}

// CheckComplete returns true once every participant has submitted a
// MsgBoundPartial reply (N-of-N quorum).
func (p *Phase) CheckComplete(ctx *phase.SessionContext) bool {
	participants, ok := phase.TryGet[[]string](ctx, defaults.CtxParticipants)
	if !ok {
		return false
	}
	return phase.QuorumReached(ctx, bucketPartials, len(participants))
}

// Exit assembles the N-party quorum of partial decrypts for each check
// ciphertext, fuses them, classifies the result against the circuit's Bound,
// and invokes the ViolationHandler for violating parties before aborting with
// ErrAppAttributable. In stub mode (fuse == nil), Exit returns nil
// unconditionally.
//
// Each sender's MsgBoundPartial payload is a JSON-serialised map[string][]byte
// keyed by checkedParty → that sender's partial of that check ciphertext.
// Exit collects, for each checked party i, all N senders' partials for i into
// a [][]byte slice of length N and calls fuse(partialsForI, 1). This is the
// correct threshold-decrypt quorum: all N parties must contribute a partial
// per ciphertext for the fusion to produce a valid plaintext.
//
// On violation:
//  1. handler.OnViolation is called for every violating party (sequentially).
//  2. A random jitter sleep is introduced to prevent timing oracles.
//  3. A generic fmt.Errorf("%w: bound violation", ErrAppAttributable) is
//     returned — no party identifiers or fused values are included to avoid
//     leaking information to the transport layer.
//
// On all-OK: returns nil; the runner advances the session to ExitState.
func (p *Phase) Exit(ctx *phase.SessionContext) error {
	// Stub mode: no partials to fuse, no check to run.
	if p.fuse == nil {
		return nil
	}

	participants, _ := phase.TryGet[[]string](ctx, defaults.CtxParticipants)
	rawPartials := phase.AccumulatedMessages(ctx, bucketPartials)

	// Decode each sender's JSON map[string][]byte (checkedParty → partial blob).
	// senderMaps[sender][checkedParty] = partial blob.
	senderMaps := make(map[string]map[string][]byte, len(rawPartials))
	for sender, raw := range rawPartials {
		var m map[string][]byte
		if err := json.Unmarshal(raw, &m); err != nil {
			return fmt.Errorf("%w: boundcheck: decode partial map from %s: %w", phase.ErrTransient, sender, err)
		}
		senderMaps[sender] = m
	}

	// For each checked party, assemble all N senders' partials for that
	// ciphertext and fuse them. nSlots=1: enc_check is a scalar (EvalProductSum
	// collapses dim slots to 1 via EvalSum).
	type violation struct {
		party string
		nu    float64
		sev   Severity
	}
	var violators []violation

	for _, checkedParty := range participants {
		// Collect one partial per sender for this checked party's ciphertext,
		// in participants order so the lead partial (participants[0]) is first.
		partialsForI := make([][]byte, 0, len(participants))
		missingQuorum := false
		for _, sender := range participants {
			senderMap, senderPresent := senderMaps[sender]
			if !senderPresent {
				missingQuorum = true
				break
			}
			blob, partialPresent := senderMap[checkedParty]
			if !partialPresent {
				missingQuorum = true
				break
			}
			partialsForI = append(partialsForI, blob)
		}
		if missingQuorum {
			// Missing partial from at least one party is a protocol violation.
			violators = append(violators, violation{party: checkedParty, nu: p.params.NuHard + 1, sev: SeverityHard})
			continue
		}

		values, err := p.fuse(partialsForI, 1)
		if err != nil {
			return fmt.Errorf("%w: boundcheck: fuse partials for checked party %s: %w", phase.ErrTransient, checkedParty, err)
		}
		if len(values) == 0 {
			return fmt.Errorf("%w: boundcheck: fuse returned no values for checked party %s", phase.ErrTransient, checkedParty)
		}
		nu, sev := classify(values[0], p.circuit.Bound(), p.params)
		if sev != SeverityOK {
			violators = append(violators, violation{party: checkedParty, nu: nu, sev: sev})
		}
	}

	if len(violators) == 0 {
		return nil
	}

	// Notify handler for each violator (invariant #4: handler is called
	// before jitter sleep so the app can record the violation synchronously).
	for _, v := range violators {
		if p.handler != nil {
			_ = p.handler.OnViolation(ctx, v.party, v.nu, v.sev)
		}
	}

	// Invariant #4: jitter sleep — prevent timing oracles.
	jitter := p.jitter
	if jitter > 0 {
		time.Sleep(time.Duration(rand.Int64N(int64(jitter))))
	}

	// Invariant #4: opaque abort — no party names or values on the wire.
	return fmt.Errorf("%w: bound violation", phase.ErrAppAttributable)
}
