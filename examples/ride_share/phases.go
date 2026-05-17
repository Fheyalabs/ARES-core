package rideshare

import "github.com/Fheyalabs/ares-core/pkg/ares/phase"

// ── PhaseInvite: assemble participants, assign roles, pin contract ─

type PhaseInvite struct{}

func NewPhaseInvite() *PhaseInvite { return &PhaseInvite{} }

func (PhaseInvite) Name() string                        { return "ride-invite" }
func (PhaseInvite) Lifetime() phase.Lifetime            { return phase.LifetimePerSession }
func (PhaseInvite) RunsAt() phase.RunsAt                { return phase.RunsAtInline }
func (PhaseInvite) EntryState() phase.SessionState      { return StateInvite }
func (PhaseInvite) ExitState() phase.SessionState       { return StateKeygen }
func (PhaseInvite) InternalStates() []phase.SessionState { return nil }
func (PhaseInvite) ConsumedMessageTypes() []string      { return nil }
func (PhaseInvite) Requires() phase.ContextSchema       { return nil }
func (PhaseInvite) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants: {TypeName: "[]string"},
		CtxRoles:        {TypeName: "map[string]string"},
		CtxCryptoContract: {TypeName: "OpenFHEContract",
			Constraints: map[string]any{
				"depth": 12, "ring_dim": 2048, "scaling_mod_size": 40,
			}},
	}
}
func (PhaseInvite) Enter(*phase.SessionContext) error    { return nil }
func (PhaseInvite) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (PhaseInvite) CheckComplete(*phase.SessionContext) bool { return true }
func (PhaseInvite) Exit(*phase.SessionContext) error     { return nil }

// ── PhaseKeygen: threshold CKKS keygen (shared with other apps) ──

type PhaseKeygen struct{}

func NewPhaseKeygen() *PhaseKeygen { return &PhaseKeygen{} }

func (PhaseKeygen) Name() string                        { return "ride-keygen" }
func (PhaseKeygen) Lifetime() phase.Lifetime            { return phase.LifetimePerSession }
func (PhaseKeygen) RunsAt() phase.RunsAt                { return phase.RunsAtInline }
func (PhaseKeygen) EntryState() phase.SessionState      { return StateKeygen }
func (PhaseKeygen) ExitState() phase.SessionState       { return StateSubmit }
func (PhaseKeygen) InternalStates() []phase.SessionState { return nil }
func (PhaseKeygen) ConsumedMessageTypes() []string {
	return []string{"ride.keygen.share"}
}
func (PhaseKeygen) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants:   {TypeName: "[]string", Required: true},
		CtxCryptoContract: {TypeName: "OpenFHEContract", Required: true, Constraints: map[string]any{"depth_min": 4}},
	}
}
func (PhaseKeygen) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxCollectivePK: {TypeName: "[]byte"},
		CtxSecretShares: {TypeName: "map[string][]byte"},
		CtxEvalKeys:     {TypeName: "OpenFHEEvalKeys"},
	}
}
func (PhaseKeygen) Enter(*phase.SessionContext) error { return nil }
func (PhaseKeygen) OnMessage(ctx *phase.SessionContext, _, from string, payload []byte) error {
	phase.AccumulateMessage(ctx, bucketKeygenShares, from, payload)
	return nil
}
func (PhaseKeygen) CheckComplete(ctx *phase.SessionContext) bool {
	participants, ok := phase.TryGet[[]string](ctx, CtxParticipants)
	if !ok {
		return false
	}
	return phase.QuorumReached(ctx, bucketKeygenShares, len(participants))
}
func (PhaseKeygen) Exit(ctx *phase.SessionContext) error {
	shares := phase.AccumulatedMessages(ctx, bucketKeygenShares)
	ctx.Set(CtxCollectivePK, []byte("stub-collective-pk"))
	ctx.Set(CtxSecretShares, shares)
	ctx.Set(CtxEvalKeys, []byte("stub-eval-keys"))
	return nil
}

// ── PhaseSubmit: encrypted driver bids and rider max price + locations ─

type PhaseSubmit struct{}

func NewPhaseSubmit() *PhaseSubmit { return &PhaseSubmit{} }

func (PhaseSubmit) Name() string                        { return "ride-submit" }
func (PhaseSubmit) Lifetime() phase.Lifetime            { return phase.LifetimePerSession }
func (PhaseSubmit) RunsAt() phase.RunsAt                { return phase.RunsAtInline }
func (PhaseSubmit) EntryState() phase.SessionState      { return StateSubmit }
func (PhaseSubmit) ExitState() phase.SessionState       { return StateScore }
func (PhaseSubmit) InternalStates() []phase.SessionState { return nil }
func (PhaseSubmit) ConsumedMessageTypes() []string {
	return []string{"ride.bid", "ride.request"}
}
func (PhaseSubmit) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants: {TypeName: "[]string", Required: true},
		CtxRoles:        {TypeName: "map[string]string", Required: true},
		CtxCollectivePK: {TypeName: "[]byte", Required: true},
		CtxCryptoContract: {TypeName: "OpenFHEContract", Required: true},
	}
}
func (PhaseSubmit) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxBids: {TypeName: "RideShareBids"},
	}
}
func (PhaseSubmit) Enter(*phase.SessionContext) error { return nil }
func (PhaseSubmit) OnMessage(ctx *phase.SessionContext, _, from string, payload []byte) error {
	phase.AccumulateMessage(ctx, bucketBids, from, payload)
	return nil
}
func (PhaseSubmit) CheckComplete(ctx *phase.SessionContext) bool {
	participants, ok := phase.TryGet[[]string](ctx, CtxParticipants)
	if !ok {
		return false
	}
	return phase.QuorumReached(ctx, bucketBids, len(participants))
}
func (PhaseSubmit) Exit(ctx *phase.SessionContext) error {
	ctx.Set(CtxBids, phase.AccumulatedMessages(ctx, bucketBids))
	return nil
}

// ── PhaseScore: composite score = α·price_fitness + β·proximity ──

type PhaseScore struct{}

func NewPhaseScore() *PhaseScore { return &PhaseScore{} }

func (PhaseScore) Name() string                        { return "ride-score" }
func (PhaseScore) Lifetime() phase.Lifetime            { return phase.LifetimePerSession }
func (PhaseScore) RunsAt() phase.RunsAt                { return phase.RunsAtInline }
func (PhaseScore) EntryState() phase.SessionState      { return StateScore }
func (PhaseScore) ExitState() phase.SessionState       { return StateDecrypt }
func (PhaseScore) InternalStates() []phase.SessionState { return nil }
func (PhaseScore) ConsumedMessageTypes() []string      { return nil }
func (PhaseScore) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants:   {TypeName: "[]string", Required: true},
		CtxCryptoContract: {TypeName: "OpenFHEContract", Required: true},
		CtxEvalKeys:       {TypeName: "OpenFHEEvalKeys", Required: true},
		CtxBids:           {TypeName: "RideShareBids", Required: true},
	}
}
func (PhaseScore) Provides() phase.ContextSchema {
	return phase.ContextSchema{CtxWinner: {TypeName: "[]byte"}}
}
func (PhaseScore) Enter(ctx *phase.SessionContext) error {
	bids := phase.AccumulatedMessages(ctx, bucketBids)
	ctx.Set(CtxWinner, append([]byte("stub-winner-of-"), byte(len(bids))))
	return nil
}
func (PhaseScore) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (PhaseScore) CheckComplete(*phase.SessionContext) bool                       { return true }
func (PhaseScore) Exit(*phase.SessionContext) error                               { return nil }

// ── PhaseDecrypt: threshold decrypt → (price, driver, rider) ──

type PhaseDecrypt struct{}

func NewPhaseDecrypt() *PhaseDecrypt { return &PhaseDecrypt{} }

func (PhaseDecrypt) Name() string                        { return "ride-decrypt" }
func (PhaseDecrypt) Lifetime() phase.Lifetime            { return phase.LifetimePerSession }
func (PhaseDecrypt) RunsAt() phase.RunsAt                { return phase.RunsAtInline }
func (PhaseDecrypt) EntryState() phase.SessionState      { return StateDecrypt }
func (PhaseDecrypt) ExitState() phase.SessionState       { return StateSettle }
func (PhaseDecrypt) InternalStates() []phase.SessionState { return nil }
func (PhaseDecrypt) ConsumedMessageTypes() []string {
	return []string{"ride.decrypt.partial"}
}
func (PhaseDecrypt) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants: {TypeName: "[]string", Required: true},
		CtxSecretShares: {TypeName: "map[string][]byte", Required: true},
		CtxWinner:       {TypeName: "[]byte", Required: true},
	}
}
func (PhaseDecrypt) Provides() phase.ContextSchema {
	return phase.ContextSchema{CtxResult: {TypeName: "RideShareResult"}}
}
func (PhaseDecrypt) Enter(*phase.SessionContext) error { return nil }
func (PhaseDecrypt) OnMessage(ctx *phase.SessionContext, _, from string, payload []byte) error {
	phase.AccumulateMessage(ctx, bucketDecryptPartials, from, payload)
	return nil
}
func (PhaseDecrypt) CheckComplete(ctx *phase.SessionContext) bool {
	participants, ok := phase.TryGet[[]string](ctx, CtxParticipants)
	if !ok {
		return false
	}
	return phase.QuorumReached(ctx, bucketDecryptPartials, len(participants))
}
func (PhaseDecrypt) Exit(ctx *phase.SessionContext) error {
	ctx.Set(CtxResult, map[string]any{
		"agreed_price": 0,
		"driver_id":    "stub-driver",
		"rider_id":     "stub-rider",
	})
	return nil
}

// ── PhaseSettle: broadcast result to both parties ──

type PhaseSettle struct{}

func NewPhaseSettle() *PhaseSettle { return &PhaseSettle{} }

func (PhaseSettle) Name() string                        { return "ride-settle" }
func (PhaseSettle) Lifetime() phase.Lifetime            { return phase.LifetimePerSession }
func (PhaseSettle) RunsAt() phase.RunsAt                { return phase.RunsAtInline }
func (PhaseSettle) EntryState() phase.SessionState      { return StateSettle }
func (PhaseSettle) ExitState() phase.SessionState       { return phase.StateNone }
func (PhaseSettle) InternalStates() []phase.SessionState { return nil }
func (PhaseSettle) ConsumedMessageTypes() []string      { return nil }
func (PhaseSettle) Requires() phase.ContextSchema {
	return phase.ContextSchema{CtxResult: {TypeName: "RideShareResult", Required: true}}
}
func (PhaseSettle) Provides() phase.ContextSchema {
	return phase.ContextSchema{CtxSettlement: {TypeName: "SignedTranscript"}}
}
func (PhaseSettle) Enter(ctx *phase.SessionContext) error {
	result, _ := ctx.Get(CtxResult)
	ctx.Set(CtxSettlement, map[string]any{
		"transcript_for": result,
		"signed_by":      "stub-rideshare-signature",
	})
	return nil
}
func (PhaseSettle) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (PhaseSettle) CheckComplete(*phase.SessionContext) bool                       { return true }
func (PhaseSettle) Exit(*phase.SessionContext) error                               { return nil }
