package recurringcohortranking

import "github.com/Fheyalabs/ares-core/pkg/ares/phase"

// ── Cohort-formation phases ───────────────────────────────────────

// PhaseCohortForm assembles N participants into a named cohort and
// pins the CKKS parameters. Runs once per cohort lifecycle.
// Entry: COHORT_FORMING, Exit: COHORT_KEYGEN.
type PhaseCohortForm struct{}

func NewPhaseCohortForm() *PhaseCohortForm { return &PhaseCohortForm{} }

func (PhaseCohortForm) Name() string              { return "cohort-form" }
func (PhaseCohortForm) Lifetime() phase.Lifetime   { return phase.LifetimePerCohort }
func (PhaseCohortForm) RunsAt() phase.RunsAt       { return phase.RunsAtInline }
func (PhaseCohortForm) EntryState() phase.SessionState { return StateCohortForming }
func (PhaseCohortForm) ExitState() phase.SessionState  { return StateCohortKeygen }
func (PhaseCohortForm) InternalStates() []phase.SessionState { return nil }
func (PhaseCohortForm) ConsumedMessageTypes() []string { return nil }
func (PhaseCohortForm) Requires() phase.ContextSchema  { return nil }
func (PhaseCohortForm) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants: {TypeName: "[]string"},
		CtxCohortID:     {TypeName: "string"},
	}
}
func (PhaseCohortForm) Enter(*phase.SessionContext) error { return nil }
func (PhaseCohortForm) OnMessage(*phase.SessionContext, string, string, []byte) error {
	return nil
}
func (PhaseCohortForm) CheckComplete(*phase.SessionContext) bool { return true }
func (PhaseCohortForm) Exit(*phase.SessionContext) error         { return nil }

// PhaseCohortKeygen runs the N-party threshold CKKS keygen once
// and persists the key bundle into context. COHORT_KEYGEN →
// COHORT_SEALED.
type PhaseCohortKeygen struct{}

func NewPhaseCohortKeygen() *PhaseCohortKeygen { return &PhaseCohortKeygen{} }

func (PhaseCohortKeygen) Name() string              { return "cohort-keygen" }
func (PhaseCohortKeygen) Lifetime() phase.Lifetime   { return phase.LifetimePerCohort }
func (PhaseCohortKeygen) RunsAt() phase.RunsAt       { return phase.RunsAtInline }
func (PhaseCohortKeygen) EntryState() phase.SessionState { return StateCohortKeygen }
func (PhaseCohortKeygen) ExitState() phase.SessionState  { return StateCohortSealed }
func (PhaseCohortKeygen) InternalStates() []phase.SessionState { return nil }
func (PhaseCohortKeygen) ConsumedMessageTypes() []string {
	return []string{"cohort.keygen.share"}
}
func (PhaseCohortKeygen) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants: {TypeName: "[]string", Required: true},
	}
}
// Cohort keygen produces a lightweight crypto contract (depth=10,
// ring_dim=2048) appropriate for the scalar-ranking circuit.
func (PhaseCohortKeygen) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxCollectivePK:   {TypeName: "[]byte", Constraints: map[string]any{"topology": "preshared"}},
		CtxSecretShares:   {TypeName: "map[string][]byte", Constraints: map[string]any{"topology": "preshared"}},
		CtxEvalKeys:       {TypeName: "OpenFHEEvalKeys"},
		CtxCryptoContract: {TypeName: "OpenFHEContract", Constraints: map[string]any{"depth": 10, "ring_dim": 2048}},
	}
}
func (PhaseCohortKeygen) Enter(*phase.SessionContext) error { return nil }
func (PhaseCohortKeygen) OnMessage(*phase.SessionContext, string, string, []byte) error {
	return nil
}
func (PhaseCohortKeygen) CheckComplete(*phase.SessionContext) bool { return false }
func (PhaseCohortKeygen) Exit(*phase.SessionContext) error         { return nil }

// ── Per-session ranking phases ────────────────────────────────────

// PhaseRankingInvitation selects N members from the cohort and
// emits ranking.invitation. RANKING_INVITING → RANKING_LOCKED.
type PhaseRankingInvitation struct{}

func NewPhaseRankingInvitation() *PhaseRankingInvitation {
	return &PhaseRankingInvitation{}
}

func (PhaseRankingInvitation) Name() string              { return "ranking-invitation" }
func (PhaseRankingInvitation) Lifetime() phase.Lifetime   { return phase.LifetimePerSession }
func (PhaseRankingInvitation) RunsAt() phase.RunsAt       { return phase.RunsAtInline }
func (PhaseRankingInvitation) EntryState() phase.SessionState { return StateRankingInviting }
func (PhaseRankingInvitation) ExitState() phase.SessionState  { return StateRankingLocked }
func (PhaseRankingInvitation) InternalStates() []phase.SessionState { return nil }
func (PhaseRankingInvitation) ConsumedMessageTypes() []string { return nil }
func (PhaseRankingInvitation) Requires() phase.ContextSchema {
	return phase.ContextSchema{CtxParticipants: {TypeName: "[]string", Required: true}}
}
func (PhaseRankingInvitation) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants: {TypeName: "[]string"},
	}
}
func (PhaseRankingInvitation) Enter(*phase.SessionContext) error { return nil }
func (PhaseRankingInvitation) OnMessage(*phase.SessionContext, string, string, []byte) error {
	return nil
}
func (PhaseRankingInvitation) CheckComplete(*phase.SessionContext) bool { return true }
func (PhaseRankingInvitation) Exit(*phase.SessionContext) error         { return nil }

// PhasePreSharedKeyLookup validates that the cohort's key bundle
// is already in the SessionContext (seeded by the caller from
// the cohort-formation runner's outputs). RANKING_LOCKED →
// RANKING_BIDDING. Per-session cost is zero — one Enter call
// with no crypto and no WS messages.
type PhasePreSharedKeyLookup struct{}

func NewPhasePreSharedKeyLookup() *PhasePreSharedKeyLookup {
	return &PhasePreSharedKeyLookup{}
}

func (PhasePreSharedKeyLookup) Name() string              { return "ranking-key-lookup" }
func (PhasePreSharedKeyLookup) Lifetime() phase.Lifetime   { return phase.LifetimePerCohort }
func (PhasePreSharedKeyLookup) RunsAt() phase.RunsAt       { return phase.RunsAtInline }
func (PhasePreSharedKeyLookup) EntryState() phase.SessionState { return StateRankingLocked }
func (PhasePreSharedKeyLookup) ExitState() phase.SessionState  { return StateRankingBidding }
func (PhasePreSharedKeyLookup) InternalStates() []phase.SessionState { return nil }
func (PhasePreSharedKeyLookup) ConsumedMessageTypes() []string { return nil }
func (PhasePreSharedKeyLookup) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxCollectivePK: {TypeName: "[]byte", Required: true},
		CtxSecretShares: {TypeName: "map[string][]byte", Required: true},
		CtxEvalKeys:     {TypeName: "OpenFHEEvalKeys", Required: true},
	}
}
func (PhasePreSharedKeyLookup) Provides() phase.ContextSchema { return nil }
func (PhasePreSharedKeyLookup) Enter(ctx *phase.SessionContext) error {
	for _, key := range []string{CtxCollectivePK, CtxSecretShares, CtxEvalKeys} {
		if !ctx.Has(key) {
			return &phase.MissingContextError{Key: key, Phase: "ranking-key-lookup"}
		}
	}
	return nil
}
func (PhasePreSharedKeyLookup) OnMessage(*phase.SessionContext, string, string, []byte) error {
	return nil
}
func (PhasePreSharedKeyLookup) CheckComplete(*phase.SessionContext) bool { return true }
func (PhasePreSharedKeyLookup) Exit(*phase.SessionContext) error         { return nil }

// PhaseSubmitRating collects one encrypted scalar rating from
// each participant. RANKING_BIDDING → RANKING_SCORING.
type PhaseSubmitRating struct{}

func NewPhaseSubmitRating() *PhaseSubmitRating { return &PhaseSubmitRating{} }

func (PhaseSubmitRating) Name() string              { return "ranking-submit-rating" }
func (PhaseSubmitRating) Lifetime() phase.Lifetime   { return phase.LifetimePerSession }
func (PhaseSubmitRating) RunsAt() phase.RunsAt       { return phase.RunsAtInline }
func (PhaseSubmitRating) EntryState() phase.SessionState { return StateRankingBidding }
func (PhaseSubmitRating) ExitState() phase.SessionState  { return StateRankingScoring }
func (PhaseSubmitRating) InternalStates() []phase.SessionState { return nil }
func (PhaseSubmitRating) ConsumedMessageTypes() []string {
	return []string{"ranking.rating"}
}
func (PhaseSubmitRating) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants: {TypeName: "[]string", Required: true},
	}
}
func (PhaseSubmitRating) Provides() phase.ContextSchema {
	return phase.ContextSchema{CtxRatings: {TypeName: "map[string][]byte"}}
}
func (PhaseSubmitRating) Enter(*phase.SessionContext) error { return nil }
func (PhaseSubmitRating) OnMessage(*phase.SessionContext, string, string, []byte) error {
	return nil
}
func (PhaseSubmitRating) CheckComplete(*phase.SessionContext) bool { return false }
func (PhaseSubmitRating) Exit(*phase.SessionContext) error         { return nil }

// PhaseArgmaxScoring runs encrypted argmax over the N scalar
// ratings. RANKING_SCORING → RANKING_DECRYPT.
type PhaseArgmaxScoring struct{}

func NewPhaseArgmaxScoring() *PhaseArgmaxScoring { return &PhaseArgmaxScoring{} }

func (PhaseArgmaxScoring) Name() string              { return "ranking-argmax-scoring" }
func (PhaseArgmaxScoring) Lifetime() phase.Lifetime   { return phase.LifetimePerSession }
func (PhaseArgmaxScoring) RunsAt() phase.RunsAt       { return phase.RunsAtInline }
func (PhaseArgmaxScoring) EntryState() phase.SessionState { return StateRankingScoring }
func (PhaseArgmaxScoring) ExitState() phase.SessionState  { return StateRankingDecrypt }
func (PhaseArgmaxScoring) InternalStates() []phase.SessionState { return nil }
func (PhaseArgmaxScoring) ConsumedMessageTypes() []string { return nil }
func (PhaseArgmaxScoring) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants:   {TypeName: "[]string", Required: true},
		CtxCryptoContract: {TypeName: "OpenFHEContract", Required: true, Constraints: map[string]any{"depth_min": 8}},
		CtxEvalKeys:       {TypeName: "OpenFHEEvalKeys", Required: true},
		CtxRatings:        {TypeName: "map[string][]byte", Required: true},
	}
}
func (PhaseArgmaxScoring) Provides() phase.ContextSchema {
	return phase.ContextSchema{CtxWinnerRating: {TypeName: "[]byte"}}
}
func (PhaseArgmaxScoring) Enter(*phase.SessionContext) error { return nil }
func (PhaseArgmaxScoring) OnMessage(*phase.SessionContext, string, string, []byte) error {
	return nil
}
func (PhaseArgmaxScoring) CheckComplete(*phase.SessionContext) bool { return false }
func (PhaseArgmaxScoring) Exit(*phase.SessionContext) error         { return nil }

// PhaseThresholdDecrypt recovers the cleartext winner rating.
// RANKING_DECRYPT → RANKING_SETTLED.
type PhaseThresholdDecrypt struct{}

func NewPhaseThresholdDecrypt() *PhaseThresholdDecrypt {
	return &PhaseThresholdDecrypt{}
}

func (PhaseThresholdDecrypt) Name() string              { return "ranking-threshold-decrypt" }
func (PhaseThresholdDecrypt) Lifetime() phase.Lifetime   { return phase.LifetimePerSession }
func (PhaseThresholdDecrypt) RunsAt() phase.RunsAt       { return phase.RunsAtInline }
func (PhaseThresholdDecrypt) EntryState() phase.SessionState { return StateRankingDecrypt }
func (PhaseThresholdDecrypt) ExitState() phase.SessionState  { return StateRankingSettled }
func (PhaseThresholdDecrypt) InternalStates() []phase.SessionState { return nil }
func (PhaseThresholdDecrypt) ConsumedMessageTypes() []string {
	return []string{"ranking.decrypt.partial"}
}
func (PhaseThresholdDecrypt) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants: {TypeName: "[]string", Required: true},
		CtxSecretShares: {TypeName: "map[string][]byte", Required: true},
		CtxWinnerRating: {TypeName: "[]byte", Required: true},
	}
}
func (PhaseThresholdDecrypt) Provides() phase.ContextSchema {
	return phase.ContextSchema{CtxWinner: {TypeName: "WinnerRating"}}
}
func (PhaseThresholdDecrypt) Enter(*phase.SessionContext) error { return nil }
func (PhaseThresholdDecrypt) OnMessage(*phase.SessionContext, string, string, []byte) error {
	return nil
}
func (PhaseThresholdDecrypt) CheckComplete(*phase.SessionContext) bool { return false }
func (PhaseThresholdDecrypt) Exit(*phase.SessionContext) error         { return nil }

// PhaseSettleRanking emits a signed transcript and terminates.
// No post-result back-channel. RANKING_SETTLED → StateNone.
type PhaseSettleRanking struct{}

func NewPhaseSettleRanking() *PhaseSettleRanking { return &PhaseSettleRanking{} }

func (PhaseSettleRanking) Name() string              { return "ranking-settle" }
func (PhaseSettleRanking) Lifetime() phase.Lifetime   { return phase.LifetimePerSession }
func (PhaseSettleRanking) RunsAt() phase.RunsAt       { return phase.RunsAtInline }
func (PhaseSettleRanking) EntryState() phase.SessionState { return StateRankingSettled }
func (PhaseSettleRanking) ExitState() phase.SessionState  { return phase.StateNone }
func (PhaseSettleRanking) InternalStates() []phase.SessionState { return nil }
func (PhaseSettleRanking) ConsumedMessageTypes() []string { return nil }
func (PhaseSettleRanking) Requires() phase.ContextSchema {
	return phase.ContextSchema{CtxWinner: {TypeName: "WinnerRating", Required: true}}
}
func (PhaseSettleRanking) Provides() phase.ContextSchema {
	return phase.ContextSchema{CtxTranscript: {TypeName: "SignedTranscript"}}
}
func (PhaseSettleRanking) Enter(*phase.SessionContext) error { return nil }
func (PhaseSettleRanking) OnMessage(*phase.SessionContext, string, string, []byte) error {
	return nil
}
func (PhaseSettleRanking) CheckComplete(*phase.SessionContext) bool { return true }
func (PhaseSettleRanking) Exit(*phase.SessionContext) error         { return nil }
