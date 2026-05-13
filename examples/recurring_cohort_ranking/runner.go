package recurringcohortranking

import "github.com/Fheyalabs/ares-core/pkg/ares/phase"

// NewCohortFormationRunner builds a SessionRunner for the one-time
// cohort formation sequence. Run it once per cohort lifecycle:
//
//   FormCohort → ThresholdKeygen → CohortSealed
//
// The key bundle produced by PhaseCohortKeygen is placed in the
// SessionContext with lifetime=per-cohort. The caller seeds each
// subsequent per-session SessionContext with the same keys before
// passing it to a NewWeeklyRankingSession runner.
func NewCohortFormationRunner() (*phase.SessionRunner, error) {
	return phase.NewSessionRunner(
		NewPhaseCohortForm(),
		NewPhaseCohortKeygen(),
		// PhaseCohortKeygen exits to COHORT_SEALED; no further
		// phases (the runner terminates after keygen).
	)
}

// NewWeeklyRankingSession builds a SessionRunner for one weekly
// session that reuses the cohort's pre-shared key bundle:
//
//   Invite → PreSharedKeyLookup → SubmitRating → Argmax → Decrypt → Settle
//
// The PreSharedKeyLookup phase validates that the key bundle (from
// a prior NewCohortFormationRunner) is already in the
// SessionContext.
func NewWeeklyRankingSession() (*phase.SessionRunner, error) {
	return phase.NewSessionRunner(
		NewPhaseRankingInvitation(),
		NewPhasePreSharedKeyLookup(),
		NewPhaseSubmitRating(),
		NewPhaseArgmaxScoring(),
		NewPhaseThresholdDecrypt(),
		NewPhaseSettleRanking(),
	)
}
