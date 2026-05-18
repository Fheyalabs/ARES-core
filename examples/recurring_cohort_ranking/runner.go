// SPDX-License-Identifier: Apache-2.0

package cohort

import (
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

// FormationPipeline builds a SessionRunner for the one-time
// cohort formation sequence. Run it once per cohort lifecycle:
//
//   FormCohort → ThresholdKeygen → CohortSealed
//
// The key bundle produced by PhaseCohortKeygen is placed in the
// SessionContext with lifetime=per-cohort. The caller seeds each
// subsequent per-session SessionContext with the same keys before
// passing it to a WeeklyPipeline runner.
func FormationPipeline() (*phase.SessionRunner, error) {
	return phase.Compose(
		NewPhaseCohortForm(),
		NewPhaseCohortKeygen(),
		// PhaseCohortKeygen exits to COHORT_SEALED; no further
		// phases (the runner terminates after keygen).
	)
}

// FormationPipelineWithHelper substitutes the helper-backed
// PhaseCohortKeygen so cohort formation produces real CKKS keys
// instead of stub bytes. The operator pulls the resulting bundle
// out of CtxCollectivePK + CtxEvalKeys (e.g. via an artifact
// endpoint) and feeds it into WeeklyPipelineWithHelper
// via pre-shared attrs.
func FormationPipelineWithHelper(helper *helperclient.Client) (*phase.SessionRunner, error) {
	return phase.Compose(
		NewPhaseCohortForm(),
		NewPhaseCohortKeygenWithHelper(helper),
	)
}

// WeeklyPipeline builds a SessionRunner for one weekly
// session that reuses the cohort's pre-shared key bundle:
//
//   Invite → PreSharedKeyLookup → SubmitRating → Argmax → Decrypt → Settle
//
// The PreSharedKeyLookup phase validates that the key bundle (from
// a prior FormationPipeline) is already in the
// SessionContext.
func WeeklyPipeline() (*phase.SessionRunner, error) {
	return phase.Compose(
		NewPhaseRankingInvitation(),
		NewPhasePreSharedKeyLookup(),
		NewPhaseSubmitRating(),
		NewPhaseArgmaxScoring(),
		NewPhaseThresholdDecrypt(),
		NewPhaseSettleRanking(),
	)
}

// WeeklyPipelineWithHelper substitutes the helper-backed
// PhaseArgmaxScoring for the stub. Used when the cohort service runs
// against a real OpenFHE helper.
func WeeklyPipelineWithHelper(
	helper *helperclient.Client,
	sharpening helperclient.EvalPolyParams,
) (*phase.SessionRunner, error) {
	return phase.Compose(
		NewPhaseRankingInvitation(),
		NewPhasePreSharedKeyLookup(),
		NewPhaseSubmitRating(),
		NewPhaseArgmaxScoringWithHelper(helper, sharpening),
		NewPhaseThresholdDecryptWithHelper(helper),
		NewPhaseSettleRanking(),
	)
}
