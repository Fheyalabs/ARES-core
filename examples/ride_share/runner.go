// SPDX-License-Identifier: Apache-2.0

package rideshare

import (
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

// Pipeline builds a SessionRunner for the inDrive-style
// ride-share pipeline:
//
//   Invite → Keygen → Submit → Score → Decrypt → Settle
//
// Six phases. Depth=12 circuit (price_fitness × proximity_fitness
// composite score — shallower than Fheya's depth=30 cosine chain
// but deeper than the auction's depth=10 scalar argmax).
//
// Roles are assigned by PhaseInvite: one rider, N drivers.
// The scorer computes a composite (weighted sum of price
// fitness and proximity) for each driver and selects the
// argmax. The winner package reveals (agreed_price,
// driver_id, rider_id) to both parties.
func Pipeline() (*phase.SessionRunner, error) {
	return phase.Compose(
		NewPhaseInvite(),
		NewPhaseKeygen(),
		NewPhaseSubmit(),
		NewPhaseScore(),
		NewPhaseDecrypt(),
		NewPhaseSettle(),
	)
}

// PipelineWithHelper substitutes the helper-backed phases
// for the stubs. PhaseKeygen produces real threshold CKKS keys
// (unless pre-shared keys are seeded into context by the trigger)
// and PhaseScore runs real argmax against the encrypted bids.
func PipelineWithHelper(
	helper *helperclient.Client,
	sharpening helperclient.EvalPolyParams,
) (*phase.SessionRunner, error) {
	return phase.Compose(
		NewPhaseInvite(),
		NewPhaseKeygenWithHelper(helper),
		NewPhaseSubmit(),
		NewPhaseScoreWithHelper(helper, sharpening),
		NewPhaseDecryptWithHelper(helper),
		NewPhaseSettle(),
	)
}
