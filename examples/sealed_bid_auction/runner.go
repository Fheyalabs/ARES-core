package sealedbidauction

import (
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

// NewSealedBidAuctionRunner builds a SessionRunner over the auction
// pipeline:
//
//	Invitation → Keygen → ScalarBid → Argmax → Decrypt → Settlement
//
// The pipeline is shorter than Fheya's (six phases vs eight) because
// the auction skips onion-shuffle and verification (no slot
// anonymity required) and replaces Phase D with a one-shot signed
// settlement.
//
// The crypto contract emitted by Invitation carries depth=10
// (vs Fheya's depth=30); Argmax requires depth_min=8, which the
// runner validates at construction time.
//
// PhaseArgmax in this variant uses the stub scoring path. For real
// CKKS scoring against the OpenFHE helper, use
// NewSealedBidAuctionRunnerWithHelper.
func NewSealedBidAuctionRunner() (*phase.SessionRunner, error) {
	return phase.NewSessionRunner(
		NewPhaseInvitation(),
		NewPhaseKeygen(),
		NewPhaseScalarBid(),
		NewPhaseArgmax(),
		NewPhaseDecrypt(),
		NewPhaseSettlement(),
	)
}

// NewSealedBidAuctionRunnerWithHelper builds the same pipeline but
// uses a helper-backed PhaseArgmax. The sharpening polynomial is
// applied to each pairwise bid difference; the [0,1]-mapped degree-3
// approximation (0.5 + 0.75x − 0.25x³) is a sensible default for
// well-separated normalized bids.
func NewSealedBidAuctionRunnerWithHelper(
	helper *helperclient.Client,
	sharpening helperclient.EvalPolyParams,
) (*phase.SessionRunner, error) {
	return phase.NewSessionRunner(
		NewPhaseInvitation(),
		NewPhaseKeygenWithHelper(helper),
		NewPhaseScalarBid(),
		NewPhaseArgmaxWithHelper(helper, sharpening),
		NewPhaseDecrypt(),
		NewPhaseSettlement(),
	)
}
