package sealedbidauction

import "github.com/Fheyalabs/ares-core/pkg/ares/phase"

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
