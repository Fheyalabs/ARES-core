// SPDX-License-Identifier: Apache-2.0

package defaults

import "github.com/Fheyalabs/ares-core/pkg/ares/phase"

// NewARESDefaultRunner builds a SessionRunner over the canonical
// ARES v2.4 phase pipeline:
//
//	Phase 1a — Session Initiation       (INVITING → LOCKED)
//	Phase 0a — Threshold Keygen         (LOCKED   → GOSSIP)
//	Phase G  — Onion Shuffle            (GOSSIP   → VERIFYING)
//	Phase G.2 — Verification            (VERIFYING → SUBMITTING)
//	Phase 1b — Encrypted Submit         (SUBMITTING → SCORING)
//	Phase 2  — FHE Scoring              (SCORING  → DECRYPTING)
//	Phase 3  — Threshold Decrypt        (DECRYPTING → BROADCASTING)
//	Phase D  — Anonymous Broadcast      (BROADCASTING → CLOSED)
//
// Phase 0b (Registration) is non-inline and not part of this runner
// — the binary instantiates it separately for the HTTP /v2/register
// handler.
//
// Application authors take this pipeline as a starting point and
// either consume it as-is (for the Fheya default behavior) or
// replace individual phases to retarget the protocol at different
// use cases. The most common replacements are Phase 2 (the scoring
// circuit) and Phase D (the post-result phase). See task #12
// (sealed-bid auction) and task #14 (non-MPC keygen variants) for
// worked examples once those land.
func NewARESDefaultRunner() (*phase.SessionRunner, error) {
	return phase.NewSessionRunner(
		NewPhase1aSessionInitiation(),
		NewPhase0aThresholdKeygen(),
		NewPhaseGOnionShuffle(),
		NewPhaseG2Verification(),
		NewPhase1bEncryptedSubmit(),
		NewPhase2FHEScoring(),
		NewPhase3ThresholdDecrypt(),
		NewPhaseDAnonymousBroadcast(),
	)
}
