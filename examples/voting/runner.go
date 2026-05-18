// SPDX-License-Identifier: Apache-2.0

package voting

import (
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/keygen"
)

// Pipeline builds the voting SessionRunner:
//
//	Invite -> PlaintextKeygen -> SubmitVote -> Tally -> Settle
//
// No FHE; PlaintextKeygen is a documented no-op that fills the
// LOCKED -> GOSSIP arc without producing crypto material. Use this
// example as a template for applications whose threat model trusts
// the orchestrator (regulated governance, internal voting, etc.).
func Pipeline() (*phase.SessionRunner, error) {
	return phase.Compose(
		NewPhaseInvite(),
		keygen.NewPlaintextKeygen(),
		NewPhaseSubmitVote(),
		NewPhaseTally(),
		NewPhaseSettle(),
	)
}
