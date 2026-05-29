// SPDX-License-Identifier: Apache-2.0

package anon

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
)

// SlotEntry is one anonymized slot's assignment in the assembled list.
type SlotEntry struct {
	SlotIndex    int    `json:"slot_index"`
	SlotDKPubHex string `json:"slot_dk_pub"`
}

// PhaseGVerify accumulates each participant's signed slot submission
// and assembles the ordered slot list. Each submission is an
// ephemeral-key-signed lineage node verified by the runner before
// OnMessage runs; the assembled list is auto-committed with those
// submissions as lineage parents, so any post-submission tampering is
// caught by the lineage layer (no bespoke hash cross-check needed).
//
// exitState is the caller's next state after VERIFYING (commonly the
// application's input-submission arc, e.g. defaults.StateSubmitting).
type PhaseGVerify struct {
	exitState phase.SessionState
}

func NewPhaseGVerify(exitState phase.SessionState) *PhaseGVerify {
	return &PhaseGVerify{exitState: exitState}
}

func (PhaseGVerify) Name() string                         { return "anon-g-verify" }
func (PhaseGVerify) Lifetime() phase.Lifetime             { return phase.LifetimePerSession }
func (PhaseGVerify) RunsAt() phase.RunsAt                 { return phase.RunsAtInline }
func (PhaseGVerify) EntryState() phase.SessionState       { return defaults.StateVerifying }
func (p PhaseGVerify) ExitState() phase.SessionState      { return p.exitState }
func (PhaseGVerify) InternalStates() []phase.SessionState { return nil }
func (PhaseGVerify) ConsumedMessageTypes() []string       { return []string{MsgSlotSubmit} }
func (PhaseGVerify) Requires() phase.ContextSchema {
	return phase.ContextSchema{CtxParticipants: {TypeName: "[]string", Required: true}}
}
func (PhaseGVerify) Provides() phase.ContextSchema {
	// []byte -> auto-committed to lineage (parents = slot submissions).
	return phase.ContextSchema{CtxAssembledSlotList: {TypeName: "[]byte"}}
}
func (PhaseGVerify) Enter(*phase.SessionContext) error { return nil }

func (PhaseGVerify) OnMessage(ctx *phase.SessionContext, _, from string, payload []byte) error {
	phase.AccumulateMessage(ctx, bucketSlots, from, payload)
	return nil
}

func (PhaseGVerify) CheckComplete(ctx *phase.SessionContext) bool {
	participants, ok := phase.TryGet[[]string](ctx, CtxParticipants)
	if !ok {
		return false
	}
	return phase.QuorumReached(ctx, bucketSlots, len(participants))
}

func (PhaseGVerify) Exit(ctx *phase.SessionContext) error {
	raw := phase.AccumulatedMessages(ctx, bucketSlots)
	entries := make([]SlotEntry, 0, len(raw))
	seen := make(map[int]bool, len(raw))
	for sender, payload := range raw {
		var e SlotEntry
		if err := json.Unmarshal(payload, &e); err != nil {
			return fmt.Errorf("anon: decode slot submission from %s: %w", sender, err)
		}
		if seen[e.SlotIndex] {
			return fmt.Errorf("anon: duplicate slot index %d", e.SlotIndex)
		}
		seen[e.SlotIndex] = true
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].SlotIndex < entries[j].SlotIndex })
	encoded, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("anon: encode assembled slot list: %w", err)
	}
	ctx.Set(CtxAssembledSlotList, encoded)
	return nil
}
