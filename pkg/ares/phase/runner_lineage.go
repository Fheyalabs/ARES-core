// SPDX-License-Identifier: Apache-2.0

package phase

import (
	"context"
	"errors"
	"fmt"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
)

// HandleLineageMessage routes an inbound message through SC-10
// verification before dispatching it to the phase's OnMessage. The
// transport layer should call this method (rather than the legacy
// HandleMessage) for runners constructed via ComposeWith.
//
// Verification steps (in order):
//  1. Pipeline is lineage-enabled (r.lineageStore != nil); otherwise
//     fall through to legacy HandleMessage.
//  2. lineageNode is non-nil (v2 frames must carry Lineage).
//  3. lineage.Verify(node, payload, r.lineageVerifiers) succeeds.
//  4. Parent refs resolve in r.lineageStore.
//  5. r.lineageStore.Append succeeds (or returns ErrNodeExists,
//     which is idempotent and OK).
//
// Any failure aborts BEFORE Phase.OnMessage is called and (when a
// failure hook is registered) fires LineageFailureEvent with
// Kind="mismatch-confirmed". The mismatch broadcast frame
// construction is in BuildMismatchClaim (Task 18).
func (r *SessionRunner) HandleLineageMessage(
	sessionID, msgType, from string,
	payload []byte,
	lineageNode *lineage.DAGNode,
) (bool, error) {
	if r.lineageStore == nil {
		// Compose-built runner; fall through to legacy path.
		return r.HandleMessage(sessionID, msgType, from, payload)
	}
	if lineageNode == nil {
		return false, errors.New("phase: HandleLineageMessage requires non-nil lineage node (v2 frame)")
	}

	// Verify the node against the payload.
	verifyErr := lineage.Verify(*lineageNode, payload, r.lineageVerifiers)
	if verifyErr == nil {
		// Parent ref check (cannot be done inside Verify, which
		// operates on a single node in isolation).
		ctx := context.Background()
		for i, parent := range lineageNode.Parents {
			if _, err := r.lineageStore.Get(ctx, parent); err != nil {
				verifyErr = &lineage.MismatchError{
					Field:    "ParentRef",
					Expected: parent[:],
					Got:      []byte(fmt.Sprintf("parent[%d] not in store: %v", i, err)),
					NodeHash: lineageNode.Hash,
				}
				break
			}
		}
	}

	if verifyErr != nil {
		// Fire structured failure event for the consuming app.
		r.fireFailureHook(LineageFailureEvent{
			Kind:       "mismatch-confirmed",
			SessionID:  sessionID,
			PhaseID:    lineageNode.PhaseID,
			Role:       lineageNode.Role,
			Attributee: string(lineageNode.Producer),
			DAGNodes:   []lineage.DAGNode{*lineageNode},
		})
		return false, fmt.Errorf("phase: lineage verify: %w", verifyErr)
	}

	// Verified; persist (idempotent on ErrNodeExists).
	if err := r.lineageStore.Append(context.Background(), *lineageNode); err != nil && !errors.Is(err, lineage.ErrNodeExists) {
		return false, fmt.Errorf("phase: lineage store append: %w", err)
	}

	// Dispatch to phase code.
	return r.HandleMessage(sessionID, msgType, from, payload)
}

// fireFailureHook invokes the registered LineageFailureFn (if any)
// with a structured event. Defensive against nil hooks and against
// hook panics (hook is wrapped in a recover() so a buggy hook
// can't take down the runner).
func (r *SessionRunner) fireFailureHook(ev LineageFailureEvent) {
	if r.lineageFailureHook == nil {
		return
	}
	defer func() {
		// Swallow hook panics; the hook is app code and the runner
		// must not crash if it misbehaves.
		_ = recover()
	}()
	r.lineageFailureHook(ev)
}

// commitPhaseOutputsIfEnabled is invoked by the runner's advance
// loop after Phase.Exit completes successfully. No-op for
// Compose-built runners (lineageStore == nil). For
// ComposeWith-built runners, iterates the phase's Provides schema
// and auto-commits each output key whose declared value is []byte
// and is not marked NoLineage.
//
// Non-[]byte values are skipped silently — apps wanting to commit
// struct types must serialize to []byte themselves before
// ctx.Set. This keeps v0.4.0 framework scope narrow; structured
// auto-serialization is a future enhancement.
//
// Parents are resolved by inspecting Phase.Requires: each
// required key whose current value in ctx is []byte and which has
// a corresponding lineage node in the store contributes a parent
// ref.
func (r *SessionRunner) commitPhaseOutputsIfEnabled(p Phase, ctx *SessionContext) error {
	if r.lineageStore == nil {
		return nil
	}
	parents, err := r.resolveParents(p, ctx)
	if err != nil {
		return err
	}
	for key, kt := range p.Provides() {
		if kt.NoLineage {
			continue
		}
		raw, ok := ctx.Get(key)
		if !ok {
			continue
		}
		payload, ok := raw.([]byte)
		if !ok {
			// Non-byte output; skip auto-commit.
			continue
		}
		node, err := lineage.Commit(
			ctx.SessionID,
			p.Name(),
			key, // role = context key name
			payload,
			parents,
			r.lineageSigner,
		)
		if err != nil {
			return fmt.Errorf("Commit %s.%s: %w", p.Name(), key, err)
		}
		if err := r.lineageStore.Append(context.Background(), node); err != nil && !errors.Is(err, lineage.ErrNodeExists) {
			return fmt.Errorf("Append %s.%s: %w", p.Name(), key, err)
		}
	}
	return nil
}

// resolveParents builds the parent DAGNode list for a phase about
// to commit. For each key in p.Requires(): if the key's current
// context value is []byte, hash it and look up a matching node in
// the store; if found, include as parent. Missing matches are not
// errors (the producer of the input may be on a different runner;
// lineage chains across boundaries are app-layer concerns for
// v0.4.0).
func (r *SessionRunner) resolveParents(p Phase, ctx *SessionContext) ([]lineage.DAGNode, error) {
	var parents []lineage.DAGNode
	for key := range p.Requires() {
		raw, ok := ctx.Get(key)
		if !ok {
			continue
		}
		payload, ok := raw.([]byte)
		if !ok {
			continue
		}
		hash := lineage.HashPayload(payload)
		// Walk the session to find a node whose PayloadHash matches.
		// O(N) per resolve — fine for v0.4.0 typical N≤6 sessions; an
		// index by PayloadHash is a v0.5.0 optimization if profiling
		// shows it.
		for node, err := range r.lineageStore.WalkSession(context.Background(), ctx.SessionID) {
			if err != nil {
				return nil, err
			}
			if node.PayloadHash == hash {
				parents = append(parents, node)
				break
			}
		}
	}
	return parents, nil
}
