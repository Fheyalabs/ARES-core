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
