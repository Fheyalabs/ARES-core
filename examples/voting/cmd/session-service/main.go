// SPDX-License-Identifier: Apache-2.0

// Command session-service runs the voting example (onion-shuffle +
// SC-10 lineage variant) as a standalone HTTP+WebSocket service.
//
// Env vars:
//
//	SESSION_PORT     listen port (default 8000)
//	ARES_WS_SECRET   HMAC key for WS auth tokens (empty ⇒ dev-bypass).
//
// To start a session:
//
//	curl -sS http://localhost:8000/admin/sessions -d '{
//	  "session_id": "vote-001",
//	  "participants": ["voter-A","voter-B","voter-C"]
//	}'
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Fheyalabs/ares-core/examples/voting"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/anon"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
	"github.com/Fheyalabs/ares-core/pkg/ares/transport"
)

func main() {
	port := getEnv("SESSION_PORT", "8000")
	secret := []byte(os.Getenv("ARES_WS_SECRET"))
	devBypass := len(secret) == 0

	signer, err := sign.NewEd25519Signer()
	if err != nil {
		log.Fatalf("voting: signer: %v", err)
	}
	verifiers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}

	runner, err := voting.PipelineWithShuffle(signer, verifiers)
	if err != nil {
		log.Fatalf("voting: build runner: %v", err)
	}

	ctx, cancel := signalContext()
	defer cancel()

	logStream := transport.NewLogStream()
	innerTrigger := transport.NewManualAdminTrigger(runner, nil, "vote.invitation")
	trigger := &votingTrigger{inner: innerTrigger}

	svc, err := transport.NewService(transport.Config{
		Addr:           ":" + port,
		ServiceName:    "voting-session-service",
		Secret:         secret,
		AllowDevBypass: devBypass,
		Runner:         runner,
		Trigger:        trigger,
		InviteType:     "vote.invitation",
		LogStream:      logStream,
	})
	if err != nil {
		log.Fatalf("voting: build service: %v", err)
	}
	innerTrigger.Hub = svc.Hub()

	log.Printf("[voting] session-service on :%s (shuffle+lineage, dev_bypass=%v)", port, devBypass)
	if err := svc.Run(ctx); err != nil {
		log.Fatalf("voting: service.Run: %v", err)
	}
}

// votingTrigger wraps ManualAdminTrigger to seed the three participant
// context keys the shuffle arc requires, then advances the session into
// the GOSSIP state so PhaseGShuffle.Enter is called immediately.
type votingTrigger struct {
	inner *transport.ManualAdminTrigger
}

func (t *votingTrigger) Start(sessionID string, participants []string, attrs map[string]any) error {
	if len(participants) < 2 {
		return fmt.Errorf("voting needs at least 2 participants, got %d", len(participants))
	}
	// PhaseInvite.Provides() declares all three keys; seed them here so
	// the session context is populated before PhaseGShuffle.Requires()
	// is consulted during the state advance.
	canonical := map[string]any{
		voting.CtxVoteParticipants:   participants,
		defaults.CtxParticipants:     participants,
		anon.CtxParticipants:         participants,
	}
	for k, v := range attrs {
		canonical[k] = v
	}
	if err := t.inner.Start(sessionID, participants, canonical); err != nil {
		return err
	}
	// Advance past INVITING (PhaseInvite) and LOCKED (PlaintextKeygen)
	// into GOSSIP, which is PhaseGShuffle's EntryState.
	return t.inner.Runner.AdvanceToState(sessionID, defaults.StateGossip)
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		log.Printf("shutdown signal received")
		cancel()
	}()
	return ctx, cancel
}
