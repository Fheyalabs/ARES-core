// Command session-service runs the ride-share example as a standalone
// HTTP+WebSocket service.
//
// Wiring:
//   - One SessionRunner built from the ride-share phase pipeline.
//   - One rideShareTrigger that seeds CtxParticipants, CtxRoles, and
//     CtxCryptoContract into each new session. The first participant in
//     the admin POST is the rider; the rest are drivers.
//   - transport.Service for the HTTP admin surface and WebSocket hub.
//
// Env vars:
//
//	SESSION_PORT             listen port (default 8000)
//	ARES_WS_SECRET           HMAC key for WS auth tokens.
//	RIDESHARE_CRYPTO_DEPTH   CKKS depth (default 30 — reuses helper
//	                         kernel without retuning).
//	RIDESHARE_RING_DIM       CKKS ring dimension (default 16384).
//
// To start a session:
//
//	curl -sS http://localhost:8000/admin/sessions -d '{
//	  "session_id": "ride-001",
//	  "participants": ["rider-A","driver-1","driver-2","driver-3"]
//	}'
//
// participants[0] is the rider; participants[1:] are drivers.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/Fheyalabs/ares-core/examples/ride_share"
	"github.com/Fheyalabs/ares-core/pkg/ares/transport"
)

func main() {
	port := getEnv("SESSION_PORT", "8000")
	depth, _ := strconv.Atoi(getEnv("RIDESHARE_CRYPTO_DEPTH", "30"))
	ringDim, _ := strconv.Atoi(getEnv("RIDESHARE_RING_DIM", "16384"))
	secret := []byte(os.Getenv("ARES_WS_SECRET"))
	devBypass := len(secret) == 0

	logStream := transport.NewLogStream()

	runner, err := rideshare.NewRideShareRunner()
	if err != nil {
		log.Fatalf("build ride-share runner: %v", err)
	}

	cryptoCtx := map[string]any{
		"depth":            depth,
		"ring_dim":         ringDim,
		"scaling_mod_size": 40,
	}

	innerTrigger := transport.NewManualAdminTrigger(runner, nil, "ride.invitation")
	trigger := &rideShareTrigger{
		inner:     innerTrigger,
		cryptoCtx: cryptoCtx,
	}

	svc, err := transport.NewService(transport.Config{
		Addr:           ":" + port,
		ServiceName:    "rideshare-session-service",
		Secret:         secret,
		AllowDevBypass: devBypass,
		Runner:         runner,
		Trigger:        trigger,
		InviteType:     "ride.invitation",
		LogStream:      logStream,
	})
	if err != nil {
		log.Fatalf("build service: %v", err)
	}
	innerTrigger.Hub = svc.Hub()

	ctx, cancel := signalContext()
	defer cancel()

	log.Printf("[rideshare] session-service starting on :%s (depth=%d ring_dim=%d dev_bypass=%v)",
		port, depth, ringDim, devBypass)
	if err := svc.Run(ctx); err != nil {
		log.Fatalf("service.Run: %v", err)
	}
}

// rideShareTrigger turns the friendly admin POST into the canonical
// (participants, roles, crypto contract) context the ride-share phases
// expect.
//
// First participant = rider; the rest = drivers. Override the role
// assignment by passing attrs["ride.roles"] explicitly.
type rideShareTrigger struct {
	inner     *transport.ManualAdminTrigger
	cryptoCtx map[string]any
}

func (t *rideShareTrigger) Start(sessionID string, participants []string, attrs map[string]any) error {
	if len(participants) < 2 {
		return fmt.Errorf("ride-share session needs at least 2 participants (1 rider + 1 driver), got %d", len(participants))
	}
	roles := defaultRoles(participants)

	canonical := map[string]any{
		rideshare.CtxParticipants:   participants,
		rideshare.CtxRoles:          roles,
		rideshare.CtxCryptoContract: t.cryptoCtx,
	}
	for k, v := range attrs {
		canonical[k] = v
	}
	return t.inner.Start(sessionID, participants, canonical)
}

func defaultRoles(participants []string) map[string]string {
	roles := make(map[string]string, len(participants))
	for i, p := range participants {
		if i == 0 {
			roles[p] = "rider"
		} else {
			roles[p] = "driver"
		}
	}
	return roles
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
