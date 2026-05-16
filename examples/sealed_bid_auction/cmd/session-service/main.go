// Command session-service runs the sealed-bid auction example as a
// standalone HTTP+WebSocket service.
//
// Wiring:
//   - One SessionRunner built from the auction phase pipeline.
//   - One ManualAdminTrigger that seeds CtxAuctionParticipants and
//     CtxAuctionCryptoContract into each new session before broadcasting
//     the "auction.invitation" frame.
//   - transport.Service for the HTTP admin surface and WebSocket hub.
//
// Env vars:
//
//	SESSION_PORT             listen port (default 8000)
//	ARES_WS_SECRET           HMAC key for WS auth tokens. If empty,
//	                         AllowDevBypass is enabled.
//	AUCTION_CRYPTO_DEPTH     CKKS depth (default 30 — reuses the
//	                         existing helper kernel without retuning).
//	AUCTION_RING_DIM         CKKS ring dimension (default 16384).
//
// To start a session:
//
//	curl -sS http://localhost:8000/admin/sessions -d '{
//	  "session_id": "auction-001",
//	  "participants": ["bidder-1","bidder-2","bidder-3"]
//	}'
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/Fheyalabs/ares-core/examples/sealed_bid_auction"
	"github.com/Fheyalabs/ares-core/pkg/ares/transport"
)

func main() {
	port := getEnv("SESSION_PORT", "8000")
	depth, _ := strconv.Atoi(getEnv("AUCTION_CRYPTO_DEPTH", "30"))
	ringDim, _ := strconv.Atoi(getEnv("AUCTION_RING_DIM", "16384"))
	secret := []byte(os.Getenv("ARES_WS_SECRET"))
	devBypass := len(secret) == 0

	logStream := transport.NewLogStream()

	runner, err := sealedbidauction.NewSealedBidAuctionRunner()
	if err != nil {
		log.Fatalf("build auction runner: %v", err)
	}

	cryptoCtx := map[string]any{
		"depth":            depth,
		"ring_dim":         ringDim,
		"scaling_mod_size": 40,
	}

	// The default ManualAdminTrigger is wrapped so that the canonical
	// context keys are seeded automatically when the smoke driver posts
	// just (session_id, participants).
	innerTrigger := transport.NewManualAdminTrigger(runner, nil, "auction.invitation")
	trigger := &auctionTrigger{
		inner:     innerTrigger,
		cryptoCtx: cryptoCtx,
	}

	svc, err := transport.NewService(transport.Config{
		Addr:           ":" + port,
		ServiceName:    "auction-session-service",
		Secret:         secret,
		AllowDevBypass: devBypass,
		Runner:         runner,
		Trigger:        trigger,
		InviteType:     "auction.invitation",
		LogStream:      logStream,
	})
	if err != nil {
		log.Fatalf("build service: %v", err)
	}
	// Re-point the trigger's hub to the live one so the invitation
	// broadcast actually reaches connected clients.
	innerTrigger.Hub = svc.Hub()

	ctx, cancel := signalContext()
	defer cancel()

	log.Printf("[auction] session-service starting on :%s (depth=%d ring_dim=%d dev_bypass=%v)",
		port, depth, ringDim, devBypass)
	if err := svc.Run(ctx); err != nil {
		log.Fatalf("service.Run: %v", err)
	}
}

// auctionTrigger wraps ManualAdminTrigger to inject the canonical
// CtxAuction* context keys from a friendly admin POST body.
type auctionTrigger struct {
	inner     *transport.ManualAdminTrigger
	cryptoCtx map[string]any
}

func (t *auctionTrigger) Start(sessionID string, participants []string, attrs map[string]any) error {
	canonical := map[string]any{
		sealedbidauction.CtxAuctionParticipants:   participants,
		sealedbidauction.CtxAuctionCryptoContract: t.cryptoCtx,
	}
	// Allow caller-supplied attrs to override defaults (e.g. tests
	// supplying a custom crypto contract).
	for k, v := range attrs {
		canonical[k] = v
	}
	return t.inner.Start(sessionID, participants, canonical)
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

