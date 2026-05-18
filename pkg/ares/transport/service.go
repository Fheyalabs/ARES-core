package transport

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

// Config wires a SessionRunner into a runnable HTTP+WebSocket service.
//
// Required fields: Addr, Runner. Everything else has a sensible default
// (RealClock, no-op trigger, empty secret with dev bypass) for the
// minimum useful service.
type Config struct {
	// Addr is the listen address (e.g. ":8000").
	Addr string

	// ServiceName tags health/stats responses (e.g. "auction-service").
	ServiceName string

	// Secret is the shared HMAC key for WS auth tokens. If empty,
	// AllowDevBypass must be true.
	Secret         []byte
	AllowDevBypass bool

	// Runner is the SessionRunner that owns the phase pipeline.
	Runner *phase.SessionRunner

	// Trigger decides when sessions start. If nil, a ManualAdminTrigger
	// with no invitation broadcast is installed.
	Trigger SessionTrigger

	// InviteType is the WS message type the default ManualAdminTrigger
	// broadcasts when a session starts. Ignored if Trigger is supplied.
	InviteType string

	// Clock is the time source. If nil, RealClock is used.
	Clock Clock

	// LogStream, if non-nil, is registered on the HTTP mux at
	// /v2/debug/logs. Construct it via NewLogStream at process start.
	LogStream *LogStream
}

// Service composes Hub + Artifacts + Admin + LogStream into a runnable
// HTTP server. Build it with NewService, then call Run.
type Service struct {
	cfg       Config
	hub       *Hub
	artifacts *ArtifactStore
	admin     *AdminHandlers
	mux       *http.ServeMux
}

// NewService validates the config and assembles the service. Returns an
// error if Addr or Runner is missing or if Secret is empty without
// AllowDevBypass.
func NewService(cfg Config) (*Service, error) {
	if cfg.Addr == "" {
		return nil, errors.New("transport: Config.Addr is required")
	}
	if cfg.Runner == nil {
		return nil, errors.New("transport: Config.Runner is required")
	}
	if len(cfg.Secret) == 0 && !cfg.AllowDevBypass {
		return nil, errors.New("transport: empty Secret requires AllowDevBypass=true")
	}
	if cfg.Clock == nil {
		cfg.Clock = RealClock()
	}

	auth := &AuthMiddleware{Secret: cfg.Secret, AllowDevBypass: cfg.AllowDevBypass}
	hub := NewHub(cfg.Clock, auth)
	artifacts := NewArtifactStore()

	if cfg.Trigger == nil {
		cfg.Trigger = NewManualAdminTrigger(cfg.Runner, hub, cfg.InviteType)
	}

	admin := &AdminHandlers{
		ServiceName: cfg.ServiceName,
		Hub:         hub,
		Runner:      cfg.Runner,
		Trigger:     cfg.Trigger,
		Artifacts:   artifacts,
	}

	mux := http.NewServeMux()
	admin.RegisterRoutes(mux)
	if cfg.LogStream != nil {
		cfg.LogStream.RegisterRoutes(mux)
	}
	mux.HandleFunc("/v2/ws", hub.HandleWS)

	// Dispatch every WS frame into the runner.
	hub.SetMessageHandler(func(c *Client, msg WSMessage) {
		if msg.SessionID == "" {
			// Frames without a session_id are non-routable (control
			// messages, future client→server pings). Ignore.
			return
		}
		_, err := cfg.Runner.HandleMessage(msg.SessionID, msg.Type, c.Pseudonym, msg.Payload)
		if err != nil && !isPhaseDoesNotConsume(err) {
			log.Printf("[dispatch] session=%s type=%s from=%s err=%v",
				shortID(msg.SessionID), msg.Type, shortID(c.Pseudonym), err)
		}
	})

	return &Service{
		cfg:       cfg,
		hub:       hub,
		artifacts: artifacts,
		admin:     admin,
		mux:       mux,
	}, nil
}

// Hub returns the underlying Hub for app-specific wiring (typically a
// phase Exit hook that broadcasts a result message).
func (s *Service) Hub() *Hub { return s.hub }

// Artifacts returns the artifact store. Phase hooks Put/Get blobs that
// don't fit in WS frames.
func (s *Service) Artifacts() *ArtifactStore { return s.artifacts }

// Mux returns the HTTP mux for additional app-specific routes.
func (s *Service) Mux() *http.ServeMux { return s.mux }

// Run starts the HTTP server and blocks until ctx is cancelled or the
// server fails. Performs a graceful shutdown on ctx cancellation.
func (s *Service) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:    s.cfg.Addr,
		Handler: s.mux,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Printf("[service] %s listening on %s", s.cfg.ServiceName, s.cfg.Addr)
		errCh <- srv.ListenAndServe()
	}()

	// Sweep the artifact store every 5 minutes.
	sweep := time.NewTicker(5 * time.Minute)
	defer sweep.Stop()

	for {
		select {
		case <-ctx.Done():
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return srv.Shutdown(shutCtx)
		case <-sweep.C:
			if n := s.artifacts.Sweep(); n > 0 {
				log.Printf("[service] swept %d expired artifacts", n)
			}
		case err := <-errCh:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		}
	}
}

func isPhaseDoesNotConsume(err error) bool {
	if err == nil {
		return false
	}
	// runner.HandleMessage returns "phase X: does not consume message
	// type Y in state Z" when the current phase does not claim the
	// message type. This is benign — the engine has already advanced
	// past that phase, or the message is a late-arriving accumulation
	// event whose phase has already completed.
	return strings.Contains(err.Error(), "does not consume message type")
}
