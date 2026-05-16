package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/gorilla/websocket"
)

// twoStatePhase consumes "advance" messages and transitions when one
// arrives. Used to exercise the end-to-end dispatch path from a WS
// frame through Service into SessionRunner.HandleMessage.
type twoStatePhase struct {
	name      string
	entry     phase.SessionState
	exit      phase.SessionState
	consumes  []string
	mu        sync.Mutex
	gotMsgsFn func()
}

func (p *twoStatePhase) Name() string                         { return p.name }
func (p *twoStatePhase) Lifetime() phase.Lifetime             { return phase.LifetimePerSession }
func (p *twoStatePhase) RunsAt() phase.RunsAt                 { return phase.RunsAtInline }
func (p *twoStatePhase) EntryState() phase.SessionState       { return p.entry }
func (p *twoStatePhase) ExitState() phase.SessionState        { return p.exit }
func (p *twoStatePhase) InternalStates() []phase.SessionState { return nil }
func (p *twoStatePhase) ConsumedMessageTypes() []string       { return p.consumes }
func (p *twoStatePhase) Requires() phase.ContextSchema        { return nil }
func (p *twoStatePhase) Provides() phase.ContextSchema        { return nil }
func (p *twoStatePhase) Enter(*phase.SessionContext) error    { return nil }
func (p *twoStatePhase) OnMessage(*phase.SessionContext, string, string, []byte) error {
	p.mu.Lock()
	if p.gotMsgsFn != nil {
		p.gotMsgsFn()
	}
	p.mu.Unlock()
	return nil
}
func (p *twoStatePhase) CheckComplete(*phase.SessionContext) bool { return true }
func (p *twoStatePhase) Exit(*phase.SessionContext) error         { return nil }

func newDispatchRunner(t *testing.T, gotMsg func()) *phase.SessionRunner {
	t.Helper()
	first := &twoStatePhase{
		name:     "first",
		entry:    "FIRST",
		exit:     "SECOND",
		consumes: []string{"advance"},
		gotMsgsFn: gotMsg,
	}
	second := &twoStatePhase{
		name:  "second",
		entry: "SECOND",
		exit:  phase.StateNone,
	}
	r, err := phase.NewSessionRunner(first, second)
	if err != nil {
		t.Fatalf("NewSessionRunner: %v", err)
	}
	return r
}

// freePort picks an available TCP port for the test service.
func freePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	return l.Addr().String()
}

func TestService_EndToEnd_AdminStartAndDispatch(t *testing.T) {
	var (
		mu     sync.Mutex
		seen   int
	)
	runner := newDispatchRunner(t, func() { mu.Lock(); seen++; mu.Unlock() })

	addr := freePort(t)
	svc, err := NewService(Config{
		Addr:           addr,
		ServiceName:    "test-service",
		AllowDevBypass: true,
		Runner:         runner,
		InviteType:     "test.invite",
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- svc.Run(ctx) }()

	// Wait for the listener to come up.
	waitForHTTP(t, "http://"+addr+"/admin/health", 2*time.Second)

	// Dial WS so the participant is connected before BeginSession.
	wsURL := url.URL{Scheme: "ws", Host: addr, Path: "/v2/ws"}
	q := wsURL.Query()
	q.Set("pseudonym", "p-alpha")
	wsURL.RawQuery = q.Encode()
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL.String(), nil)
	if err != nil {
		t.Fatalf("dial ws: %v", err)
	}
	defer wsConn.Close()

	waitFor(t, func() bool { return svc.Hub().IsConnected("p-alpha") }, 2*time.Second)

	// POST /admin/sessions to start a session.
	body, _ := json.Marshal(sessionStartRequest{
		SessionID:    "S-1",
		Participants: []string{"p-alpha"},
	})
	resp, err := http.Post("http://"+addr+"/admin/sessions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST sessions: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	// Drain the invite frame.
	wsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := wsConn.ReadMessage(); err != nil {
		t.Fatalf("expected invite, got err=%v", err)
	}

	// Send an "advance" message via WS. The dispatch path should
	// land it in SessionRunner.HandleMessage → phase OnMessage.
	frame := WSMessage{
		Type:      "advance",
		SessionID: "S-1",
	}
	frameBody, _ := json.Marshal(frame)
	if err := wsConn.WriteMessage(websocket.TextMessage, frameBody); err != nil {
		t.Fatalf("write: %v", err)
	}

	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return seen >= 1 }, 2*time.Second)

	// GET /admin/sessions/{id} should now report state=SECOND.
	r, err := http.Get("http://" + addr + "/admin/sessions/S-1")
	if err != nil {
		t.Fatalf("GET session: %v", err)
	}
	defer r.Body.Close()
	var sr sessionStartResponse
	_ = json.NewDecoder(r.Body).Decode(&sr)
	if sr.State != "SECOND" {
		t.Errorf("session state = %q, want SECOND", sr.State)
	}
}

func TestService_RejectsMissingAddr(t *testing.T) {
	_, err := NewService(Config{AllowDevBypass: true, Runner: newDispatchRunner(t, nil)})
	if err == nil {
		t.Errorf("expected NewService to require Addr")
	}
}

func TestService_RejectsEmptySecretWithoutBypass(t *testing.T) {
	_, err := NewService(Config{
		Addr:   ":9999",
		Runner: newDispatchRunner(t, nil),
	})
	if err == nil {
		t.Errorf("expected NewService to reject empty Secret without AllowDevBypass")
	}
}

func TestService_ArtifactPutGet(t *testing.T) {
	runner := newDispatchRunner(t, nil)
	addr := freePort(t)
	svc, err := NewService(Config{
		Addr:           addr,
		AllowDevBypass: true,
		Runner:         runner,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go svc.Run(ctx)
	waitForHTTP(t, "http://"+addr+"/admin/health", 2*time.Second)

	// PUT artifact.
	req, _ := http.NewRequest(http.MethodPut, "http://"+addr+"/v2/artifacts/blob-1", bytes.NewReader([]byte("hello")))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT status = %d", resp.StatusCode)
	}

	// GET it back.
	r, err := http.Get("http://" + addr + "/v2/artifacts/blob-1")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer r.Body.Close()
	buf := make([]byte, 64)
	n, _ := r.Body.Read(buf)
	if string(buf[:n]) != "hello" {
		t.Errorf("artifact body = %q, want hello", buf[:n])
	}
}

func waitForHTTP(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("HTTP %s did not become reachable within %s", url, timeout)
}
