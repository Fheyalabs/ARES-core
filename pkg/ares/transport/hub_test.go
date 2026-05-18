// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// wsServer stands up the hub on an httptest server and returns a
// connected client. Caller defers teardown.
func wsServer(t *testing.T, hub *Hub, pseudonym, token string) (*websocket.Conn, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(hub.HandleWS))
	u, _ := url.Parse(srv.URL)
	u.Scheme = "ws"
	q := u.Query()
	q.Set("pseudonym", pseudonym)
	q.Set("auth", token)
	u.RawQuery = q.Encode()
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		srv.Close()
		t.Fatalf("dial: %v", err)
	}
	return conn, func() {
		conn.Close()
		srv.Close()
	}
}

func waitFor(t *testing.T, cond func() bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out after %s", timeout)
}

func TestHub_ConnectAndReceiveBroadcast(t *testing.T) {
	hub := NewHub(RealClock(), &AuthMiddleware{AllowDevBypass: true})
	conn, teardown := wsServer(t, hub, "alice", "")
	defer teardown()

	waitFor(t, func() bool { return hub.IsConnected("alice") }, 2*time.Second)

	hub.Broadcast(WSMessage{Type: "hello", Payload: json.RawMessage(`"world"`)})

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	var got WSMessage
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Type != "hello" {
		t.Errorf("got Type=%q, want hello", got.Type)
	}
}

func TestHub_DispatchInboundMessage(t *testing.T) {
	hub := NewHub(RealClock(), &AuthMiddleware{AllowDevBypass: true})

	var (
		mu   sync.Mutex
		seen WSMessage
		got  bool
	)
	hub.SetMessageHandler(func(_ *Client, msg WSMessage) {
		mu.Lock()
		seen = msg
		got = true
		mu.Unlock()
	})

	conn, teardown := wsServer(t, hub, "bob", "")
	defer teardown()

	waitFor(t, func() bool { return hub.IsConnected("bob") }, 2*time.Second)

	payload := WSMessage{Type: "ride.bid", SessionID: "S1", Payload: json.RawMessage(`{"price":99}`)}
	body, _ := json.Marshal(payload)
	if err := conn.WriteMessage(websocket.TextMessage, body); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return got }, 2*time.Second)
	mu.Lock()
	defer mu.Unlock()
	if seen.Type != "ride.bid" || seen.SessionID != "S1" {
		t.Errorf("dispatch saw type=%q session=%q", seen.Type, seen.SessionID)
	}
}

func TestHub_RejectsUnauthorized(t *testing.T) {
	hub := NewHub(RealClock(), &AuthMiddleware{
		Secret:         []byte("real-secret"),
		AllowDevBypass: false,
	})
	srv := httptest.NewServer(http.HandlerFunc(hub.HandleWS))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	u.Scheme = "ws"
	q := u.Query()
	q.Set("pseudonym", "mallory")
	q.Set("auth", "wrong-token")
	u.RawQuery = q.Encode()

	_, resp, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err == nil {
		t.Fatalf("expected dial to fail")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %v", resp)
	}
	if !strings.Contains(err.Error(), "bad handshake") && !strings.Contains(err.Error(), "401") {
		t.Errorf("unexpected dial error: %v", err)
	}
}

func TestHub_SendToDisconnectedReturnsNil(t *testing.T) {
	hub := NewHub(RealClock(), &AuthMiddleware{AllowDevBypass: true})
	err := hub.SendTo("ghost", WSMessage{Type: "x"})
	if err != nil {
		t.Errorf("SendTo to disconnected pseudonym returned err=%v, want nil", err)
	}
}

func TestHub_BroadcastToSessionRoutesByPseudonym(t *testing.T) {
	hub := NewHub(RealClock(), &AuthMiddleware{AllowDevBypass: true})
	aConn, aDown := wsServer(t, hub, "a", "")
	defer aDown()
	bConn, bDown := wsServer(t, hub, "b", "")
	defer bDown()
	cConn, cDown := wsServer(t, hub, "c", "")
	defer cDown()

	waitFor(t, func() bool { return hub.ConnectedCount() == 3 }, 2*time.Second)

	hub.BroadcastToSession("S2", []string{"a", "b"}, WSMessage{Type: "session.start"})

	// a and b should each receive one frame; c should time out.
	for _, conn := range []*websocket.Conn{aConn, bConn} {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _, err := conn.ReadMessage()
		if err != nil {
			t.Errorf("expected message, got err=%v", err)
		}
	}
	cConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _, err := cConn.ReadMessage()
	if err == nil {
		t.Errorf("c received a message it should not have")
	}
}
