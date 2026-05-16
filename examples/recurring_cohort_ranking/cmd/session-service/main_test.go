package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Fheyalabs/ares-core/examples/recurring_cohort_ranking"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/transport"
)

func freePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	_, p, _ := net.SplitHostPort(l.Addr().String())
	return p
}

func startTestService(t *testing.T, mode string) (string, *phase.SessionRunner, transport.SessionTrigger, func()) {
	t.Helper()
	runner, trigger, inviteType, err := buildRunner(mode, 30, 16384)
	if err != nil {
		t.Fatalf("buildRunner(%s): %v", mode, err)
	}
	port := freePort(t)
	svc, err := transport.NewService(transport.Config{
		Addr:           ":" + port,
		ServiceName:    "cohort-" + mode + "-test",
		AllowDevBypass: true,
		Runner:         runner,
		Trigger:        trigger,
		InviteType:     inviteType,
	})
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	if w, ok := trigger.(hubWiring); ok {
		w.setHub(svc.Hub())
	}
	ctx, cancel := context.WithCancel(context.Background())
	go svc.Run(ctx)
	base := "http://127.0.0.1:" + port
	waitForHTTP(t, base+"/admin/health", 2*time.Second)
	return base, runner, trigger, cancel
}

func TestCohortService_FormationStartsAtForming(t *testing.T) {
	base, runner, _, stop := startTestService(t, "formation")
	defer stop()

	body, _ := json.Marshal(map[string]any{
		"session_id":   "cohort-A-init",
		"participants": []string{"m1", "m2", "m3", "m4"},
	})
	resp, _ := http.Post(base+"/admin/sessions", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	s, _ := runner.CurrentState("cohort-A-init")
	if s != recurringcohortranking.StateCohortForming {
		t.Errorf("state = %q, want COHORT_FORMING", s)
	}
}

func TestCohortService_WeeklyRequiresKeyBundle(t *testing.T) {
	base, _, _, stop := startTestService(t, "weekly")
	defer stop()

	// Missing key-bundle attrs — should be rejected at trigger time.
	body, _ := json.Marshal(map[string]any{
		"session_id":   "w-missing",
		"participants": []string{"m1", "m2"},
	})
	resp, _ := http.Post(base+"/admin/sessions", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
}

func TestCohortService_WeeklyAcceptsSeededBundleAndAdvances(t *testing.T) {
	base, runner, _, stop := startTestService(t, "weekly")
	defer stop()

	body, _ := json.Marshal(map[string]any{
		"session_id":   "w-good",
		"participants": []string{"m1", "m2"},
		"attrs": map[string]any{
			recurringcohortranking.CtxCollectivePK: "fake-pk-bytes",
			recurringcohortranking.CtxSecretShares: map[string]any{
				"m1": "share-1", "m2": "share-2",
			},
			recurringcohortranking.CtxEvalKeys: "fake-eval-keys",
		},
	})
	resp, err := http.Post(base+"/admin/sessions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := readAll(resp)
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	s, _ := runner.CurrentState("w-good")
	// After AdvanceToState past the seeder, session sits at
	// RANKING_INVITING (PhaseRankingInvitation's CheckComplete is true,
	// but it auto-advances only after a message — so we expect to stop
	// at the entry of PhaseRankingInvitation).
	if s != recurringcohortranking.StateRankingInviting {
		t.Errorf("state = %q, want RANKING_INVITING", s)
	}
}

func TestBuildRunner_RejectsUnknownMode(t *testing.T) {
	_, _, _, err := buildRunner("bogus", 30, 16384)
	if err == nil {
		t.Errorf("expected unknown mode to fail")
	}
}

func readAll(resp *http.Response) (string, error) {
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	return string(buf), nil
}

func waitForHTTP(t *testing.T, u string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(u)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("HTTP %s never came up", u)
}
