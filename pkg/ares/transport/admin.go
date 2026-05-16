package transport

import (
	"encoding/json"
	"net/http"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

// AdminHandlers exposes the HTTP admin surface:
//
//	GET  /admin/health             — liveness probe
//	GET  /admin/stats              — connected count, sessions started
//	POST /admin/sessions           — start a session (SessionTrigger.Start)
//	GET  /admin/sessions/{id}      — current state of a session
//	PUT  /v2/artifacts/{key}       — upload an artifact
//	GET  /v2/artifacts/{key}       — download an artifact
//
// All admin endpoints are auth-bypassed in dev mode; production
// deployments should sit them behind a reverse proxy that enforces
// access control.
type AdminHandlers struct {
	ServiceName string
	Hub         *Hub
	Runner      *phase.SessionRunner
	Trigger     SessionTrigger
	Artifacts   *ArtifactStore
}

// RegisterRoutes mounts the admin endpoints on mux.
func (a *AdminHandlers) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/health", a.handleHealth)
	mux.HandleFunc("GET /admin/stats", a.handleStats)
	mux.HandleFunc("POST /admin/sessions", a.handleSessionStart)
	mux.HandleFunc("GET /admin/sessions/{id}", a.handleSessionGet)
	mux.HandleFunc("PUT /v2/artifacts/{key}", a.handleArtifactPut)
	mux.HandleFunc("GET /v2/artifacts/{key}", a.handleArtifactGet)
}

func (a *AdminHandlers) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": a.ServiceName,
	})
}

type statsResponse struct {
	Service         string `json:"service"`
	ConnectedClients int   `json:"connected_clients"`
}

func (a *AdminHandlers) handleStats(w http.ResponseWriter, r *http.Request) {
	connected := 0
	if a.Hub != nil {
		connected = a.Hub.ConnectedCount()
	}
	writeJSON(w, http.StatusOK, statsResponse{
		Service:          a.ServiceName,
		ConnectedClients: connected,
	})
}

type sessionStartRequest struct {
	SessionID    string         `json:"session_id"`
	Participants []string       `json:"participants"`
	Attrs        map[string]any `json:"attrs,omitempty"`
}

type sessionStartResponse struct {
	SessionID string `json:"session_id"`
	State     string `json:"state"`
}

func (a *AdminHandlers) handleSessionStart(w http.ResponseWriter, r *http.Request) {
	if a.Trigger == nil {
		http.Error(w, "no SessionTrigger configured", http.StatusServiceUnavailable)
		return
	}
	var req sessionStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.SessionID == "" {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}
	if err := a.Trigger.Start(req.SessionID, req.Participants, req.Attrs); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	state, _ := a.Runner.CurrentState(req.SessionID)
	writeJSON(w, http.StatusCreated, sessionStartResponse{
		SessionID: req.SessionID,
		State:     string(state),
	})
}

func (a *AdminHandlers) handleSessionGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	state, ok := a.Runner.CurrentState(id)
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, sessionStartResponse{
		SessionID: id,
		State:     string(state),
	})
}

func (a *AdminHandlers) handleArtifactPut(w http.ResponseWriter, r *http.Request) {
	if a.Artifacts == nil {
		http.Error(w, "no artifact store configured", http.StatusServiceUnavailable)
		return
	}
	key := r.PathValue("key")
	if key == "" {
		http.Error(w, "missing key", http.StatusBadRequest)
		return
	}
	buf := make([]byte, 0, r.ContentLength)
	tmp := make([]byte, 32*1024)
	for {
		n, err := r.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	a.Artifacts.Put(key, buf)
	w.WriteHeader(http.StatusNoContent)
}

func (a *AdminHandlers) handleArtifactGet(w http.ResponseWriter, r *http.Request) {
	if a.Artifacts == nil {
		http.Error(w, "no artifact store configured", http.StatusServiceUnavailable)
		return
	}
	key := r.PathValue("key")
	data, ok := a.Artifacts.Get(key)
	if !ok {
		http.Error(w, "artifact not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
