package server

import (
	"context"
	"net/http"
	"time"
)

// handleHealthEndpoints returns the accumulated per-target health snapshot
// (state, latency, success rate, avg latency, reconnections, uptime).
func (s *Server) handleHealthEndpoints(w http.ResponseWriter, r *http.Request) {
	if s.monitor == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, s.monitor.Snapshot())
}

// handleHealthTest probes a single target immediately ("Test now").
func (s *Server) handleHealthTest(w http.ResponseWriter, r *http.Request) {
	if s.monitor == nil {
		writeErr(w, http.StatusServiceUnavailable, "monitor not running")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, s.monitor.ProbeOne(ctx, r.PathValue("id")))
}
