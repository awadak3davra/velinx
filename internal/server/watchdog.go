package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// handleWatchdog reports the crash-restart supervisor state (restarts, last
// restart, backoff) for the Dashboard / Diagnostics.
func (s *Server) handleWatchdog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.watchdog.Stats())
}

// makeWebhookNotifier returns an alert hook that POSTs {"text":"…"} to url on
// each crash-restart (e.g. a WGBot webhook). Fire-and-forget with a short timeout.
func makeWebhookNotifier(url string) func(string) {
	return func(msg string) {
		body, _ := json.Marshal(map[string]string{"text": msg})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}
}
