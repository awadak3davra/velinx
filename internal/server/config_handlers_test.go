package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"wakeroute/internal/config"
)

// TestPutConfig_RoundTripsGateway guards the cutover toggle: PUT /api/config must
// persist the gateway flag (a regression once dropped it silently), and it must
// flow through genOptions into TunEnabled.
func TestPutConfig_RoundTripsGateway(t *testing.T) {
	s := opshandlers_server(t)
	// Give the live config a file path so Save() works (Default() has none).
	path := filepath.Join(t.TempDir(), "config.json")
	data, _ := json.Marshal(s.cfg)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	s.cfg = loaded

	cfg := s.config()
	cfg.Gateway = true
	body, _ := json.Marshal(cfg)
	w := opshandlers_post(s.handlePutConfig, "/api/config", string(body))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT /api/config = %d: %s", w.Code, w.Body.String())
	}
	if !s.config().Gateway {
		t.Fatal("handlePutConfig dropped the gateway flag")
	}
	gp := s.store.Profile()
	if !s.genOptions(&gp).TunEnabled {
		t.Fatal("gateway=true did not set genOptions().TunEnabled")
	}
}
