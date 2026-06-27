package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSubRotateInvalidatesOldURL guards the token-rotation feature: rotating issues a new
// token, the old /api/sub/{old} URL stops working (403), and the new one serves.
func TestSubRotateInvalidatesOldURL(t *testing.T) {
	srv, h := backup_newServer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	old := srv.subToken() // first-use generation
	if old == "" {
		t.Fatal("subToken() returned empty")
	}

	resp, err := ts.Client().Post(ts.URL+"/api/subscription/rotate", "", nil)
	if err != nil {
		t.Fatalf("POST rotate: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotate: got %d, want 200 (%s)", resp.StatusCode, body)
	}
	var out struct {
		Token string `json:"token"`
		Path  string `json:"path"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("bad rotate JSON: %v", err)
	}
	if out.Token == "" || out.Token == old {
		t.Fatalf("rotate did not change the token: old=%q new=%q", old, out.Token)
	}
	if out.Path != "/api/sub/"+out.Token {
		t.Errorf("path=%q want /api/sub/%s", out.Path, out.Token)
	}

	// The OLD subscription URL must now be rejected.
	r1, _ := ts.Client().Get(ts.URL + "/api/sub/" + old)
	if r1 != nil {
		r1.Body.Close()
		if r1.StatusCode != http.StatusForbidden {
			t.Errorf("old token still works: status %d, want 403", r1.StatusCode)
		}
	}
	// The NEW subscription URL serves.
	r2, _ := ts.Client().Get(ts.URL + "/api/sub/" + out.Token)
	if r2 != nil {
		r2.Body.Close()
		if r2.StatusCode != http.StatusOK {
			t.Errorf("new token failed: status %d, want 200", r2.StatusCode)
		}
	}
}
