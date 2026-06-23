package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestLimitBody verifies the request-body cap: a read within maxRequestBody
// succeeds and delivers the bytes intact, while a body larger than the cap makes
// the handler's read fail (so a JSON decoder returns its usual 400 instead of
// buffering unbounded memory and risking an OOM on the RAM-constrained router).
func TestLimitBody(t *testing.T) {
	// The wrapped handler drains the body and records whether the read errored
	// and how many bytes it got.
	var gotErr bool
	var gotN int
	h := limitBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		gotErr = err != nil
		gotN = len(b)
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		name     string
		size     int
		wantErr  bool
		wantRead int // bytes the handler should have read before any error
	}{
		{"well under cap", 1024, false, 1024},
		{"just under cap", maxRequestBody - 1, false, maxRequestBody - 1},
		{"at cap", maxRequestBody, false, maxRequestBody},
		{"over cap errors", maxRequestBody + 1024, true, maxRequestBody},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotErr, gotN = false, 0
			body := strings.NewReader(strings.Repeat("a", c.size))
			req := httptest.NewRequest(http.MethodPost, "http://192.168.2.1:8088/api/import", body)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if gotErr != c.wantErr {
				t.Errorf("read error = %v, want %v (size %d)", gotErr, c.wantErr, c.size)
			}
			// On an over-cap body the reader yields exactly maxRequestBody bytes
			// before failing; within the cap it yields the whole body.
			if gotN != c.wantRead {
				t.Errorf("bytes read = %d, want %d (size %d)", gotN, c.wantRead, c.size)
			}
		})
	}
}

// TestLimitBodyNilBodySafe ensures the middleware doesn't panic when there is no
// body (e.g. a bodyless POST like /api/service/restart).
func TestLimitBodyNilBodySafe(t *testing.T) {
	reached := false
	h := limitBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "http://192.168.2.1:8088/api/service/restart", nil)
	req.Body = nil // explicit: no body at all
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !reached {
		t.Fatal("handler not reached with a nil body")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}
