package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHostAllowGuard pins the opt-in DNS-rebinding guard: an EMPTY allow-list is a
// no-op (any Host served), a non-empty list serves only listed hosts (port-stripped,
// case-insensitive) and 403s the rest — for ALL methods, since a rebind could be
// used to GET secrets, not just to POST.
func TestHostAllowGuard(t *testing.T) {
	mkHandler := func(allowed []string, reached *bool) http.Handler {
		return hostAllowGuard(func() []string { return allowed }, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*reached = true
			w.WriteHeader(http.StatusOK)
		}))
	}

	// Empty list -> guard disabled -> any Host (even a hostile one) is served.
	t.Run("empty list allows all", func(t *testing.T) {
		var reached bool
		h := mkHandler(nil, &reached)
		req := httptest.NewRequest(http.MethodGet, "http://attacker.example.com/", nil)
		req.Host = "attacker.example.com"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if !reached || rec.Code != http.StatusOK {
			t.Errorf("empty allow-list must serve any host; reached=%v code=%d", reached, rec.Code)
		}
	})

	allowed := []string{"192.168.2.1", "10.0.0.30", "Router.LAN", "::1"}
	cases := []struct {
		name, method, host string
		wantOK             bool
	}{
		{"listed IP with port", "GET", "192.168.2.1:8088", true},
		{"listed mesh IP", "POST", "10.0.0.30:8088", true},
		{"listed hostname case-insensitive", "GET", "router.lan:8088", true},
		{"listed IPv6 bracketed", "GET", "[::1]:8088", true},
		{"unlisted host (rebinding attacker) blocked", "GET", "attacker.example.com:8088", false},
		{"unlisted host blocked on POST too", "POST", "evil.test", false},
		{"unlisted bare IP blocked", "GET", "203.0.113.5:8088", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var reached bool
			h := mkHandler(allowed, &reached)
			req := httptest.NewRequest(c.method, "http://"+c.host+"/api/config", nil)
			req.Host = c.host
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if c.wantOK && (!reached || rec.Code != http.StatusOK) {
				t.Errorf("host %q must be allowed; reached=%v code=%d", c.host, reached, rec.Code)
			}
			if !c.wantOK && (reached || rec.Code != http.StatusForbidden) {
				t.Errorf("host %q must be 403'd; reached=%v code=%d", c.host, reached, rec.Code)
			}
		})
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"192.168.2.1:8088": "192.168.2.1",
		"192.168.2.1":      "192.168.2.1",
		"Router.LAN:8088":  "router.lan",
		"ROUTER.LAN":       "router.lan",
		"[::1]:8088":       "::1",
		"[fe80::1]":        "fe80::1",
		"  10.0.0.30  ":    "10.0.0.30",
	}
	for in, want := range cases {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}
