package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"wakeroute/internal/netdiag"
)

// handleProbeTLS probes a Reality dest/SNI from the router's vantage: is the
// camouflage site TCP-reachable, does it speak TLS, and does it negotiate TLS 1.3?
// (Reality borrows a real public TLS 1.3 site's SNI as cover; a bad dest silently
// breaks the connection — this surfaces it before the user saves.) Additive,
// read-only: it dials out but changes nothing.
//
//	POST /api/probe/tls   body {"host":"example.com"}  → netdiag.ProbeTLSResult
func (s *Server) handleProbeTLS(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host string `json:"host"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	host := strings.TrimSpace(body.Host)
	if host == "" {
		writeErr(w, http.StatusBadRequest, "enter a host or SNI to check")
		return
	}
	// Format guard: a Reality SNI is a bare hostname/IP[:port]. Strip an optional port
	// before the host-character check (ValidTarget rejects host:port forms), then
	// require the bare host to be a safe target — blocks injection / pathological input.
	bare := host
	// Strip a trailing :port ONLY when it is genuinely numeric. net.SplitHostPort is
	// lenient — it splits "http://x/y" into host="http", port="//x/y" — so without the
	// numeric-port check a URL-shaped input would pass ValidTarget on the bogus "http"
	// half and the original URL would reach the probe. A numeric port means it was a real
	// host:port; otherwise bare stays the full input and ValidTarget rejects the slashes.
	if h, p, err := net.SplitHostPort(host); err == nil {
		if _, perr := strconv.Atoi(p); perr == nil {
			bare = h
		}
	}
	if !netdiag.ValidTarget(bare) {
		writeErr(w, http.StatusBadRequest, "invalid host")
		return
	}

	// SSRF guard: a Reality dest is ALWAYS a public site, so refuse to dial an
	// internal address (loopback / private / link-local / metadata / unspecified /
	// multicast). Resolve the host and apply the SAME predicate as the subscription-
	// fetch dial guard (blockInternalDial) so the panel can't be turned into a probe
	// of the router's own services or the LAN. IP-literal hosts resolve locally.
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	if err := refuseInternalHost(ctx, bare); err != nil {
		writeErr(w, http.StatusForbidden, "internal hosts are not allowed")
		return
	}

	writeJSON(w, http.StatusOK, netdiag.ProbeTLS(ctx, host))
}

// refuseInternalHost resolves host and returns an error if ANY resolved IP is one
// blockInternalDial would refuse (loopback / private / link-local uni+multicast /
// unspecified). It reuses isInternalDialIP — the exact predicate blockInternalDial
// applies at dial time — so the probe guard and the subscription-fetch guard can
// never diverge. Refusing when ANY address is internal (not just the first) closes a
// split-horizon DNS gap where a name resolves to both a public and an internal IP.
func refuseInternalHost(ctx context.Context, host string) error {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		// Can't resolve → let ProbeTLS surface the real dial error rather than a 403.
		return nil
	}
	for _, ip := range ips {
		if isInternalDialIP(ip) {
			return errInternalHost
		}
	}
	return nil
}
