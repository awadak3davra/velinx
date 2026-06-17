package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"wakeroute/internal/model"
	"wakeroute/internal/netdiag"
)

// handleNetDiag runs a single network test against a target. For WAN egress
// ("direct" or empty) it shells out to ping + traceroute + DNS (real ICMP
// diagnostics, no sing-box needed). For a tunnel egress it instead does an
// HTTP(S) reachability probe routed THROUGH that outbound via the Clash API —
// because ICMP cannot traverse a proxy.
func (s *Server) handleNetDiag(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target string `json:"target"`
		Egress string `json:"egress"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	body.Target = strings.TrimSpace(body.Target)
	body.Egress = strings.TrimSpace(body.Egress)

	// WAN / direct: full ping + traceroute + DNS, on the router's own route.
	if body.Egress == "" || body.Egress == model.OutboundDirect {
		host := netdiag.HostOf(body.Target)
		if !netdiag.ValidTarget(host) {
			writeErr(w, http.StatusBadRequest, "enter a valid host or IP address")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 70*time.Second)
		defer cancel()
		rep, err := netdiag.Run(ctx, host)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, rep)
		return
	}

	// Tunnel: HTTP(S) reachability through the chosen outbound (needs sing-box).
	if s.clash == nil {
		writeErr(w, http.StatusServiceUnavailable, "sing-box is not running — start it to test through a tunnel")
		return
	}
	if _, ok := netdiag.TargetURL(body.Target); !ok {
		writeErr(w, http.StatusBadRequest, "enter a valid host, IP or http(s) URL")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	reach := netdiag.ReachVia(ctx, s.clash, body.Target, body.Egress, 8000)
	reach.Name = s.egressName(body.Egress)
	writeJSON(w, http.StatusOK, reach)
}

// handleNetDiagStream streams a single diagnostic to the browser as Server-Sent
// Events — one output line per event — so a slow tool surfaces its progress live
// instead of blocking until done. ICMP can't traverse a proxy, but it CAN be bound
// to a kernel interface: when egress maps to an interface-backed endpoint (awg0 /
// awg1), ping/traceroute run through that link (-I/-i); else they use the WAN.
//
//	GET /api/netdiag/stream?tool=ping|traceroute|dns|all&target=<host>&egress=<tag>
func (s *Server) handleNetDiagStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	tool := r.URL.Query().Get("tool")
	host := netdiag.HostOf(strings.TrimSpace(r.URL.Query().Get("target")))
	if !netdiag.ValidTarget(host) {
		writeErr(w, http.StatusBadRequest, "enter a valid host or IP address")
		return
	}
	// An interface-backed egress (an external endpoint, e.g. awg0/awg1) binds the
	// probe to that interface, so ping/traceroute can run through a specific
	// tunnel/link instead of only the WAN. WAN / proxy egresses resolve to "".
	iface := s.egressIface(strings.TrimSpace(r.URL.Query().Get("egress")))
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// One SSE data frame per line; collapse stray CR/LF so a line stays one frame.
	emit := func(line string) {
		line = strings.ReplaceAll(strings.ReplaceAll(line, "\r", ""), "\n", " ")
		fmt.Fprintf(w, "data: %s\n\n", line)
		flusher.Flush()
	}
	ctx := r.Context()
	dns := func(c context.Context) {
		lk := netdiag.DNSLookup(c, host)
		if lk.Err != "" {
			emit("error: " + lk.Err)
			return
		}
		if lk.CNAME != "" {
			emit("CNAME " + lk.CNAME)
		}
		for _, ip := range lk.IPs {
			emit(ip)
		}
		if len(lk.IPs) == 0 {
			emit("(no records)")
		}
	}
	switch tool {
	case "ping":
		c, cancel := context.WithTimeout(ctx, 30*time.Second)
		netdiag.StreamPing(c, emit, host, iface, 6)
		cancel()
	case "traceroute":
		c, cancel := context.WithTimeout(ctx, 70*time.Second)
		netdiag.StreamTraceroute(c, emit, host, iface, 20)
		cancel()
	case "dns":
		c, cancel := context.WithTimeout(ctx, 8*time.Second)
		dns(c)
		cancel()
	case "all", "":
		c1, cancel1 := context.WithTimeout(ctx, 8*time.Second)
		emit("== DNS lookup ==")
		dns(c1)
		cancel1()
		emit("")
		c2, cancel2 := context.WithTimeout(ctx, 30*time.Second)
		emit("== Ping ==")
		netdiag.StreamPing(c2, emit, host, iface, 6)
		cancel2()
		emit("")
		c3, cancel3 := context.WithTimeout(ctx, 70*time.Second)
		emit("== Traceroute ==")
		netdiag.StreamTraceroute(c3, emit, host, iface, 20)
		cancel3()
	default:
		emit("unknown tool: " + tool)
	}
	fmt.Fprint(w, "event: done\ndata: end\n\n")
	flusher.Flush()
}

// egressName resolves an outbound tag to the same human label the egress dropdown
// shows: "WAN (direct)", an endpoint's name, or a "▣ "-prefixed group name.
func (s *Server) egressName(tag string) string {
	if tag == "" || tag == model.OutboundDirect {
		return "WAN (direct)"
	}
	prof := s.store.Profile()
	for _, e := range prof.Endpoints {
		if e.ID == tag {
			if e.Name != "" {
				return e.Name
			}
			return e.ID
		}
	}
	for _, g := range prof.Groups {
		if g.ID == tag {
			return "▣ " + g.Name
		}
	}
	return tag
}

// egressIface resolves an egress tag to the kernel interface a ping/traceroute can
// bind to: an external endpoint's bound interface (params.interface, e.g. awg0 /
// awg1), or "" for WAN ("direct"/"") and for proxy endpoints/groups — those have no
// interface (ICMP can't traverse a proxy), so the caller leaves the probe on the WAN.
func (s *Server) egressIface(tag string) string {
	if tag == "" || tag == model.OutboundDirect {
		return ""
	}
	prof := s.store.Profile()
	for _, e := range prof.Endpoints {
		if e.ID == tag {
			if iface, ok := e.Params["interface"].(string); ok && netdiag.ValidIface(iface) {
				return iface
			}
			return ""
		}
	}
	return ""
}

// handleNetDiagAll probes one target through every exit at once — WAN (direct)
// plus each enabled tunnel and group — and returns a comparison so the user can
// see which exit reaches a (possibly blocked) resource. All probes are HTTP(S)
// reachability via the Clash API, run in parallel.
func (s *Server) handleNetDiagAll(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	body.Target = strings.TrimSpace(body.Target)
	if _, ok := netdiag.TargetURL(body.Target); !ok {
		writeErr(w, http.StatusBadRequest, "enter a valid host, IP or http(s) URL")
		return
	}
	if s.clash == nil {
		writeErr(w, http.StatusServiceUnavailable, "sing-box is not running — start it to test through tunnels")
		return
	}

	type egress struct{ tag, name string }
	egrs := []egress{{model.OutboundDirect, "WAN (direct)"}}
	prof := s.store.Profile()
	for _, e := range prof.Endpoints {
		if e.Enabled {
			name := e.Name
			if name == "" {
				name = e.ID
			}
			egrs = append(egrs, egress{e.ID, name})
		}
	}
	for _, g := range prof.Groups {
		egrs = append(egrs, egress{g.ID, "▣ " + g.Name})
	}

	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	results := make([]netdiag.Reach, len(egrs))
	var wg sync.WaitGroup
	for i, e := range egrs {
		wg.Add(1)
		go func(i int, e egress) {
			defer wg.Done()
			rc := netdiag.ReachVia(ctx, s.clash, body.Target, e.tag, 7000)
			rc.Name = e.name
			results[i] = rc
		}(i, e)
	}
	wg.Wait()

	writeJSON(w, http.StatusOK, map[string]any{"target": body.Target, "results": results})
}
