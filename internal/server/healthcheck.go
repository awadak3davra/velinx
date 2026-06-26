package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// healthRow is one server-side diagnostic result, shaped for the Diagnostics
// "Run all checks" battery in the UI (status drives the pill colour).
type healthRow struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Status  string `json:"status"` // pass | warn | fail
	Summary string `json:"summary"`
	Detail  string `json:"detail,omitempty"`
	Fix     string `json:"fix,omitempty"`
}

// handleHealthCheck runs the diagnostic probes the BROWSER cannot do itself — it is
// same-origin-locked and can read neither /proc nor a raw cross-origin Date/IPv6
// response. Two high-leverage VPN checks live here: router clock skew (from a remote
// HTTP Date header, since NTP is often blocked) and an IPv6-leak test (the tunnels
// are IPv4-only, so working global IPv6 silently bypasses the VPN). Each sub-check
// degrades to a warn result rather than failing the whole call. The UI battery folds
// these rows in next to its client-composed checks (core/tunnels/internet/exit/log).
func (s *Server) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	// The checks are independent + each fans out to remote probes, so run them
	// concurrently — sequential would risk blowing the request timeout.
	checks := []func(context.Context) healthRow{clockSkewCheck, ipv6LeakCheck, dnsHealthCheck, flowOffloadCheck}
	rows := make([]healthRow, len(checks))
	var wg sync.WaitGroup
	for i, fn := range checks {
		wg.Add(1)
		go func(i int, fn func(context.Context) healthRow) { defer wg.Done(); rows[i] = fn(ctx) }(i, fn)
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, map[string]any{"checks": rows})
}

// clockSkewCheck compares the router clock to a remote server's Date header.
func clockSkewCheck(ctx context.Context) healthRow {
	row := healthRow{ID: "time", Label: "Router clock is correct"}
	cl := &http.Client{Timeout: 6 * time.Second}
	defer cl.CloseIdleConnections() // release pooled TCP conns (matches dohProbe) — no idle-conn buildup on the 256 MB router
	var dateHdr string
	for _, u := range []string{"https://www.cloudflare.com/", "https://www.google.com/generate_204"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
		if err != nil {
			continue
		}
		resp, err := cl.Do(req)
		if err != nil {
			continue
		}
		dateHdr = resp.Header.Get("Date")
		resp.Body.Close()
		if dateHdr != "" {
			break
		}
	}
	if dateHdr == "" {
		row.Status, row.Summary = "warn", "couldn't reach a time source"
		return row
	}
	t, err := http.ParseTime(dateHdr)
	if err != nil {
		row.Status, row.Summary = "warn", "unreadable time source"
		return row
	}
	row.Status, row.Summary, row.Fix = skewVerdict(time.Since(t))
	row.Detail = "remote time " + dateHdr + "; local skew " + time.Since(t).Round(time.Second).String()
	return row
}

// skewVerdict maps an absolute clock skew to a status + plain-language fix.
func skewVerdict(skew time.Duration) (status, summary, fix string) {
	if skew < 0 {
		skew = -skew
	}
	s := skew.Round(time.Second).String()
	switch {
	case skew < 30*time.Second:
		return "pass", "clock is correct", ""
	case skew < 5*time.Minute:
		return "warn", "clock is off by " + s, "The router clock drifts. Enable NTP / fix the time — large skew breaks secure (TLS/Reality) connections."
	default:
		return "fail", "clock is wrong by " + s, "The router's clock is far off, which breaks secure (TLS/Reality) tunnels and makes working exits look broken. Fix the time / enable NTP."
	}
}

// ipv6LeakCheck flags the dual-stack bypass: the tunnels are IPv4-only, so a working
// global IPv6 path lets v6 traffic skip the VPN and expose the real address.
func ipv6LeakCheck(ctx context.Context) healthRow {
	row := healthRow{ID: "ipv6", Label: "No IPv6 leak"}
	b, err := os.ReadFile("/proc/net/if_inet6")
	if err != nil {
		row.Status, row.Summary = "warn", "can't read IPv6 state (non-Linux?)"
		return row
	}
	if !ipv6HasGlobal(string(b)) {
		row.Status, row.Summary = "pass", "no global IPv6 on the router"
		return row
	}
	// Global v6 present — does raw v6 actually reach the internet (bypassing v4 tunnels)?
	cl := &http.Client{Timeout: 6 * time.Second}
	defer cl.CloseIdleConnections() // release pooled TCP conns (matches dohProbe) — no idle-conn buildup on the 256 MB router
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api6.ipify.org", nil)
	resp, err := cl.Do(req)
	if err != nil {
		row.Status, row.Summary = "pass", "IPv6 present but firewalled (OK)"
		row.Detail = "a direct IPv6 request did not reach the internet: " + err.Error()
		return row
	}
	defer resp.Body.Close()
	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	row.Status, row.Summary = "fail", "IPv6 reaches the internet directly"
	row.Detail = "raw IPv6 egress works (real v6 address " + strings.TrimSpace(string(buf[:n])) + ") — the v4-only tunnels don't cover it"
	row.Fix = "Your device can use IPv6 to bypass the VPN and expose your real address. Disable IPv6 on the router, or block IPv6 forwarding."
	return row
}

// ipv6HasGlobal reports whether /proc/net/if_inet6 lists a global (internet-scope)
// IPv6 address. Each line is "addr ifindex prefixlen scope flags devname"; scope
// "00" is global. Loopback (::1), link-local (fe80::/10) and ULA (fc00::/7) are
// skipped — only a genuinely routable address counts (the live GET is the real test).
func ipv6HasGlobal(ifInet6 string) bool {
	for _, ln := range strings.Split(ifInet6, "\n") {
		f := strings.Fields(ln)
		if len(f) < 4 || f[3] != "00" {
			continue
		}
		addr := strings.ToLower(f[0])
		if addr == "00000000000000000000000000000001" || strings.HasPrefix(addr, "fe80") ||
			strings.HasPrefix(addr, "fc") || strings.HasPrefix(addr, "fd") {
			continue
		}
		return true
	}
	return false
}

// flowOffloadCheck reports whether the kernel flow-offload fast path is enabled. On capable
// hardware (e.g. the MediaTek PPE on MT7981) hardware offload can multiply routed throughput
// and cut CPU; with it off, forwarding is bounded by the CPU. This is advisory only and reads
// the fw4 (uci) firewall config — it never changes it. IMPORTANT: WakeRoute routes tunnel
// carve-outs by firewall mark, so a flowtable must EXCLUDE marked connections; otherwise a
// carve-out could be offloaded straight past the VPN (a leak). The fix text says so, to avoid
// a naive flow_offloading_hw flip. Degrades to a warn off-OpenWrt.
func flowOffloadCheck(_ context.Context) healthRow {
	row := healthRow{ID: "offload", Label: "Flow offload (fast path)"}
	b, err := os.ReadFile("/etc/config/firewall")
	if err != nil {
		row.Status, row.Summary = "warn", "can't read the firewall config (non-OpenWrt?)"
		return row
	}
	sw, hw := parseOffloadConfig(string(b))
	switch {
	case sw && hw:
		row.Status, row.Summary = "pass", "hardware flow offload enabled"
		row.Detail = "general routed (non-tunnel) traffic uses the hardware fast path"
	case sw:
		row.Status, row.Summary = "pass", "software flow offload enabled"
		row.Detail = "routed traffic uses the software fast path; hardware offload may give more throughput on capable NICs"
	case hw && !sw:
		row.Status, row.Summary = "warn", "hardware offload set but software offload is off"
		row.Detail = "flow_offloading_hw has no effect unless flow_offloading is also enabled"
		row.Fix = "Set firewall flow_offloading '1' as well so hardware offload can take effect."
	default:
		row.Status, row.Summary = "warn", "flow offload is off"
		row.Detail = "general routed throughput is bounded by the CPU forwarding rate; the hardware fast path is unused"
		row.Fix = "Enabling flow offload (hardware where supported) can greatly increase routed throughput and lower CPU. Because WakeRoute routes tunnel carve-outs by firewall mark, the flowtable must EXCLUDE marked connections so a carve-out isn't offloaded past the VPN — don't just flip flow_offloading_hw without that exclusion."
	}
	return row
}

// parseOffloadConfig reads the fw4 (uci) firewall text and reports whether software and
// hardware flow offloading are enabled in the defaults section. Pure (no I/O) for testing;
// accepts the common uci truthy spellings ('1'/true/on/yes, quoted or not).
func parseOffloadConfig(cfg string) (sw, hw bool) {
	for _, ln := range strings.Split(cfg, "\n") {
		f := strings.Fields(ln)
		if len(f) >= 3 && f[0] == "option" {
			on := false
			switch strings.Trim(f[2], "'\"") {
			case "1", "true", "on", "yes":
				on = true
			}
			switch f[1] {
			case "flow_offloading":
				sw = on
			case "flow_offloading_hw":
				hw = on
			}
		}
	}
	return sw, hw
}

// dnsHealthCheck probes whether encrypted DNS (DoH) is reachable from the router.
// It queries a few major DoH resolvers with a dns-json request and verifies the
// DNS rcode is NOERROR (Status==0 with an answer) — not merely HTTP 200. If at
// least one resolver answers, the router can resolve names over DoH rather than
// leaking plaintext queries to the ISP; if none answer it degrades to warn (it
// can't prove a leak, only that the encrypted path is unreachable).
func dnsHealthCheck(ctx context.Context) healthRow {
	row := healthRow{ID: "dns", Label: "DNS is private (DoH)"}
	// All three must expose a JSON DoH API (?name=&type= + Accept: application/dns-json):
	// Cloudflare + AdGuard answer at /dns-query and /resolve, Google at /resolve. NB:
	// Quad9 is deliberately NOT here — its /dns-query speaks only RFC8484 wireformat
	// (a ?name= query returns HTTP 400) and it has no JSON endpoint, so it can't be
	// probed this way without a wireformat encoder.
	providers := []struct{ name, url string }{
		{"Cloudflare", "https://cloudflare-dns.com/dns-query?name=cloudflare.com&type=A"},
		{"Google", "https://dns.google/resolve?name=google.com&type=A"},
		{"AdGuard", "https://dns.adguard-dns.com/resolve?name=adguard.com&type=A"},
	}
	type res struct {
		name string
		ok   bool
		ms   int64
	}
	out := make([]res, len(providers))
	var wg sync.WaitGroup
	for i, p := range providers {
		wg.Add(1)
		go func(i int, name, u string) {
			defer wg.Done()
			ok, ms := dohProbe(ctx, u)
			out[i] = res{name, ok, ms}
		}(i, p.name, p.url)
	}
	wg.Wait()

	healthy := 0
	var parts []string
	for _, r := range out {
		if r.ok {
			healthy++
			parts = append(parts, fmt.Sprintf("%s ✓ %d ms", r.name, r.ms))
		} else {
			parts = append(parts, r.name+" ✗")
		}
	}
	row.Detail = strings.Join(parts, " · ")
	if healthy == 0 {
		row.Status = "warn"
		row.Summary = "no DoH resolver reachable"
		row.Fix = "Encrypted DNS (DoH) couldn't be reached from the router, so DNS may be falling back to your ISP's plaintext servers. Check https-dns-proxy / your DNS settings — or it may just be a transient network blip."
		return row
	}
	row.Status = "pass"
	row.Summary = fmt.Sprintf("encrypted DNS (DoH) working · %d/%d resolvers", healthy, len(providers))
	return row
}

// dohProbe sends one dns-json query and returns whether it produced a valid DNS
// answer plus the round-trip in ms. Errors (network, HTTP, bad rcode) -> false.
func dohProbe(ctx context.Context, u string) (bool, int64) {
	cl := &http.Client{Timeout: 6 * time.Second}
	defer cl.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, 0
	}
	req.Header.Set("Accept", "application/dns-json")
	start := time.Now()
	resp, err := cl.Do(req)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()
	ms := time.Since(start).Milliseconds()
	if resp.StatusCode != http.StatusOK {
		return false, ms
	}
	body := make([]byte, 0, 2048)
	buf := make([]byte, 2048)
	for len(body) < 8192 {
		n, e := resp.Body.Read(buf)
		body = append(body, buf[:n]...)
		if e != nil {
			break
		}
	}
	return dnsJSONOK(body), ms
}

// dnsJSONOK reports whether a dns-json body is a successful resolution: rcode 0
// (NOERROR) with at least one answer record.
func dnsJSONOK(body []byte) bool {
	var v struct {
		Status int               `json:"Status"`
		Answer []json.RawMessage `json:"Answer"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return false
	}
	return v.Status == 0 && len(v.Answer) > 0
}
