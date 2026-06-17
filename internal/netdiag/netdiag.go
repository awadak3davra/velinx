// Package netdiag runs on-box network diagnostics (ping, traceroute, DNS
// lookup) against a target. It shells out to the system tools (busybox on the
// router) and parses a small summary, plus returns raw output for display.
package netdiag

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// validTarget guards against shell-metacharacter injection (exec.Command does
// not use a shell, but we still reject anything that isn't a host/IP). The first
// character may NOT be a hyphen: a target like "-f" or "--help" passes the
// character-class test but is parsed by ping/traceroute as a FLAG, not a host
// (argument injection, CWE-88). Real hostnames/IPs never start with "-"
// (RFC 1123), so the leading-char class simply omits it.
var validTarget = regexp.MustCompile(`^[a-zA-Z0-9._:\[\]][a-zA-Z0-9._:\-\[\]]{0,252}$`)

// ValidTarget reports whether s is a safe ping/traceroute target.
func ValidTarget(s string) bool { return validTarget.MatchString(s) }

// DialPort reports whether a TCP connection to host:port succeeds within timeout
// (used to check an SSH port is open before provisioning).
func DialPort(host string, port int, timeout time.Duration) bool {
	if !ValidTarget(host) || port < 1 || port > 65535 {
		return false
	}
	d := net.Dialer{Timeout: timeout}
	c, err := d.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// PingResult summarizes a ping run.
type PingResult struct {
	Target  string  `json:"target"`
	Ok      bool    `json:"ok"`
	LossPct int     `json:"loss_pct"` // -1 unknown
	AvgMs   float64 `json:"avg_ms"`   // -1 unknown
	Output  string  `json:"output"`
}

// Lookup is a DNS resolution result.
type Lookup struct {
	Target string   `json:"target"`
	IPs    []string `json:"ips"`
	CNAME  string   `json:"cname,omitempty"`
	Err    string   `json:"err,omitempty"`
}

// Report bundles all three diagnostics for a target.
type Report struct {
	Target     string     `json:"target"`
	Ping       PingResult `json:"ping"`
	Traceroute string     `json:"traceroute"`
	Lookup     Lookup     `json:"lookup"`
}

var (
	reLossUnix = regexp.MustCompile(`(\d+)% packet loss`)
	reLossWin  = regexp.MustCompile(`\((\d+)% loss\)`)
	reAvgUnix  = regexp.MustCompile(`=\s*[\d.]+/([\d.]+)/`) // min/avg/max
	reAvgWin   = regexp.MustCompile(`Average\s*=\s*(\d+)ms`)
)

// Ping sends `count` echo requests to host.
func Ping(ctx context.Context, host string, count int) PingResult {
	res := PingResult{Target: host, LossPct: -1, AvgMs: -1}
	if !ValidTarget(host) {
		res.Output = "invalid target"
		return res
	}
	if count < 1 || count > 10 {
		count = 4
	}
	var args []string
	if runtime.GOOS == "windows" {
		args = []string{"-n", strconv.Itoa(count), "-w", "1500", host}
	} else {
		args = []string{"-c", strconv.Itoa(count), "-W", "2", host}
	}
	out, _ := exec.CommandContext(ctx, "ping", args...).CombinedOutput()
	res.Output = strings.TrimSpace(string(out))

	if m := reLossUnix.FindStringSubmatch(res.Output); m != nil {
		res.LossPct, _ = strconv.Atoi(m[1])
	} else if m := reLossWin.FindStringSubmatch(res.Output); m != nil {
		res.LossPct, _ = strconv.Atoi(m[1])
	}
	if m := reAvgUnix.FindStringSubmatch(res.Output); m != nil {
		res.AvgMs, _ = strconv.ParseFloat(m[1], 64)
	} else if m := reAvgWin.FindStringSubmatch(res.Output); m != nil {
		res.AvgMs, _ = strconv.ParseFloat(m[1], 64)
	}
	res.Ok = res.LossPct >= 0 && res.LossPct < 100
	return res
}

// Traceroute traces the path to host (raw output; tools differ by platform).
func Traceroute(ctx context.Context, host string, maxHops int) string {
	if !ValidTarget(host) {
		return "invalid target"
	}
	if maxHops < 1 || maxHops > 30 {
		maxHops = 20
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "tracert", "-d", "-h", strconv.Itoa(maxHops), "-w", "1000", host)
	} else {
		cmd = exec.CommandContext(ctx, "traceroute", "-n", "-m", strconv.Itoa(maxHops), "-w", "2", host)
	}
	out, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(out))
	if s == "" && err != nil {
		return "traceroute unavailable: " + err.Error()
	}
	return s
}

// DNSLookup resolves host to IPs (and a CNAME when present), Go-native.
func DNSLookup(ctx context.Context, host string) Lookup {
	l := Lookup{Target: host}
	if !ValidTarget(host) {
		l.Err = "invalid target"
		return l
	}
	var r net.Resolver
	ips, err := r.LookupHost(ctx, host)
	if err != nil {
		l.Err = err.Error()
		return l
	}
	l.IPs = ips
	if cname, err := r.LookupCNAME(ctx, host); err == nil && cname != "" && !strings.EqualFold(strings.TrimSuffix(cname, "."), host) {
		l.CNAME = strings.TrimSuffix(cname, ".")
	}
	return l
}

// --- reachability through a specific outbound (tunnel or WAN) ---
//
// ICMP ping/traceroute cannot traverse a proxy, so "test target X through tunnel
// Y" is necessarily an HTTP(S) GET that sing-box routes through outbound Y. We
// reuse the Clash API delay probe (GET /proxies/{tag}/delay) for that.

// Delayer issues an HTTP-GET latency probe through a named sing-box outbound (the
// Clash API /proxies/{name}/delay). *clash.Client satisfies it; keeping it an
// interface lets netdiag avoid a clash import and makes ReachVia unit-testable.
type Delayer interface {
	Delay(ctx context.Context, name, testURL string, timeoutMS int) (int, error)
}

// Reach is the result of testing a target's reachability THROUGH one outbound
// (a tunnel, or "direct" = WAN). LatencyMs is -1 when unreachable.
type Reach struct {
	Target    string `json:"target"`
	Egress    string `json:"egress"` // outbound tag tested ("direct" = WAN)
	Name      string `json:"name,omitempty"`
	URL       string `json:"url"` // the URL actually requested
	Reachable bool   `json:"reachable"`
	LatencyMs int    `json:"latency_ms"`
	Err       string `json:"err,omitempty"`
}

// HostOf reduces a target (bare host, host:port, or http(s) URL) to its hostname,
// for the shell ping/traceroute/DNS path which wants a host, not a URL.
func HostOf(target string) string {
	target = strings.TrimSpace(target)
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	if i := strings.IndexByte(target, '/'); i >= 0 {
		target = target[:i]
	}
	if h, _, err := net.SplitHostPort(target); err == nil {
		return h
	}
	return target
}

// TargetURL turns a target into the http(s) URL to GET for a reachability test:
// an explicit http(s) URL is kept as-is, a bare host/IP[:port][/path] becomes
// https://<target>. ok=false guards the same way ValidTarget guards the shell
// path: the host must be a safe host/IP, or the input a valid http(s) URL.
func TargetURL(target string) (string, bool) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", false
	}
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			return "", false
		}
		return u.String(), true
	}
	if !ValidTarget(HostOf(target)) {
		return "", false
	}
	return "https://" + target, true
}

// ReachVia tests whether target is reachable THROUGH the given outbound tag, via
// an HTTP(S) GET that sing-box routes through that outbound (the Clash delay
// probe). egress "" or "direct" tests the WAN path. It never shells out, so it is
// safe for arbitrary URLs. Any delay error (proxy down, or Clash unreachable)
// yields Reachable=false with the cause in Err.
func ReachVia(ctx context.Context, d Delayer, target, egress string, timeoutMS int) Reach {
	if egress == "" {
		egress = "direct"
	}
	r := Reach{Target: target, Egress: egress, LatencyMs: -1}
	u, ok := TargetURL(target)
	if !ok {
		r.Err = "invalid target — enter a host, IP or http(s) URL"
		return r
	}
	r.URL = u
	if timeoutMS < 1000 || timeoutMS > 20000 {
		timeoutMS = 8000
	}
	ms, err := d.Delay(ctx, egress, u, timeoutMS)
	if err != nil {
		r.Err = err.Error()
		return r
	}
	r.Reachable = true
	r.LatencyMs = ms
	return r
}

// Run executes all three diagnostics with sane per-tool timeouts.
func Run(ctx context.Context, host string) (Report, error) {
	if !ValidTarget(host) {
		return Report{}, fmt.Errorf("invalid target %q", host)
	}
	rep := Report{Target: host}

	pctx, pcancel := context.WithTimeout(ctx, 15*time.Second)
	rep.Ping = Ping(pctx, host, 4)
	pcancel()

	lctx, lcancel := context.WithTimeout(ctx, 8*time.Second)
	rep.Lookup = DNSLookup(lctx, host)
	lcancel()

	tctx, tcancel := context.WithTimeout(ctx, 45*time.Second)
	rep.Traceroute = Traceroute(tctx, host, 20)
	tcancel()

	return rep, nil
}
