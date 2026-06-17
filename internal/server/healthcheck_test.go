package server

import (
	"testing"
	"time"
)

func TestSkewVerdict(t *testing.T) {
	cases := []struct {
		skew time.Duration
		want string
	}{
		{5 * time.Second, "pass"},
		{-10 * time.Second, "pass"}, // absolute value
		{45 * time.Second, "warn"},
		{4 * time.Minute, "warn"},
		{10 * time.Minute, "fail"},
		{-30 * time.Minute, "fail"},
	}
	for _, c := range cases {
		got, summary, fix := skewVerdict(c.skew)
		if got != c.want {
			t.Errorf("skewVerdict(%v) = %q, want %q", c.skew, got, c.want)
		}
		if summary == "" {
			t.Errorf("skewVerdict(%v) empty summary", c.skew)
		}
		if (got == "pass") != (fix == "") {
			t.Errorf("skewVerdict(%v): pass<->no-fix invariant broken (status=%q fix=%q)", c.skew, got, fix)
		}
	}
}

func TestIPv6HasGlobal(t *testing.T) {
	// scope "00" = global; field order: addr ifindex prefixlen scope flags devname
	global := "2a0212340000000000000000dead0001 03 40 00 00 eth0\n" +
		"fe80000000000000abcdabcdabcdabcd 02 40 20 80 eth0\n"
	if !ipv6HasGlobal(global) {
		t.Error("expected a global IPv6 to be detected")
	}
	noGlobal := "00000000000000000000000000000001 01 80 10 80 lo\n" + // ::1 loopback
		"fe80000000000000020000fffe000001 02 40 20 80 eth0\n" + // link-local
		"fd001234000000000000000000000001 03 40 00 00 br-lan\n" // ULA (fd, skipped)
	if ipv6HasGlobal(noGlobal) {
		t.Error("loopback + link-local + ULA must NOT count as a global IPv6 leak")
	}
	if ipv6HasGlobal("") {
		t.Error("empty if_inet6 must be no-leak")
	}
}

func TestDNSJSONOK(t *testing.T) {
	if !dnsJSONOK([]byte(`{"Status":0,"Answer":[{"name":"cloudflare.com","type":1,"data":"104.16.132.229"}]}`)) {
		t.Error("NOERROR with an answer must be ok")
	}
	if dnsJSONOK([]byte(`{"Status":2,"Answer":[{"data":"x"}]}`)) {
		t.Error("SERVFAIL must not be ok")
	}
	if dnsJSONOK([]byte(`{"Status":0,"Answer":[]}`)) {
		t.Error("NOERROR with no answer must not be ok")
	}
	if dnsJSONOK([]byte(`{"Status":0}`)) {
		t.Error("missing Answer must not be ok")
	}
	if dnsJSONOK([]byte(`<html>blocked</html>`)) {
		t.Error("non-JSON (e.g. a captive/blocking page) must not be ok")
	}
	// AdGuard's /resolve omits the top-level Status field on success; an absent Status
	// is the Go zero value (0 = NOERROR), so a body with answers must still count as ok.
	if !dnsJSONOK([]byte(`{"Question":[{"name":"adguard.com."}],"Answer":[{"name":"adguard.com.","data":"104.18.188.9","type":1}],"Extra":null}`)) {
		t.Error("AdGuard-shape response (no Status, has Answer) must be ok")
	}
}
