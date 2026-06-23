package server

import "testing"

// TestParseDefaultRouteDev covers the `ip -o route show default` shapes the offload probe
// must handle, including the real on-device line (double space before src), a PPPoE WAN,
// a no-dev line, and multiple defaults (first wins).
func TestParseDefaultRouteDev(t *testing.T) {
	cases := []struct{ in, want string }{
		{"default via 192.168.1.254 dev wan  src 192.168.1.70", "wan"}, // real device output
		{"default via 10.0.0.1 dev eth1 proto static metric 1", "eth1"},
		{"default dev pppoe-wan scope link", "pppoe-wan"},
		{"", ""},
		{"blackhole default", ""}, // no dev token
		{"default via 1.2.3.4 dev wan\ndefault via 5.6.7.8 dev wwan metric 20", "wan"}, // first wins
		{"dev", ""}, // trailing dev with no name must not panic
	}
	for _, c := range cases {
		if got := parseDefaultRouteDev(c.in); got != c.want {
			t.Errorf("parseDefaultRouteDev(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAppendUniqueStr(t *testing.T) {
	got := appendUniqueStr(appendUniqueStr([]string{"wan"}, "br-lan"), "wan")
	if len(got) != 2 || got[0] != "wan" || got[1] != "br-lan" {
		t.Errorf("appendUniqueStr dedup failed: %v", got)
	}
}
