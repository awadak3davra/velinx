package keenetic

import (
	"strings"
	"testing"
)

// synthetic running-config in the exact KeeneticOS shape (no real keys/IPs).
const rcFixture = `! $$$ Model: Keenetic Hopper SE
interface Wireguard0
    description ND_VPS
    ip address 10.8.1.10 255.255.255.255
    wireguard asc 5 49 998 17 110 1 2 3 4
    wireguard peer AAAA=
        endpoint 192.0.2.10:443
        keepalive-interval 21
        allow-ips 0.0.0.0 0.0.0.0
        connect
    !
    up
!
interface Wireguard1
    description Netherlands
    wireguard peer BBBB=
        endpoint vpn.example.com:51820
    !
    up
!
interface Wireguard2
    description mgmt
    wireguard peer CCCC=
        endpoint 198.51.100.5:8443
    up
!
interface Wireguard5
    description NL_failover
    wireguard peer DDDD=
        endpoint 203.0.113.7:8443
    up
!
ip route 0.0.0.0 0.0.0.0 ISP
`

func TestParseWireguardEndpoints(t *testing.T) {
	got := parseWireguardEndpoints(rcFixture)
	if len(got) != 4 {
		t.Fatalf("want 4 interfaces, got %d: %+v", len(got), got)
	}
	want := []WGInterface{
		{"Wireguard0", "ND_VPS", "192.0.2.10", "443"},
		{"Wireguard1", "Netherlands", "vpn.example.com", "51820"},
		{"Wireguard2", "mgmt", "198.51.100.5", "8443"},
		{"Wireguard5", "NL_failover", "203.0.113.7", "8443"},
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("iface[%d] = %+v, want %+v", i, got[i], w)
		}
	}
}

func TestBypassHosts_SkipsMgmt(t *testing.T) {
	ifaces := parseWireguardEndpoints(rcFixture)
	hosts := BypassHosts(ifaces, "Wireguard2") // mgmt iface excluded
	joined := strings.Join(hosts, ",")
	if strings.Contains(joined, "198.51.100.5") {
		t.Error("mgmt peer endpoint must NOT be in the bypass set")
	}
	for _, want := range []string{"192.0.2.10", "vpn.example.com", "203.0.113.7"} {
		if !strings.Contains(joined, want) {
			t.Errorf("bypass missing %q (got %v)", want, hosts)
		}
	}
}

// TestReconcileAdopt: endpoints are matched to live interfaces by INTERFACE NUMBER
// (nwg5↔Wireguard5), not description — so nl_failover (nwg5, description "frunze-main" on the
// real box) is correctly adopted, and keentest (nwg3, no live Wireguard3) is reported missing.
func TestReconcileAdopt(t *testing.T) {
	live := parseWireguardEndpoints(rcFixture) // Wireguard0/1/2/5 live, no Wireguard3
	adopt, missing := ReconcileAdopt(live, LiveAdoptInterfaces())

	if adopt[EpNdVps] != "nwg0" || adopt[EpNetherlands] != "nwg1" || adopt[EpNlFailover] != "nwg5" {
		t.Errorf("adopt map wrong (by number): %v", adopt)
	}
	if _, ok := adopt[EpKeentest]; ok {
		t.Error("keentest must NOT be adopted — no live Wireguard3")
	}
	if len(missing) != 1 || missing[0] != EpKeentest {
		t.Errorf("missing = %v, want [%s]", missing, EpKeentest)
	}
}

func TestSplitEndpoint(t *testing.T) {
	cases := map[string][2]string{
		"192.0.2.10:443":        {"192.0.2.10", "443"},
		"vpn.example.com:51820": {"vpn.example.com", "51820"},
		"[2001:db8::1]:443":     {"2001:db8::1", "443"},
		"bare-host":             {"bare-host", ""},
	}
	for in, want := range cases {
		h, p := splitEndpoint(in)
		if h != want[0] || p != want[1] {
			t.Errorf("splitEndpoint(%q) = (%q,%q), want (%q,%q)", in, h, p, want[0], want[1])
		}
	}
}
