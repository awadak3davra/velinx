package keenetic

import (
	"strings"
	"testing"
)

// TestBuildProfile_ReconcilesAndValidates: assembling against live interfaces WITHOUT keentest
// (no nwg3) drops keentest, remaps it to netherlands in the groups (deduped), imports the
// keen-pbr lists, builds the adopt map from the live interfaces, and validates.
func TestBuildProfile_ReconcilesAndValidates(t *testing.T) {
	live := parseWireguardEndpoints(rcFixture) // ND_VPS/Netherlands/mgmt/NL_failover — no keentest
	files := map[string][]string{"/opt/etc/keen-pbr/local.lst": {"lampa.mx"}}

	p, adopt, warnings, err := BuildProfile([]byte(kpFixture), files, live, "")
	if err != nil {
		t.Fatal(err)
	}

	for _, e := range p.Endpoints {
		if e.ID == EpKeentest {
			t.Error("keentest endpoint must be dropped (no live interface)")
		}
	}
	if _, ok := adopt[EpKeentest]; ok {
		t.Error("keentest must not be in the adopt map")
	}
	if adopt[EpNdVps] != "nwg0" || adopt[EpNetherlands] != "nwg1" || adopt[EpNlFailover] != "nwg5" {
		t.Errorf("adopt map (from live ifaces, by number) wrong: %v", adopt)
	}
	if !strings.Contains(strings.Join(warnings, " "), "keentest") {
		t.Errorf("expected a keentest remap warning, got %v", warnings)
	}

	groups := map[string][]string{}
	for _, g := range p.Groups {
		groups[g.ID] = g.Members
	}
	// blocked_rf [keentest, nd_vps] → keentest→netherlands → [netherlands, nd_vps]: TUNNEL-ONLY,
	// NO WAN (censored content can't use the RU WAN; keep a tunnel rather than break Telegram).
	if got := groups["blocked_rf"]; len(got) != 2 || got[0] != EpNetherlands || got[1] != EpNdVps {
		t.Errorf("blocked_rf = %v, want [netherlands nd_vps] (tunnel-only)", got)
	}
	// failover_with_wan [keentest, netherlands, nd_vps] → keentest→netherlands deduped →
	// [netherlands, nd_vps]: tunnel-only (no WAN — list traffic stays on a VPN).
	if got := groups["failover_with_wan"]; len(got) != 2 || got[0] != EpNetherlands || got[1] != EpNdVps {
		t.Errorf("failover_with_wan = %v, want [netherlands nd_vps] (tunnel-only)", got)
	}

	if len(p.RoutingLists) == 0 {
		t.Error("no routing lists imported")
	}
	// The IP-feed plane split survives assembly: telegram is a kernel CIDRSource.
	var tg *struct{ src, cidr string }
	for _, l := range p.RoutingLists {
		if l.ID == "telegram" {
			tg = &struct{ src, cidr string }{l.Source, l.CIDRSource}
		}
	}
	if tg == nil || tg.cidr == "" || tg.src != "" {
		t.Errorf("telegram must remain a kernel CIDRSource after assembly: %+v", tg)
	}
}

// TestBuildProfile_RemapTargetMissing_FallsBackToLiveTunnel: when the DEFAULT remap target
// (netherlands/nwg1) is itself down, BuildProfile must self-heal to a surviving tunnel instead of
// aborting the whole migration with a "member does not resolve" error.
func TestBuildProfile_RemapTargetMissing_FallsBackToLiveTunnel(t *testing.T) {
	var live []WGInterface
	for _, w := range parseWireguardEndpoints(rcFixture) {
		if w.Iface != "Wireguard1" { // drop netherlands/nwg1 → the default remapTo is now missing
			live = append(live, w)
		}
	}
	files := map[string][]string{"/opt/etc/keen-pbr/local.lst": {"lampa.mx"}}

	p, _, warnings, err := BuildProfile([]byte(kpFixture), files, live, "") // remapTo "" → EpNetherlands (missing)
	if err != nil {
		t.Fatalf("BuildProfile must self-heal when the default remap target is down, got: %v", err)
	}
	for _, g := range p.Groups {
		for _, m := range g.Members {
			if m == EpNetherlands {
				t.Errorf("group %s still references the down netherlands tunnel: %v", g.ID, g.Members)
			}
		}
	}
	if !strings.Contains(strings.Join(warnings, " "), "no live interface") {
		t.Errorf("expected a remap-fallback warning naming the down target, got %v", warnings)
	}
}
