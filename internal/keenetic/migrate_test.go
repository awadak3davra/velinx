package keenetic

import (
	"strings"
	"testing"
)

// TestLiveProfile_ValidatesAndAdopts: the live-setup model validates, and compiling it with
// the adopt map produces ZERO interface blocks (the 4 AmneziaWG tunnels are reused, never
// recreated) with each adopted endpoint mapped to its live nwg.
func TestLiveProfile_ValidatesAndAdopts(t *testing.T) {
	p := LiveProfile()
	if err := p.Validate(); err != nil {
		t.Fatalf("LiveProfile must validate: %v", err)
	}

	adopt := LiveAdoptInterfaces()
	for _, id := range []string{EpKeentest, EpNetherlands, EpNdVps, EpNlFailover} {
		if adopt[id] == "" {
			t.Errorf("adopt map missing %s", id)
		}
	}

	plan, err := Compile(p, CompileOptions{AdoptInterfaces: adopt})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Interfaces) != 0 {
		t.Errorf("all AmneziaWG adopted → expected 0 interface blocks, got %d", len(plan.Interfaces))
	}
	for _, id := range []string{EpKeentest, EpNetherlands, EpNdVps, EpNlFailover} {
		if plan.IfaceFor[id] != adopt[id] {
			t.Errorf("IfaceFor[%s] = %q, want %q (adopted)", id, plan.IfaceFor[id], adopt[id])
		}
	}
	// No `no interface` for any adopted tunnel on teardown.
	if td := strings.Join(TeardownCommands(plan), "\n"); strings.Contains(td, "no interface") {
		t.Errorf("teardown must not remove an adopted tunnel:\n%s", td)
	}
}

// TestLiveGroups_OrderedWanFallback: failover groups for ACCESSIBLE content end in `direct`
// (WAN) per the no-kill-switch posture; blocked_rf (censored) is TUNNEL-ONLY (the RU WAN blocks
// it, so a WAN fallback is useless and would break Telegram). All are high-tolerance (sticky).
func TestLiveGroups_OrderedWanFallback(t *testing.T) {
	for _, g := range liveGroups() {
		if len(g.Members) < 2 {
			t.Errorf("group %s has too few members", g.ID)
		}
		last := g.Members[len(g.Members)-1]
		if g.ID == "default_3tier" {
			if last != "direct" {
				t.Errorf("default_3tier must end in WAN (general traffic, no-kill-switch): %v", g.Members)
			}
		} else if last == "direct" {
			// All LIST groups (blocked_rf/failover_strict/failover_with_wan) are tunnel-only.
			t.Errorf("list group %s must be tunnel-only (no WAN terminal): %v", g.ID, g.Members)
		}
		if g.Test == nil || g.Test.Tolerance < 1000 {
			t.Errorf("group %s needs a high tolerance for sticky ordered failover", g.ID)
		}
	}
	// Default 3-tier is Hy2 → AWG(NL) → VLESS → WAN, in that order.
	var def []string
	for _, g := range liveGroups() {
		if g.ID == "default_3tier" {
			def = g.Members
		}
	}
	want := []string{EpHy2, EpNlFailover, EpVless, "direct"}
	if strings.Join(def, ",") != strings.Join(want, ",") {
		t.Errorf("default_3tier order = %v, want %v", def, want)
	}
}
