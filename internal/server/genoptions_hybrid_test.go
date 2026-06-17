package server

import (
	"reflect"
	"testing"

	"wakeroute/internal/model"
	"wakeroute/internal/pbr"
)

// TestGenOptionsHybrid verifies the RoutingMode wiring: "hybrid" compiles the profile
// into a pbr.Plan and folds its zone+bypass CIDRs into the generator's KernelExclude
// lists (the single source of truth), forcing the TUN on; the default "" mode leaves
// Hybrid off and derives TunEnabled from Gateway (back-compat, unchanged).
func TestGenOptionsHybrid(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if err := s.store.UpsertEndpoint(model.Endpoint{
		ID: "ru-awg1", Name: "RU", Engine: model.EngineExternal, Server: "198.51.100.20",
		Enabled: true, Params: map[string]any{"interface": "awg1"},
	}); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	if err := s.store.UpsertRoutingList(model.RoutingList{
		ID: "carrier-carveout", Name: "VoWiFi", Manual: []string{"198.51.100.0/24"}, Outbound: "ru-awg1", Enabled: true,
	}); err != nil {
		t.Fatalf("UpsertRoutingList: %v", err)
	}
	p := s.store.Profile()

	// Default mode: no hybrid, TunEnabled follows Gateway (false here).
	s.cfg.RoutingMode = ""
	s.cfg.Gateway = false
	if o := s.genOptions(&p); o.Hybrid || o.TunEnabled || len(o.KernelExcludeV4) > 0 {
		t.Errorf("default mode: Hybrid=%v TunEnabled=%v exclude=%v, want all empty/false", o.Hybrid, o.TunEnabled, o.KernelExcludeV4)
	}

	// Hybrid mode: Hybrid on, TUN forced on, exclude == pbr.Compile union.
	s.cfg.RoutingMode = "hybrid"
	o := s.genOptions(&p)
	if !o.Hybrid || !o.TunEnabled {
		t.Fatalf("hybrid mode: Hybrid=%v TunEnabled=%v, want both true", o.Hybrid, o.TunEnabled)
	}
	plan, _, err := pbr.Compile(&p, pbr.Options{})
	if err != nil {
		t.Fatalf("pbr.Compile: %v", err)
	}
	var wantV4, wantV6 []string
	for _, z := range plan.Zones {
		wantV4 = append(wantV4, z.V4...)
		wantV6 = append(wantV6, z.V6...)
	}
	wantV4 = append(wantV4, plan.BypassV4...)
	wantV6 = append(wantV6, plan.BypassV6...)
	if !reflect.DeepEqual(o.KernelExcludeV4, wantV4) {
		t.Errorf("KernelExcludeV4 = %v, want %v (pbr.Plan zones+bypass)", o.KernelExcludeV4, wantV4)
	}
	if !reflect.DeepEqual(o.KernelExcludeV6, wantV6) {
		t.Errorf("KernelExcludeV6 = %v, want %v", o.KernelExcludeV6, wantV6)
	}
	// The VoWiFi zone CIDR and the peer anti-loop /32 must both be excluded.
	if !genopts_has(o.KernelExcludeV4, "198.51.100.0/24") {
		t.Errorf("exclude missing the VoWiFi zone: %v", o.KernelExcludeV4)
	}
	if !genopts_has(o.KernelExcludeV4, "198.51.100.20/32") {
		t.Errorf("exclude missing the peer anti-loop /32: %v", o.KernelExcludeV4)
	}

	// Block stays in the sing-box reject plane: a block list's CIDR must NOT be
	// excluded from the TUN (excluding it would let blocked traffic fall through to WAN),
	// while the kernel zones remain excluded.
	if err := s.store.UpsertRoutingList(model.RoutingList{
		ID: "blk", Name: "Block", Manual: []string{"10.10.0.0/16"}, Outbound: model.OutboundBlock, Enabled: true,
	}); err != nil {
		t.Fatalf("UpsertRoutingList block: %v", err)
	}
	pb := s.store.Profile()
	ob := s.genOptions(&pb)
	if genopts_has(ob.KernelExcludeV4, "10.10.0.0/16") {
		t.Errorf("block CIDR must NOT be in the TUN exclude (enforced by sing-box reject): %v", ob.KernelExcludeV4)
	}
	if !genopts_has(ob.KernelExcludeV4, "198.51.100.0/24") {
		t.Errorf("kernel zone CIDR lost after adding a block list: %v", ob.KernelExcludeV4)
	}
}

func genopts_has(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
