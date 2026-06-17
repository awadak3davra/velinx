package server

import (
	"net/http"

	"wakeroute/internal/pbr"
)

// handlePBRPreview compiles the current profile into a kernel policy-based-routing plan
// and returns it READ-ONLY — the rendered nftables ruleset, the ip rule/route commands,
// and warnings about model content the IP-based compiler does not kernel-route (domains,
// geoip rule-sets, group failover, proxy-engine targets). Diagnostics for the native-
// first "hybrid" routing mode (docs/ARCHITECTURE_NATIVE_FIRST.md). It does NOT touch the
// router — no nft/ip is executed.
func (s *Server) handlePBRPreview(w http.ResponseWriter, r *http.Request) {
	p := s.store.Profile()
	plan, warns, err := pbr.Compile(&p, pbr.Options{})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if warns == nil {
		warns = []pbr.Warning{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"mode":     s.config().RoutingMode,
		"plan":     plan,
		"nft":      plan.RenderNft(),
		"ip":       plan.RenderIP(pbr.Options{}),
		"teardown": plan.RenderTeardown(pbr.Options{}),
		"warnings": warns,
	})
}
