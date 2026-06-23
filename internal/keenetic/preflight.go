package keenetic

import (
	"net"
	"strings"
)

// preflight.go reads the LIVE device state the cutover needs but the static model can't carry
// (see the red-team's bypass + adopt holes). Pure parsers here; the RCI/file reads that feed
// them happen at deploy pre-flight.

// WGInterface is one AmneziaWG/WireGuard interface from `show running-config`: its NDM name,
// description, and peer endpoint (the server the tunnel dials).
type WGInterface struct {
	Iface    string // "Wireguard0"
	Name     string // `description` (e.g. "ND_VPS")
	Endpoint string // peer endpoint host — IP or hostname
	Port     string // peer endpoint port
}

// parseWireguardEndpoints extracts the live AmneziaWG/WireGuard interfaces + their peer
// endpoints from a KeeneticOS `show running-config`. Pre-flight uses this to (1) build the
// REAL adopt map from interfaces that actually exist (keen-pbr references nwg3/keentest but
// only Wireguard0/1/2/5 are live — that stale tag must be reconciled, not assumed) and (2)
// seed the anti-loop bypass with the peer endpoint IPs (adopted External endpoints carry no
// model Server, so the bypass cannot come from the model).
func parseWireguardEndpoints(runningConfig string) []WGInterface {
	var out []WGInterface
	var cur *WGInterface
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}
	for _, line := range strings.Split(runningConfig, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "interface Wireguard"):
			flush()
			cur = &WGInterface{Iface: strings.TrimSpace(strings.TrimPrefix(t, "interface "))}
		case cur != nil && strings.HasPrefix(t, "description "):
			cur.Name = strings.TrimSpace(strings.TrimPrefix(t, "description "))
		case cur != nil && strings.HasPrefix(t, "endpoint "):
			cur.Endpoint, cur.Port = splitEndpoint(strings.TrimSpace(strings.TrimPrefix(t, "endpoint ")))
		case line == "!": // a TOP-LEVEL "!" (no indentation) closes the interface; the indented "    !" closes only the peer
			flush()
		}
	}
	flush()
	return out
}

// splitEndpoint splits "host:port" / "[v6]:port" via net.SplitHostPort; a bare host (no port)
// is returned as-is.
func splitEndpoint(ep string) (host, port string) {
	if h, p, err := net.SplitHostPort(ep); err == nil {
		return h, p
	}
	return ep, ""
}

// BypassHosts returns the peer endpoint hosts that must egress via ISP (anti-loop), skipping
// the management interface (Wireguard2 / nwg2, which the live S89 explicitly never touches).
func BypassHosts(ifaces []WGInterface, mgmtIface string) []string {
	var out []string
	for _, w := range ifaces {
		if w.Iface == mgmtIface || w.Endpoint == "" {
			continue
		}
		out = append(out, w.Endpoint)
	}
	return out
}

// ReconcileAdopt builds the REAL adopt map (endpoint ID → kernel interface) by checking, for
// each expected endpoint, whether its kernel interface (nwgN) is actually LIVE — matched by
// INTERFACE NUMBER (nwg5 ↔ Wireguard5 in the running-config), NOT by the human `description`
// (which varies, e.g. Wireguard5's is "frunze-main", not "NL_failover"). expectedNwg is the
// endpoint ID → nwgN map (LiveAdoptInterfaces). Endpoints whose interface is gone are returned
// in `missing` — keen-pbr's `keentest` (→nwg3) has no live Wireguard3, so the assembly drops/
// remaps it instead of routing to a dead interface.
func ReconcileAdopt(live []WGInterface, expectedNwg map[string]string) (adopt map[string]string, missing []string) {
	liveSet := map[string]bool{} // "Wireguard5" present?
	for _, w := range live {
		liveSet[w.Iface] = true
	}
	adopt = map[string]string{}
	for id, nwg := range expectedNwg {
		num := strings.TrimPrefix(nwg, "nwg")
		if liveSet["Wireguard"+num] {
			adopt[id] = nwg
		} else {
			missing = append(missing, id)
		}
	}
	return adopt, missing
}
