// Package pbr compiles the protocol-agnostic model into a kernel policy-based-routing
// plan (nftables fwmark + `ip rule`/`ip route`) for the native-first "hybrid" routing
// mode — see docs/ARCHITECTURE_NATIVE_FIRST.md. It is the kernel-routing brain that
// keen-pbr provided externally before the TUN cutover, now as native WakeRoute code.
//
// Phase 1 (this file): a pure, testable compiler + nftables/ip renderers for IP-CIDR
// routing (manual IP lists, geoip-by-IP, the VoWiFi/ePDG carve-out). Domain/GeoSite/
// GeoIP-by-rule-set zones and live Apply/teardown + kernel failover are Phase 2; the
// compiler surfaces them as Warnings rather than mis-routing them.
package pbr

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"wakeroute/internal/model"
	"wakeroute/internal/util"
)

// EgressKind classifies a kernel routing destination.
type EgressKind string

const (
	EgressWAN       EgressKind = "wan"       // the system default route (main table)
	EgressInterface EgressKind = "interface" // route out a kernel netdev (awg0/awg1/wr-xxxx)
	EgressBlackhole EgressKind = "blackhole" // drop (block list)
)

// Egress is one kernel routing destination with its assigned fwmark + routing table.
type Egress struct {
	Tag   string // model outbound tag (endpoint id, group id, "direct", "block")
	Kind  EgressKind
	Iface string // kernel ifname when Kind==EgressInterface
	Mark  uint32 // fwmark (masked by Plan.Mask)
	Table int    // routing table number
}

// Zone is an IP-CIDR set whose matching destination traffic is marked for an egress.
type Zone struct {
	Name      string   // stable, nft-safe set name
	EgressTag string   // which Egress this zone routes to
	Mark      uint32   // == the egress mark (denormalized for rendering)
	V4        []string // IPv4 CIDRs (normalized, sorted)
	V6        []string // IPv6 CIDRs
}

// Warning flags model content the IP-based Phase-1 compiler does not kernel-route.
type Warning struct {
	Scope string // rule/list id
	Msg   string
}

// Plan is the compiled kernel-routing plan for hybrid mode.
type Plan struct {
	Table    string   // nft table name (own table, coexists with fw4)
	Mask     uint32   // fwmark mask owned by this plan
	Egresses []Egress // sorted: wan first, then the rest by tag
	Zones    []Zone   // sorted by name
	BypassV4 []string // kernel endpoints' own server IPs → main table (anti-loop)
	BypassV6 []string
}

// Options tune the marking/table scheme (defaults mirror the keen-pbr layout).
type Options struct {
	Table     string // default "wakeroute_pbr"
	MarkMask  uint32 // default 0x00ff0000
	MarkStep  uint32 // default 0x00010000 (egress N gets N*MarkStep)
	TableBase int    // default 151 (first non-main routing table)
	WANTable  int    // default 254 (main)
	RulePref  int    // default 150 (base ip-rule priority)
}

func (o *Options) withDefaults() {
	if o.Table == "" {
		o.Table = "wakeroute_pbr"
	}
	if o.MarkMask == 0 {
		o.MarkMask = 0x00ff0000
	}
	if o.MarkStep == 0 {
		o.MarkStep = 0x00010000
	}
	if o.TableBase == 0 {
		o.TableBase = 151
	}
	if o.WANTable == 0 {
		o.WANTable = 254
	}
	if o.RulePref == 0 {
		o.RulePref = 150
	}
}

// KernelIface returns the kernel interface name an endpoint routes out through, or ""
// if the endpoint is not a kernel-plane (interface-backed) engine. Exported so the
// generator's hybrid-split classifier uses the IDENTICAL kernel/proxy test as Compile
// (no drift: the two planes must partition the same set of outbounds).
func KernelIface(e *model.Endpoint) string { return kernelIface(e) }

// kernelIface returns the kernel interface name an endpoint routes out through, or ""
// if the endpoint is not a kernel-plane (interface-backed) engine.
func kernelIface(e *model.Endpoint) string {
	switch e.Engine {
	case model.EngineExternal:
		s, _ := e.Params["interface"].(string)
		return s
	case model.EngineAmneziaWG:
		return util.AWGIface(e.ID)
	default:
		return ""
	}
}

// Compile turns the profile into a kernel-routing Plan plus warnings for anything the
// IP-based Phase-1 compiler cannot kernel-route (domains, geoip/geosite rule-sets,
// group failover, proxy-engine targets).
func Compile(p *model.Profile, opt Options) (*Plan, []Warning, error) {
	opt.withDefaults()
	if p == nil {
		return nil, nil, fmt.Errorf("nil profile")
	}
	plan := &Plan{Table: opt.Table, Mask: opt.MarkMask}
	var warns []Warning
	warn := func(scope, msg string) { warns = append(warns, Warning{Scope: scope, Msg: msg}) }

	// resolveEgress maps a model outbound tag to a kernel egress kind+iface.
	resolveEgress := func(scope, tag string) (EgressKind, string, bool) {
		switch tag {
		case model.OutboundDirect, "":
			return EgressWAN, "", true
		case model.OutboundBlock:
			return EgressBlackhole, "", true
		}
		if e := p.EndpointByID(tag); e != nil {
			if ifc := kernelIface(e); ifc != "" {
				return EgressInterface, ifc, true
			}
			warn(scope, "outbound "+tag+" is a proxy endpoint (userspace plane) — not kernel-routed")
			return "", "", false
		}
		if g := p.GroupByID(tag); g != nil {
			for _, m := range g.Members {
				if me := p.EndpointByID(m); me != nil {
					if ifc := kernelIface(me); ifc != "" {
						warn(scope, "group "+tag+" → kernel primary "+ifc+"; kernel failover is Phase 2")
						return EgressInterface, ifc, true
					}
				}
			}
			warn(scope, "group "+tag+" has no kernel-plane member — not kernel-routed")
			return "", "", false
		}
		warn(scope, "unknown outbound "+tag)
		return "", "", false
	}

	// Collect zones from IP-based rules + routing lists; track which egress tags are used.
	usedEgress := map[string]struct{}{}
	addZone := func(name, egTag string, cidrs []string, scope string) {
		v4, v6, bad := classifyCIDRs(cidrs)
		for _, b := range bad {
			warn(scope, "skipped non-IP entry "+b+" (domain matching is Phase 2)")
		}
		if len(v4) == 0 && len(v6) == 0 {
			return
		}
		usedEgress[egTag] = struct{}{}
		plan.Zones = append(plan.Zones, Zone{Name: name, EgressTag: egTag, V4: v4, V6: v6})
	}

	for i := range p.Rules {
		r := &p.Rules[i]
		// A default rule is sing-box's catch-all (route.final): its matcher fields are
		// meaningless (sing-box ignores them), so a stale IPCIDR on it must NOT become a
		// zone — that would TUN-exclude the CIDR and silently shadow an earlier proxy
		// rule for the same IP. Unmatched traffic falls through to WAN (the main table)
		// on its own; the generator's route.final handles the in-TUN default.
		if r.Default {
			continue
		}
		if len(r.Domain)+len(r.DomainSuffix)+len(r.GeoSite) > 0 {
			warn(r.ID, "domain/geosite matching not kernel-routed in Phase 1")
		}
		if len(r.GeoIP) > 0 {
			warn(r.ID, "geoip rule-set not kernel-routed in Phase 1 (expand to a CIDR set in Phase 2)")
		}
		if len(r.IPCIDR) == 0 {
			continue
		}
		if k, _, ok := resolveEgress(r.ID, r.Outbound); ok && k != "" {
			addZone("rule_"+nftName(r.ID), r.Outbound, r.IPCIDR, r.ID)
		}
	}
	for i := range p.RoutingLists {
		rl := &p.RoutingLists[i]
		if !rl.Enabled {
			continue
		}
		if rl.Source != "" {
			warn(rl.ID, "remote rule-set ("+rl.Source+") not kernel-routed in Phase 1 (set population is Phase 2)")
		}
		if len(rl.Manual) == 0 {
			continue
		}
		if k, _, ok := resolveEgress(rl.ID, rl.Outbound); ok && k != "" {
			addZone("list_"+nftName(rl.ID), rl.Outbound, rl.Manual, rl.ID)
		}
	}

	// Anti-loop bypass: every kernel endpoint's own server IP must egress via WAN, not
	// back into a tunnel (mirrors generator.endpointBypass).
	var bypass []string
	for i := range p.Endpoints {
		e := &p.Endpoints[i]
		// Only ENABLED kernel endpoints (a disabled one is never emitted/used, and
		// generator.endpointBypass also skips it — keep the two in sync).
		if e.Enabled && kernelIface(e) != "" && e.Server != "" {
			bypass = append(bypass, e.Server)
		}
	}
	plan.BypassV4, plan.BypassV6, _ = classifyCIDRs(bypass)

	// Assign marks + tables. WAN is always present (the bypass + any "direct" zone use it);
	// then each other used egress, in stable order.
	plan.Egresses = append(plan.Egresses, Egress{Tag: model.OutboundDirect, Kind: EgressWAN, Mark: opt.MarkStep, Table: opt.WANTable})
	var others []string
	for tag := range usedEgress {
		if tag != model.OutboundDirect {
			others = append(others, tag)
		}
	}
	sort.Strings(others)
	for i, tag := range others {
		k, ifc, _ := resolveEgress(tag, tag) // already validated above; re-resolve for kind/iface
		plan.Egresses = append(plan.Egresses, Egress{
			Tag: tag, Kind: k, Iface: ifc,
			Mark:  uint32(i+2) * opt.MarkStep,
			Table: opt.TableBase + i,
		})
	}

	// Denormalize each zone's mark from its egress, and sort for stable output.
	markByTag := map[string]uint32{}
	for _, e := range plan.Egresses {
		markByTag[e.Tag] = e.Mark
	}
	for i := range plan.Zones {
		plan.Zones[i].Mark = markByTag[plan.Zones[i].EgressTag]
	}
	sort.Slice(plan.Zones, func(i, j int) bool { return plan.Zones[i].Name < plan.Zones[j].Name })
	return plan, warns, nil
}

// classifyCIDRs normalizes IP/CIDR strings into sorted v4 + v6 CIDR lists; non-IP
// entries (e.g. domains) are returned in `bad`.
func classifyCIDRs(in []string) (v4, v6, bad []string) {
	seen4, seen6 := map[string]bool{}, map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		var pfx netip.Prefix
		if strings.Contains(s, "/") {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				bad = append(bad, s)
				continue
			}
			pfx = p.Masked()
		} else {
			a, err := netip.ParseAddr(s)
			if err != nil {
				bad = append(bad, s)
				continue
			}
			bits := 32
			if a.Is6() {
				bits = 128
			}
			pfx = netip.PrefixFrom(a, bits)
		}
		if pfx.Addr().Is6() {
			if !seen6[pfx.String()] {
				seen6[pfx.String()] = true
				v6 = append(v6, pfx.String())
			}
		} else {
			if !seen4[pfx.String()] {
				seen4[pfx.String()] = true
				v4 = append(v4, pfx.String())
			}
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6, bad
}

// nftName makes an id safe to embed in an nft identifier.
func nftName(id string) string {
	var b strings.Builder
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}
