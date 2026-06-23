package pbr

import (
	"fmt"
	"sort"
	"strings"
)

// hexMark formats a 32-bit fwmark/mask.
func hexMark(v uint32) string { return fmt.Sprintf("0x%08x", v) }

// markSet renders the nft expression that sets our mark bits while preserving any
// non-owned bits (so it coexists with fw4's own marks).
func (pl *Plan) markSet(mark uint32) string {
	return fmt.Sprintf("meta mark set meta mark & %s | %s", hexMark(^pl.Mask), hexMark(mark))
}

func nftElements(cidrs []string) string { return strings.Join(cidrs, ", ") }

// RenderNft returns the full nftables ruleset for this plan's OWN table (applied via
// `nft -f -`). It only ever touches `table inet <pl.Table>`, so it coexists with fw4
// and sing-box's auto_redirect table and survives `fw4 reload` (re-apply on reload).
func (pl *Plan) RenderNft() string {
	var b strings.Builder
	// Self-flushing idiom: one atomic `nft -f` transaction that recreates our table from
	// scratch (ensure-exists → delete → recreate) so apply is idempotent with no gap.
	fmt.Fprintf(&b, "table inet %s {}\ndelete table inet %s\n", pl.Table, pl.Table)
	fmt.Fprintf(&b, "table inet %s {\n", pl.Table)

	// Phase 1b flow-offload datapath (opt-in; nil unless Options.Offload was set). The
	// flowtable + the mark-gated flow-add chain live in OUR table, so they tear down with
	// it (fail-safe-safe) and never touch fw4. The forward chain runs AFTER prerouting
	// (where wr_mark set the fwmark), so carve-out flows (any owned mark bit set) hit the
	// `return` and are NEVER offloaded — keeping their per-packet PBR (and the UDP calls it
	// carries) intact; only general (mark 0) traffic is added to the flowtable.
	if ft := pl.Flowtable; ft != nil && len(ft.Devices) > 0 {
		b.WriteString("\tflowtable ft {\n\t\thook ingress priority filter - 1;\n")
		fmt.Fprintf(&b, "\t\tdevices = { %s };\n", strings.Join(ft.Devices, ", "))
		if ft.HW {
			b.WriteString("\t\tflags offload;\n")
		}
		b.WriteString("\t}\n")
	}

	if len(pl.BypassV4) > 0 {
		fmt.Fprintf(&b, "\tset bypass4 { type ipv4_addr; flags interval; elements = { %s } }\n", nftElements(pl.BypassV4))
	}
	if len(pl.BypassV6) > 0 {
		fmt.Fprintf(&b, "\tset bypass6 { type ipv6_addr; flags interval; elements = { %s } }\n", nftElements(pl.BypassV6))
	}
	for _, z := range pl.Zones {
		if len(z.V4) > 0 {
			fmt.Fprintf(&b, "\tset %s_4 { type ipv4_addr; flags interval; elements = { %s } }\n", z.Name, nftElements(z.V4))
		}
		if len(z.V6) > 0 {
			fmt.Fprintf(&b, "\tset %s_6 { type ipv6_addr; flags interval; elements = { %s } }\n", z.Name, nftElements(z.V6))
		}
	}

	// Chain name must NOT be an nft reserved keyword — `chain mark { ... }` fails to
	// parse ("unexpected mark"), since `mark` is a keyword (meta mark / ct mark). Use a
	// namespaced identifier instead. (Caught only by a real `nft -f` on-device; the unit
	// tests use a mock runner and never parsed the ruleset.)
	b.WriteString("\tchain wr_mark {\n")
	b.WriteString("\t\ttype filter hook prerouting priority mangle; policy accept;\n")
	// Anti-loop bypass first: tunnel peer IPs egress via WAN (main table).
	wanMark := pl.markByKind(EgressWAN)
	if len(pl.BypassV4) > 0 {
		fmt.Fprintf(&b, "\t\tip daddr @bypass4 %s\n", pl.markSet(wanMark))
	}
	if len(pl.BypassV6) > 0 {
		fmt.Fprintf(&b, "\t\tip6 daddr @bypass6 %s\n", pl.markSet(wanMark))
	}
	for _, z := range pl.Zones {
		if len(z.V4) > 0 {
			fmt.Fprintf(&b, "\t\tip daddr @%s_4 %s\n", z.Name, pl.markSet(z.Mark))
		}
		if len(z.V6) > 0 {
			fmt.Fprintf(&b, "\t\tip6 daddr @%s_6 %s\n", z.Name, pl.markSet(z.Mark))
		}
	}
	// Save the chosen egress fwmark into the connmark so the connection's exit is visible in
	// /proc/net/nf_conntrack (the Dashboard reads `mark=` to attribute each connection to its
	// tunnel/WAN). Informational only — it does not affect routing (the meta mark above does).
	b.WriteString("\t\tct mark set meta mark\n")
	b.WriteString("\t}\n")

	// Flow-offload chain (Phase 1b): only when a flowtable is present. Base chain on the
	// forward hook just BEFORE fw4's (priority filter-1) with policy accept, so it adds
	// flows without short-circuiting fw4's filtering (accept is non-terminating across base
	// chains; only the per-packet offload decision is ours). Carve-outs (mark != 0) return
	// before the flow-add; general (mark 0) tcp/udp is offloaded to @ft.
	if pl.Flowtable != nil && len(pl.Flowtable.Devices) > 0 {
		b.WriteString("\tchain wr_offload {\n")
		b.WriteString("\t\ttype filter hook forward priority filter - 1; policy accept;\n")
		fmt.Fprintf(&b, "\t\tmeta mark & %s != 0x0 return\n", hexMark(pl.Mask))
		b.WriteString("\t\tmeta l4proto { tcp, udp } flow add @ft\n")
		b.WriteString("\t}\n")
	}

	b.WriteString("}\n")
	return b.String()
}

func (pl *Plan) markByKind(k EgressKind) uint32 {
	for _, e := range pl.Egresses {
		if e.Kind == k {
			return e.Mark
		}
	}
	return 0
}

// ipRuleExclude is a destination CIDR pinned to the main table at a given priority.
type ipRuleExclude struct {
	CIDR     string
	Priority int
}

// privateExcludes returns ip-rule exclusions that keep LAN/private-destination traffic
// on the main table, just BELOW the fwmark rules. Without them the CONNMARK-restore
// re-marks an established flow's RETURN packets (internet→LAN) with the tunnel mark, and
// since each table holds only `default dev <tunnel>`, the reply to a LAN client loops
// back out the tunnel instead of reaching it — a real SYN_RECV stall seen live on the
// Keenetic. RFC1918 dsts never belong on a tunnel egress (the censored sets are public),
// so this is safe; priorities sit just under RulePref so they win over the fwmark rules.
func privateExcludes(opt Options) []ipRuleExclude {
	return excludesFor(opt, []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"})
}

// privateExcludesV6 is the IPv6 analogue: ULA + link-local stay on the main table so a
// v6 LAN/local-dst reply isn't re-marked onto a tunnel table (same loop the v4 exclusion
// prevents). Emitted only when the plan actually marks v6.
func privateExcludesV6(opt Options) []ipRuleExclude {
	return excludesFor(opt, []string{"fc00::/7", "fe80::/10"})
}

func excludesFor(opt Options, cidrs []string) []ipRuleExclude {
	opt.withDefaults()
	out := make([]ipRuleExclude, len(cidrs))
	for j, c := range cidrs {
		out[j] = ipRuleExclude{c, opt.RulePref - len(cidrs) + j}
	}
	return out
}

// RenderIP returns the idempotent `ip rule`/`ip route` commands to install the plan.
// WAN-marked traffic (the bypass) needs no rule — it falls through to the main table.
func (pl *Plan) RenderIP(opt Options) []string {
	opt.withDefaults()
	var cmds []string
	for _, x := range privateExcludes(opt) {
		cmds = append(cmds, fmt.Sprintf("ip rule add to %s lookup main priority %d", x.CIDR, x.Priority))
	}
	for i, e := range pl.nonWanEgresses() {
		pref := opt.RulePref + i
		cmds = append(cmds, fmt.Sprintf("ip rule add fwmark %s/%s table %d priority %d",
			hexMark(e.Mark), hexMark(pl.Mask), e.Table, pref))
		switch e.Kind {
		case EgressInterface:
			cmds = append(cmds, fmt.Sprintf("ip route replace default dev %s table %d", e.Iface, e.Table))
		case EgressBlackhole:
			cmds = append(cmds, fmt.Sprintf("ip route replace blackhole default table %d", e.Table))
		}
	}
	return cmds
}

// ipTeardown returns just the `ip rule`/`ip route` removal commands (no nft).
func (pl *Plan) ipTeardown(opt Options) []string {
	opt.withDefaults()
	var cmds []string
	for i, e := range pl.nonWanEgresses() {
		pref := opt.RulePref + i
		cmds = append(cmds, fmt.Sprintf("ip rule del fwmark %s/%s table %d priority %d",
			hexMark(e.Mark), hexMark(pl.Mask), e.Table, pref))
		cmds = append(cmds, fmt.Sprintf("ip route flush table %d", e.Table))
	}
	for _, x := range privateExcludes(opt) {
		cmds = append(cmds, fmt.Sprintf("ip rule del to %s lookup main priority %d", x.CIDR, x.Priority))
	}
	return cmds
}

// RenderTeardown returns the commands to remove everything RenderNft/RenderIP installed.
func (pl *Plan) RenderTeardown(opt Options) []string {
	return append([]string{fmt.Sprintf("nft delete table inet %s", pl.Table)}, pl.ipTeardown(opt)...)
}

// nonWanEgresses returns interface/blackhole egresses in stable (mark) order.
func (pl *Plan) nonWanEgresses() []Egress {
	var out []Egress
	for _, e := range pl.Egresses {
		if e.Kind != EgressWAN {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mark < out[j].Mark })
	return out
}
